"""Offline reports: transport facts are separated from protocol hypotheses."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import zipfile
from .capture import MAX_INPUT, FormatError, decode_usb, read_packets

METADATA = {'observations.json', 'issues.json', 'api_name_hints.json', 'application.json',
            'input_file.json', 'usb_devices.json', 'usb_drivers.json', 'capture_session.json'}


def bounded_read(path, limit=MAX_INPUT):
    with Path(path).open('rb') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise FormatError(f'{Path(path).name}: exceeds input size limit')
    return data


def load_source(path):
    """Never extract ZIP paths. Accept exactly one capture, tolerate absent capture."""
    path = Path(path)
    metadata, capture = {}, None
    if path.is_dir():
        matches = sorted(p for p in path.iterdir() if p.suffix.lower() in ('.pcap', '.pcapng'))
        if len(matches) > 1:
            raise FormatError('Multiple captures: pass one capture file explicitly')
        capture = bounded_read(matches[0]) if matches else None
        for name in METADATA:
            if (path / name).is_file():
                metadata[name] = json.loads(bounded_read(path / name, 4 * 1024 * 1024).decode('utf-8-sig'))
    elif path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as z:
            members = [m for m in z.infolist() if not m.is_dir()]
            if len(members) > 1000 or sum(m.file_size for m in members) > MAX_INPUT:
                raise FormatError('ZIP too large; pass capture directly')
            captures = [m for m in members if PurePosixPath(m.filename).suffix.lower() in ('.pcap', '.pcapng')]
            if len(captures) > 1:
                raise FormatError('ZIP contains multiple captures; pass one explicitly')
            if captures:
                capture = z.read(captures[0])
            for m in members:
                name = PurePosixPath(m.filename).name
                if name in METADATA:
                    if name in metadata:
                        raise FormatError(f'Ambiguous duplicate metadata: {name}')
                    if m.file_size > 4 * 1024 * 1024:
                        raise FormatError('Metadata too large')
                    metadata[name] = json.loads(z.read(m).decode('utf-8-sig'))
    else:
        capture = bounded_read(path)
    return capture, metadata


def sha(data):
    return hashlib.sha256(data).hexdigest()


def entropy(data):
    if not data:
        return 0.0
    return round(-sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values()), 5)


def collect(data, bus=None, device=None):
    rows, warnings, pending = [], [], {}
    links, skipped = Counter(), 0
    for p in read_packets(data):
        links[p.linktype] += 1
        u = decode_usb(p)
        if u is None:
            skipped += 1
            continue
        if bus is not None and u.bus != bus or device is not None and u.device != device:
            continue
        row = dict(frame=p.frame, section=p.section, interface=p.interface, timestamp=p.timestamp,
                   bus=u.bus, device=u.device, endpoint=f'0x{u.endpoint:02x}', direction=u.direction,
                   transfer=u.transfer, stage=u.stage, irp=f'0x{u.irp:x}',
                   phase='complete' if u.complete else 'submit', status=u.status if u.complete else None,
                   declared_length=u.declared_length, captured_length=len(u.payload), truncated=u.truncated,
                   paired_frame=None, completion_status=None, latency_ms=None,
                   setup_hex='', payload_hex=u.payload.hex(), selected=False)
        if not u.complete and (u.transfer != 2 or u.stage == 0):
            if u.key in pending:
                warnings.append(f'Frame {p.frame}: IRP reused before completion; previous pairing discarded')
            pending[u.key] = row
        start = pending.get(u.key)
        if u.transfer == 2 and u.stage == 0:
            if len(u.payload) >= 8:
                row['setup_hex'] = u.payload[:8].hex()
                row['direction'] = 'IN' if u.payload[0] & 128 else 'OUT'
                row['payload_hex'] = u.payload[8:].hex()
            else:
                warnings.append(f'Frame {p.frame}: incomplete control SETUP')
        elif u.transfer == 2 and start and start['setup_hex']:
            row['direction'] = start['direction']
            row['setup_hex'] = start['setup_hex']
        if u.complete:
            # Separate transport completion from an application reply on another IRP.
            if start is not None:
                row['paired_frame'] = start['frame']
                start['paired_frame'] = p.frame
                start['completion_status'] = u.status
                if p.timestamp is not None and start['timestamp'] is not None:
                    row['latency_ms'] = round((p.timestamp - start['timestamp']) * 1000, 6)
                if u.transfer != 2 or u.stage in (2, 3):
                    pending.pop(u.key, None)
            else:
                warnings.append(f'Frame {p.frame}: completion without captured submit')
        if u.truncated:
            warnings.append(f'Frame {p.frame}: truncated; excluded from streams')
        # Only bulk/interrupt canonical data phases, never both submit and completion.
        row['selected'] = (u.transfer in (1, 3) and not u.truncated and bool(u.payload) and
                           ((u.direction == 'OUT' and not u.complete) or
                            (u.direction == 'IN' and u.complete and u.status == 0)))
        rows.append(row)
    for row in rows:
        if row['direction'] == 'OUT' and row['completion_status'] not in (None, 0):
            row['selected'] = False
    if skipped:
        warnings.append(f'{skipped} non-USBPcap packets skipped (linktypes: {dict(links)})')
    if pending:
        warnings.append(f'{len(pending)} submissions lack completion; OUT data is attempted, not proven delivered')
    if not rows:
        warnings.append('No matching USBPcap frames. Check capture linktype and bus/device selection.')
    if any(r['timestamp'] is None for r in rows):
        warnings.append('Some packets have no timestamp (simple packet block). No timing can be inferred.')
    warnings.append('Device addresses can be reused after reconnection within a section. Inspect enumeration before joining sessions.')
    return rows, warnings


def stream_key(row):
    return f"s{row['section']}_i{row['interface']}_b{row['bus']}_d{row['device']}_ep{row['endpoint'][2:]}_{row['direction']}"


def streams_from(rows):
    result = defaultdict(bytearray)
    boundaries = defaultdict(list)
    for r in rows:
        if r['selected']:
            key = stream_key(r)
            payload = bytes.fromhex(r['payload_hex'])
            boundaries[key].append({'frame': r['frame'], 'offset': len(result[key]), 'length': len(payload)})
            result[key].extend(payload)
    return {k: bytes(v) for k, v in result.items()}, dict(boundaries)


def compare_streams(a, b):
    result = []
    for key in sorted(a.keys() | b.keys()):
        left, right = a.get(key), b.get(key)
        if left is None or right is None:
            result.append({'stream': key, 'state': 'only_first' if right is None else 'only_second'})
            continue
        common = 0
        for x, y in zip(left, right):
            if x != y:
                break
            common += 1
        changes = []
        total = 0
        for index, (x, y) in enumerate(zip(left, right)):
            if x != y:
                total += 1
                if len(changes) < 128:
                    changes.append(index)
        result.append({'stream': key, 'identical': left == right, 'size_first': len(left),
                       'size_second': len(right), 'common_prefix_bytes': common,
                       'different_positions_in_overlap': total, 'first_128_different_offsets': changes,
                       'note': 'Positional comparison only; insertion or changed USB address can invalidate alignment.'})
    return result


def file_matches(streams, original):
    results = []
    for key, data in streams.items():
        # Sample beginning/middle/end rather than unbounded all-pairs searches.
        width = min(32, len(original))
        samples = []
        if width:
            for offset in sorted({0, max(0, len(original)//2-width//2), len(original)-width}):
                pos = data.find(original[offset:offset + width])
                samples.append({'file_offset': offset, 'length': width, 'first_stream_offset': pos})
        results.append({'stream': key, 'identical_to_file': data == original,
                        'whole_file_first_offset': data.find(original) if original else None,
                        'samples': samples,
                        'note': 'Exact-byte evidence only; short/repeated samples may match by chance. Absence is not proof of encryption.'})
    return results


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')


def analyze(source, output, bus=None, device=None, compare=None, input_file=None, marker=None):
    data, metadata = load_source(source)
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    rows, warnings = collect(data, bus, device) if data is not None else ([], ['No capture in result; metadata-only report.'])
    streams, boundaries = streams_from(rows)
    (out / 'streams').mkdir()
    summaries = []
    for key, payload in sorted(streams.items()):
        (out / 'streams' / (key + '.bin')).write_bytes(payload)
        blocks = [bytes.fromhex(r['payload_hex']) for r in rows if r['selected'] and stream_key(r) == key]
        summaries.append({'stream': key, 'bytes': len(payload), 'sha256': sha(payload),
                          'entropy_bits_per_byte': entropy(payload), 'transfers': len(blocks),
                          'repeated_payloads': [{'sha256': sha(p), 'bytes': len(p), 'count': n}
                                                for p, n in Counter(blocks).most_common(10) if n > 1]})
    write_json(out / 'frames.json', rows)
    write_json(out / 'boundaries.json', boundaries)
    # CSV leaves payload in JSON only, preventing oversized spreadsheet cells.
    fields = [k for k in rows[0] if k not in ('payload_hex', 'setup_hex')] if rows else ['frame']
    with (out / 'timeline.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    facts = Counter((r['bus'], r['device']) for r in rows)
    if len(facts) > 1:
        warnings.append('Multiple bus/device pairs present. Re-run with --bus and --device before interpreting protocol.')
    payload_rows = [r for r in rows if r['payload_hex'] or r['setup_hex']]
    if marker is not None:
        t0 = next((r['timestamp'] for r in rows if r['timestamp'] is not None), None)
        if t0 is not None:
            tail = [r['frame'] for r in payload_rows if r['timestamp'] is not None and r['timestamp'] - t0 <= marker][-20:]
        else:
            tail = []
            warnings.append('Marker ignored: no timestamps')
    else:
        tail = [r['frame'] for r in payload_rows[-20:]]
        warnings.append('No message timestamp provided: tail frames are NOT proven to precede the UI message.')
    report = {'version': '0.2.0', 'metadata': metadata, 'usb_frames': len(rows),
              'devices': [{'bus': b, 'device': d, 'frames': n} for (b, d), n in sorted(facts.items())],
              'stream_summary': summaries, 'candidate_tail_frames': tail,
              'marker_seconds_from_first_selected_frame': marker, 'warnings': warnings,
              'interpretation': 'Streams are transport payloads, not decrypted files. URB completion success is not application-level success.'}
    if compare:
        other, _ = load_source(compare)
        if other is None:
            warnings.append('Comparison result has no capture')
        else:
            other_rows, other_warnings = collect(other, bus, device)
            report['comparison'] = compare_streams(streams, streams_from(other_rows)[0])
            report['comparison_warnings'] = other_warnings
    if input_file:
        report['input_file_matches'] = file_matches(streams, bounded_read(input_file))
    write_json(out / 'report.json', report)
    lines = ['# USB 분석 결과', '', f"- USB 프레임: {len(rows)}", f'- 추출 스트림: {len(streams)}',
             '- 성공 응답값, 복호화 여부, 메시지 원인은 아직 판정하지 않았습니다.', '', '## 장비', '',
             '| Bus | Device | Frames |', '| --- | --- | --- |']
    lines += [f'| {b} | {d} | {n} |' for (b, d), n in sorted(facts.items())]
    lines += ['', '## 추출 스트림', '', '| Stream | Bytes | Transfers | Entropy |', '| --- | --- | --- | --- |']
    lines += [f"| {s['stream']} | {s['bytes']} | {s['transfers']} | {s['entropy_bits_per_byte']} |" for s in summaries]
    lines += ['', '## 확인할 프레임', '', ', '.join(map(str, tail)) or '없음', '', '## 해석 제한', '']
    lines += ['- ' + w for w in warnings]
    lines += ['', '## 다음 단계', '',
              '1. 여러 장비가 있으면 bus/device를 지정해 다시 분석합니다.',
              '2. frames.json의 setup_hex/payload_hex와 timeline.csv에서 상태 조회 후보를 찾습니다.',
              '3. 동일 파일 2회 캡처를 --compare로 비교합니다. 주소가 바뀌면 자동 대응하지 않습니다.',
              '4. EXE 정적 분석으로 해당 문자열/API의 교차 참조를 찾고 실행 시 버퍼와 대조합니다.',
              '5. 검증한 요청/응답만 오프라인 모사 규칙으로 작성합니다.',
              '', 'Entropy는 압축/암호화를 구별하지 못합니다. 스트림 연결은 파일 재조립을 보장하지 않습니다.',
              '이 보고서와 페이로드는 로컬 분석 결과입니다. 공개 저장소에 커밋하지 마세요.']
    (out / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return report
