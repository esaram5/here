# USB 결과 분석 및 오프라인 모사

## 실행 조건

분석기는 Python 3.10 이상과 표준 라이브러리만 사용합니다. 분석 PC에는 Wireshark가 없어도 됩니다.
기존 수집기 `Run.cmd`는 여전히 Python 없이 사용할 수 있습니다.

Windows에서 ZIP/PCAP을 `Analyze.cmd` 위에 드래그하거나 다음 명령을 실행합니다.
출력 폴더는 새 이름이어야 합니다. 기존 분석 결과를 덮어쓰지 않습니다.

```powershell
py -3 -m usb_recovery analyze "results_....zip" --out analysis_first
py -3 -m usb_recovery analyze "results_....zip" --bus 1 --device 5 --out analysis_target
py -3 -m usb_recovery analyze first.zip --compare second.zip --input-file encrypted.dat --out analysis_compare
```

Linux/macOS는 `py -3` 대신 `python3`을 사용합니다. 파일 이름은 실제 파일로 바꿉니다.
장비 선택 값은 첫 보고서의 장비 목록에서 확인합니다. VID/PID에서 device 주소를 자동 추정하지 않습니다.
`--marker 2.5`는 선택된 USB 프레임 중 첫 timestamp로부터 2.5초 이내의 마지막 20개 데이터 프레임을 보여 줍니다.
UI 메시지의 시각을 실제로 기록했을 때만 사용하세요. v1 수집기의 텍스트 관찰값은 정확한 timestamp가 아닙니다.

## 출력

| 파일 | 내용 |
| --- | --- |
| report.md | 한국어 요약과 다음 단계 |
| report.json | 수치, 메타데이터, 비교 및 입력 파일 일치 결과 |
| frames.json | 모든 선택 USB 프레임, 상태, SETUP, payload hex |
| timeline.csv | 시간순 프레임과 IRP 제출/완료 관계 |
| boundaries.json | 추출 스트림의 offset과 원래 프레임 관계 |
| streams/*.bin | bulk/interrupt 데이터 단계의 연결 결과 |

`report.json`과 `frames.json`을 먼저 분석에 전달하고, 바이트 재조립이 필요할 때 원본 ZIP도 전달합니다.
control/isochronous는 자동 스트림 연결 대상이 아닙니다. control 데이터는 frames.json에 남고,
isochronous 데이터는 개별 iso descriptor 검증 전 원시 payload로만 취급합니다.

## 예상 관찰과 구현된 처리

| 관찰 | 도구의 처리 | 다음 판단 |
| --- | --- | --- |
| 캡처 없음 | 메타데이터 전용 보고서 | USBPcap 설치·인터페이스 확인 |
| 여러 장비 통신 | 장비 목록과 분리된 스트림 | bus/device 선택 후 재분석 |
| 요청·완료에 같은 데이터 | bulk/interrupt의 OUT 제출, IN 성공 완료만 선택 | transport 중복 제거 |
| 같은 데이터가 실제로 반복 전송 | 삭제하지 않고 반복 횟수 표시 | 재시도인지 프로토콜 의미인지 별도 확인 |
| 오류 완료 / 잘린 payload | 스트림에서 제외, 원시 프레임 보존 | 정상 전체 캡처 확보 |
| 제출만 있고 완료 없음 | OUT을 시도된 데이터로 보존하고 경고 | 전달 성공으로 해석하지 않음 |
| 두 실행의 바이트가 동일 | 동일성·SHA256 표시 | 결정적 변환의 단서, 복호화 증명 아님 |
| 일부 바이트가 다름 | 동일 offset 차이 최대 128개 표시 | 주소 변경/삽입 시 정렬부터 재검토 |
| 암호화 파일 조각과 일치 | 시작·중간·끝 sample 및 전체 파일 검색 | 짧고 반복적인 패턴은 우연 가능 |
| 짧은 IN 응답 후 정지 | 마지막 프레임 후보 표시 | API/문자열 분기와 대조해야 의미 확정 |

## 오프라인 응답 모사

```powershell
py -3 -m usb_recovery simulate examples/toy_rules.json examples/toy_requests.json --out simulation_demo
```

예제의 `10 → 9000`, `20 → 91`, `30 → 9200`은 전부 가상 프로토콜입니다.
실제 장비의 명령이나 정상 응답이라고 사용하면 안 됩니다.

규칙 필드:

- `state`, `next_state`: 현재/다음 상태.
- `expect_hex`: 정확한 요청 길이와 기대 바이트.
- `mask_hex`: 선택 사항. FF는 해당 비트 비교, 00은 무시. 길이는 기대 요청과 동일.
- `response_hex`: 명시적으로 정한 응답.
- `echo`: 요청의 `[start,end)` 구간을 응답 offset으로 복사하는 선택 기능.
- `save_range`: 요청의 `[start,end)`를 saved_payload.bin에 저장.

매 단계 하나의 규칙만 일치해야 합니다. 일치 없음/중복 일치/최종 상태 미도달은 실패합니다.
기본 성공 응답, 자동 체크섬 추정, USB 전송, DLL hooking은 없습니다.
이 모사는 규칙 자체를 검증하며 기존 Windows 프로그램에 가짜 장비를 연결하지 않습니다.

## 재현 가능한 자체 검증

```powershell
py -3 -m unittest discover -s tests -v
py -3 examples/make_demo.py demo.pcap
py -3 -m usb_recovery analyze demo.pcap --out analysis_demo
```

가상 캡처의 기대 결과: USB 6프레임, 2개 스트림, OUT 15바이트, IN 2바이트.
가상 모사의 저장 결과: `HELL` 4바이트, 최종 상태 `done`.
실제 Windows USB 하드웨어 테스트는 아직 수행하지 않았습니다.

## 지원 범위와 한계

- PCAP 2.4: 양쪽 endian, micro/nanosecond timestamp.
- PCAPNG 1.0: SHB/IDB/EPB/SPB 및 구형 packet block, 다중 section/interface,
  timestamp resolution/offset. 알 수 없는 블록은 건너뜁니다.
- USBPcap LINKTYPE 249만 USB로 해석. Linux usbmon/hardware analyzer 형식은 지원하지 않습니다.
- 입력 256 MiB, 패킷 16 MiB, 패킷 수 500,000개 제한. 초과 파일은 나누어 분석합니다.
- ZIP은 디스크에 추출하지 않고 알려진 메타데이터와 캡처만 읽습니다. 여러 캡처 ZIP은 거부합니다.
- IRP ID는 application 명령 ID가 아닙니다. OUT과 뒤따르는 IN을 임의로 요청/응답 쌍으로 만들지 않습니다.
- 재연결로 같은 USB 주소가 재사용되면 같은 section의 스트림이 섞일 수 있습니다. 재연결별로 캡처를 분리하세요.
- 높은 entropy만으로 압축과 암호화를 구분할 수 없습니다. bin 출력은 원본 파일이라고 보장하지 않습니다.
- 원본/복원 파일, 캡처, 분석 보고서는 공개 저장소에 올리지 않습니다.

## 구현 근거

- [USBPcap capture format](https://desowin.org/usbpcap/captureformat.html)
- [USBPcap capture limitations](https://desowin.org/usbpcap/capture_limitations.html)
- [PCAPNG format working draft](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html)
- [Wireshark USB reference](https://www.wireshark.org/docs/dfref/u/usb.html)
