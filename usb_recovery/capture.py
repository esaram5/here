"""Bounded PCAP/PCAPNG reader; USBPcap header is always little endian.

References: desowin.org/usbpcap/captureformat.html; pcapng/pcapng specification.
Only LINKTYPE_USBPCAP (249) is decoded. No dependency on class dissectors.
"""
from dataclasses import dataclass
import struct

MAX_INPUT = 256 * 1024 * 1024
MAX_PACKET = 16 * 1024 * 1024
MAX_PACKETS = 500_000

class FormatError(ValueError):
    pass

@dataclass
class Packet:
    frame: int
    section: int
    interface: int
    timestamp: float | None
    linktype: int
    data: bytes
    original_length: int

@dataclass
class USB:
    packet: Packet
    irp: int
    status: int
    function: int
    complete: bool
    bus: int
    device: int
    endpoint: int
    transfer: int
    stage: int | None
    declared_length: int
    payload: bytes
    truncated: bool

    @property
    def direction(self):
        return 'IN' if self.endpoint & 0x80 else 'OUT'

    @property
    def key(self):
        return (self.packet.section, self.packet.interface, self.bus, self.device, self.irp)


def options(data, endian):
    pos = 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise FormatError('Truncated PCAPNG option header')
        code, size = struct.unpack_from(endian + 'HH', data, pos)
        pos += 4
        if code == 0:
            if size != 0:
                raise FormatError('Invalid option terminator')
            return
        end = pos + ((size + 3) & ~3)
        if end > len(data):
            raise FormatError('Truncated PCAPNG option value')
        yield code, data[pos:pos + size]
        pos = end


def read_packets(data):
    if len(data) > MAX_INPUT:
        raise FormatError('Input exceeds 256 MiB; split the capture first')
    magic = data[:4]
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
               b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9)}
    if magic in formats:
        endian, resolution = formats[magic]
        if len(data) < 24:
            raise FormatError('Truncated PCAP header')
        major, minor, _, _, snaplen, network = struct.unpack_from(endian + 'HHIIII', data, 4)
        if (major, minor) != (2, 4):
            raise FormatError('Only PCAP 2.4 is supported')
        pos, frame = 24, 0
        while pos < len(data):
            if pos + 16 > len(data):
                raise FormatError('Truncated PCAP record header')
            sec, subsec, size, original = struct.unpack_from(endian + 'IIII', data, pos)
            pos += 16
            if size > MAX_PACKET or size > original or (snaplen and size > snaplen) or pos + size > len(data):
                raise FormatError('Invalid/truncated PCAP packet length')
            frame += 1
            if frame > MAX_PACKETS:
                raise FormatError('Too many packets; split capture')
            yield Packet(frame, 0, 0, sec + subsec * resolution, network & 0xffff,
                         data[pos:pos + size], original)
            pos += size
        return
    if magic != b'\x0a\x0d\x0d\x0a':
        raise FormatError('Not a PCAP or PCAPNG file')
    pos, frame, section = 0, 0, -1
    endian, interfaces = None, []
    while pos < len(data):
        if pos + 12 > len(data):
            raise FormatError('Truncated PCAPNG block')
        is_section = data[pos:pos + 4] == b'\x0a\x0d\x0d\x0a'
        if is_section:
            bom = data[pos + 8:pos + 12]
            endian = {b'\x4d\x3c\x2b\x1a': '<', b'\x1a\x2b\x3c\x4d': '>'}.get(bom)
            if endian is None:
                raise FormatError('Invalid PCAPNG byte order magic')
        kind, size = struct.unpack_from(endian + 'II', data, pos)
        if size < 12 or size % 4 or size > MAX_PACKET + 65536 or pos + size > len(data):
            raise FormatError('Invalid/truncated PCAPNG block length')
        if struct.unpack_from(endian + 'I', data, pos + size - 4)[0] != size:
            raise FormatError('PCAPNG trailing block length mismatch')
        body = data[pos + 8:pos + size - 4]
        pos += size
        if is_section:
            if len(body) < 16 or struct.unpack_from(endian + 'HH', body, 4) != (1, 0):
                raise FormatError('Only PCAPNG section version 1.0 is supported')
            section += 1
            interfaces = []
        elif kind == 1:
            if len(body) < 8:
                raise FormatError('Truncated interface description')
            link, _, snap = struct.unpack_from(endian + 'HHI', body)
            resolution, offset = 1e-6, 0
            for code, value in options(body[8:], endian):
                if code == 9:
                    if len(value) != 1:
                        raise FormatError('Invalid if_tsresol')
                    v = value[0]
                    resolution = (2 if v & 128 else 10) ** -(v & 127)
                elif code == 14:
                    if len(value) != 8:
                        raise FormatError('Invalid if_tsoffset')
                    offset = struct.unpack(endian + 'q', value)[0]
            interfaces.append((link, snap, resolution, offset))
        elif kind in (6, 2, 3):
            if kind in (6, 2):
                if len(body) < 20:
                    raise FormatError('Truncated packet block')
                if kind == 6:
                    interface, hi, lo, caplen, original = struct.unpack_from(endian + 'IIIII', body)
                else:
                    interface, _, hi, lo, caplen, original = struct.unpack_from(endian + 'HHIIII', body)
                begin, ticks = 20, (hi << 32) | lo
            else:
                if len(body) < 4 or not interfaces:
                    raise FormatError('Invalid simple packet block')
                interface, begin, ticks = 0, 4, None
                original = struct.unpack_from(endian + 'I', body)[0]
                caplen = min(original, interfaces[0][1] or original)
            if interface >= len(interfaces):
                raise FormatError('Packet refers to an undefined interface')
            link, snap, resolution, offset = interfaces[interface]
            if caplen > MAX_PACKET or caplen > original or (snap and caplen > snap) or begin + ((caplen + 3) & ~3) > len(body):
                raise FormatError('Invalid/truncated PCAPNG packet data')
            frame += 1
            if frame > MAX_PACKETS:
                raise FormatError('Too many packets; split capture')
            timestamp = None if ticks is None else ticks * resolution + offset
            yield Packet(frame, section, interface, timestamp, link, body[begin:begin + caplen], original)


def decode_usb(p):
    if p.linktype != 249:
        return None
    if len(p.data) < 27:
        raise FormatError(f'Frame {p.frame}: truncated USBPcap header')
    length, irp, status, function, info, bus, device, ep, transfer, declared = struct.unpack_from('<HQIHBHHBBI', p.data)
    if length < 27 or length > len(p.data):
        raise FormatError(f'Frame {p.frame}: invalid USBPcap header length')
    stage = None
    if transfer == 2:
        if length < 28:
            raise FormatError(f'Frame {p.frame}: missing control stage')
        stage = p.data[27]
    available = p.data[length:]
    return USB(p, irp, status, function, bool(info & 1), bus, device, ep, transfer, stage,
               declared, available[:declared], len(available) < declared or len(p.data) < p.original_length)
