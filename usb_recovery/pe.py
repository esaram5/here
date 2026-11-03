"""Read-only PE triage. Does not load or execute the supplied EXE/DLL."""
import struct
from pathlib import Path
from .analyze import bounded_read, entropy, sha, write_json
from .capture import FormatError

API_GROUPS = {
    'winusb': ['WinUsb_ReadPipe','WinUsb_WritePipe','WinUsb_ControlTransfer','WinUsb_GetOverlappedResult'],
    'hid': ['HidD_GetFeature','HidD_SetFeature','HidD_GetInputReport','HidD_SetOutputReport'],
    'generic_io': ['ReadFile','WriteFile','DeviceIoControl','CreateFileA','CreateFileW','GetOverlappedResult'],
    'ftdi': ['FT_Read','FT_Write','FT_Open','FT_OpenEx'],
    'libusb': ['libusb_bulk_transfer','libusb_control_transfer','libusb_interrupt_transfer'],
    'crypto': ['CryptDecrypt','CryptEncrypt','BCryptDecrypt','BCryptEncrypt','CryptDeriveKey','BCryptGenerateSymmetricKey'],
    'dynamic_loading': ['LoadLibraryA','LoadLibraryW','GetProcAddress'],
    'message_ui': ['MessageBoxA','MessageBoxW']
}
DEFAULT_NEEDLES = ['already written','already programmed','already exists','이미 쓰여','이미 기록','이미 프로그램']

class PE:
    def __init__(self, data):
        self.data = data
        if data[:2] != b'MZ': raise FormatError('Not an MZ/PE executable')
        pe = self.unpack('<I',0x3c)[0]
        if self.take(pe,4) != b'PE\0\0': raise FormatError('Missing PE signature')
        machine, count, _, _, _, optional_size, _ = self.unpack('<HHIIIHH',pe+4)
        if count > 96: raise FormatError('Excessive PE section count')
        opt = pe+24; self.take(opt,optional_size)
        magic = self.unpack('<H',opt)[0]
        if magic not in (0x10b,0x20b): raise FormatError('Unsupported PE optional header')
        self.bits = 64 if magic == 0x20b else 32
        self.machine = machine
        directory_offset = 112 if self.bits == 64 else 96
        if optional_size < directory_offset: raise FormatError('Short optional header')
        self.image_base = self.unpack('<Q' if self.bits==64 else '<I',opt+(24 if self.bits==64 else 28))[0]
        self.entry_rva = self.unpack('<I',opt+16)[0]
        self.header_size = self.unpack('<I',opt+60)[0]
        directory_count = self.unpack('<I',opt+directory_offset-4)[0]
        if directory_count > (optional_size-directory_offset)//8: raise FormatError('Data directories exceed optional header')
        self.directories = [self.unpack('<II',opt+directory_offset+8*i) for i in range(min(directory_count,16))]
        self.sections = []
        for i in range(count):
            off=opt+optional_size+40*i
            name=self.take(off,8).split(b'\0')[0].decode('ascii','replace')
            vs,va,rs,rp=self.unpack('<IIII',off+8)
            characteristics=self.unpack('<I',off+36)[0]
            raw=self.take(rp,rs) if rs else b''
            self.sections.append(dict(name=name,rva=va,virtual_size=vs,raw_offset=rp,raw_size=rs,
                                      entropy_bits_per_byte=entropy(raw),executable=bool(characteristics&0x20000000)))

    def take(self,offset,size):
        if offset < 0 or size < 0 or offset+size > len(self.data): raise FormatError('PE offset/size exceeds file')
        return self.data[offset:offset+size]

    def unpack(self,fmt,offset):
        return struct.unpack(fmt,self.take(offset,struct.calcsize(fmt)))

    def rva_offset(self,rva,size=1):
        if 0 <= rva and rva+size <= self.header_size:
            self.take(rva,size);return rva
        matches=[]
        for s in self.sections:
            delta=rva-s['rva']
            if 0 <= delta and delta+size <= s['raw_size']:
                off=s['raw_offset']+delta;self.take(off,size);matches.append(off)
        if len(matches)!=1: raise FormatError(f'Unmapped or ambiguous file-backed RVA 0x{rva:x}')
        return matches[0]

    def offset_rva(self,offset):
        if offset < self.header_size:return offset
        matches=[s['rva']+offset-s['raw_offset'] for s in self.sections if s['raw_offset']<=offset<s['raw_offset']+s['raw_size']]
        return matches[0] if len(matches)==1 else None

    def directory(self,index):
        return self.directories[index] if len(self.directories)>index else (0,0)

    def cstring(self,rva):
        # Bounded reads across only mapped bytes; no reading virtual zero-fill as names.
        result=bytearray()
        for i in range(2048):
            value=self.data[self.rva_offset(rva+i)]
            if value==0:return result.decode('ascii','replace')
            result.append(value)
        raise FormatError('Unterminated/oversized import name')

    def imports(self):
        rva,size=self.directory(1)
        if not rva or not size:return []
        imports=[]; width=self.bits//8; high=1<<(self.bits-1)
        for n in range(min(size//20,4096)):
            fields=self.unpack('<IIIII',self.rva_offset(rva+20*n,20))
            if not any(fields):return imports
            lookup,_,_,name,iat=fields
            dll=self.cstring(name)
            for i in range(16384):
                thunk=self.unpack('<Q' if width==8 else '<I',self.rva_offset((lookup or iat)+width*i,width))[0]
                if not thunk:break
                symbol=('#'+str(thunk&0xffff)) if thunk&high else self.cstring(thunk+2)
                if len(imports) >= 50000: raise FormatError('Total imports exceed limit')
                imports.append(dict(dll=dll,name=symbol,iat_rva=iat+i*width))
            else:raise FormatError('Import thunk table exceeds limit')
        raise FormatError('Import descriptors lack terminator within directory size')


def inspect_pe(path, output, needles=None):
    data=bounded_read(path,128*1024*1024); pe=PE(data); warnings=[]
    try: imports=pe.imports()
    except FormatError as exc:
        imports=[]; warnings.append('Import parsing incomplete: '+str(exc))
    if pe.directory(13)[0]:warnings.append('Delay imports present; not decoded by this triage. Inspect them in Ghidra/IDA.')
    hits=[]
    for text in dict.fromkeys(DEFAULT_NEEDLES+(needles or [])):
        if not text or len(text)>256:raise ValueError('Needle must contain 1-256 characters')
        for encoding in ('utf-8','utf-16le','cp949'):
            try:pattern=text.encode(encoding)
            except UnicodeEncodeError:continue
            start=0
            for _ in range(100):
                offset=data.find(pattern,start)
                if offset<0:break
                hits.append(dict(text=text,encoding=encoding,file_offset=offset,rva=pe.offset_rva(offset)))
                start=offset+len(pattern)
            else:warnings.append(f'Needle {text!r} has at least 100 hits; output capped per encoding')
    named={x['name'].lower() for x in imports}
    groups={group:[name for name in names if name.lower() in named] for group,names in API_GROUPS.items()}
    managed=bool(pe.directory(14)[0] and pe.directory(14)[1])
    choice='ILSpy first (.NET CLR directory present; inspect managed/native boundary)' if managed else 'Ghidra or IDA first (no CLR directory; absence does not rule out a managed bundle)'
    report=dict(file_name=Path(path).name,size=len(data),sha256=sha(data),machine=f'0x{pe.machine:04x}',
                bits=pe.bits,image_base=pe.image_base,entry_rva=pe.entry_rva,clr_directory_present=managed,
                sections=pe.sections,imports=imports,api_groups=groups,string_hits=hits,
                suggested_route=choice,warnings=warnings,
                limitations=['No execution, decompilation, xrefs, dynamic imports or unpacking performed.',
                             'API presence is not proof of execution or decryption.',
                             'High section entropy is a hint only, not proof of packing.',
                             'Only exact keyword matches are emitted; missing strings may be encoded or resources.'])
    out=Path(output);out.mkdir(parents=True,exist_ok=False)
    write_json(out/'pe_report.json',report)
    lines=['# EXE/DLL 정적 분석', '',f'- 파일: `{Path(path).name}`',f'- PE: {pe.bits}bit / machine 0x{pe.machine:04x}',
           f'- 권장 경로: {choice}',f'- import 수: {len(imports)}',f'- 문자열 위치 수: {len(hits)}','',
           '## API 단서','']
    lines += [f'- {group}: '+', '.join(names) for group,names in groups.items() if names]
    lines += ['', '## 다음 단계', '', '1. pe_report.json의 문자열 RVA를 decompiler에서 열어 교차 참조를 확인합니다.',
              '2. 통신 API의 호출자를 거슬러 올라가 파일 읽기와 변환 함수를 찾습니다.',
              '3. runtime module base + RVA로 주소를 계산하고 실제 버퍼와 USB 캡처를 비교합니다.',
              '4. x64/x86, 동기/비동기, 파일 handle/장비 handle을 구분합니다.', '', '## 제한', '']
    lines += ['- '+s for s in warnings+report['limitations']]
    (out/'pe_report.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return report
