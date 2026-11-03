# USB 프로그램 리버싱 경로

검토 기준일: 2026-11-04. 실제 대상 EXE/DLL은 아직 제공되지 않아, 아래는 구현된 정적 분석과 조사 절차입니다.
USB 분석기/오프라인 모사를 먼저 완료한 뒤 추가했습니다.

## 결론

프로그램이 파일을 복호화하고 USB로 보내는 구조라면, 송신 버퍼의 생성자를 찾는 것이
장비 전체 프로토콜 모사보다 직접적일 수 있습니다. 상태 확인 이전에 복호화했다면
“이미 쓰여 있음”으로 멈추더라도 파일 변환 함수나 메모리 버퍼를 찾을 가능성이 있습니다.
반대로 복호화가 장비에서 일어나면 PC 리버싱만으로 평문을 확보할 수 있다고 보장할 수 없습니다.

## 도구 선택

| 조건 | 우선 경로 | 역할/제한 |
| --- | --- | --- |
| CLR directory가 있는 .NET PE | ILSpy | 관리 코드의 파일 로딩, 변환, P/Invoke, 메시지 처리 확인 |
| native x86/x64 PE | Ghidra 또는 보유한 IDA | 문자열·imports의 cross-reference와 호출자 추적 |
| AI 보조가 필요 | REA + 지원되는 분석 엔진 | 탐색·설명 보조; 실제 어셈블리/버퍼와 검증 |
| 실행 중 버퍼 확인 | x64dbg/x32dbg | API 진입·완료 지점에서 데이터 확인 |
| 난독화/packing/런타임 해석 | 별도 unpacking·runtime 조사 | import 없음/높은 entropy만으로 결론 내리지 않음 |

최근 도구의 정확한 이름은 아직 확인되지 않았습니다. 후보로 검토한 REA의 공식 출처는
[morluto/rea](https://github.com/morluto/rea)입니다. Ghidra/Hopper/IDA 등의 엔진을 연결하는 도구이며,
프로그램 전체 소스나 비밀키가 자동으로 복원된다는 의미는 아닙니다.
공식 README는 Windows Ghidra 지원을 experimental로 안내합니다.
[IDA 9.5 Beta](https://hex-rays.com/blog/ida-9.5-beta-is-available)는 공식 MCP와 Assist를 안내하지만,
이 프로젝트를 위해 유료 라이선스를 먼저 구매할 필요는 없습니다.

REA 설치를 선택할 때는 공식 저장소의 현재 안내를 확인합니다. 일반 진입 명령은 다음과 같습니다.
이 저장소의 스크립트가 해당 도구를 자동 설치하거나 MCP 설정을 변경하지는 않습니다.

```text
npx rea-agents setup
```

MCP 설치가 이 ChatGPT 대화에 자동으로 연결되는 것은 아닙니다. 로컬 MCP를 지원하는 클라이언트의
설정과 분석 엔진이 필요합니다. 이 프로젝트의 `inspect-pe`는 별도 MCP 없이 실행됩니다.

## 1. 실행하지 않고 대상 분류

```powershell
py -3 -m usb_recovery inspect-pe "C:\path\writer.exe" --out static_writer --needle "이미 쓰여 있음"
```

또는 EXE/DLL을 `Inspect.cmd` 위에 드래그합니다.
프로그램과 같은 폴더의 통신 DLL도 각각 다른 output 이름으로 분석할 수 있습니다.

결과 `pe_report.json` / `pe_report.md`에는 다음이 포함됩니다.

- PE32/PE32+와 machine, image base, entry RVA.
- CLR directory 존재 여부(.NET 후보; native host/bundle을 완전히 분류하지는 못함).
- section의 크기와 entropy.
- 실제 일반 import table: DLL, symbol/ordinal, IAT RVA.
- WinUSB/HID/FTDI/libusb/generic I/O/암호화/동적 로딩/API 단서.
- 기본 오류 문구와 `--needle` 문자열의 UTF-8/UTF-16LE/CP949 정확 일치 위치.
- 파일 offset과 대응 RVA. ASLR 환경에서는 runtime module base + RVA를 사용.

최대 입력 128 MiB입니다. 일반 imports만 해석하며 delay imports는 존재를 알리고 별도 분석 대상으로 표시합니다.
동적 GetProcAddress, bound IAT, packing, 암호화 문자열, .NET 리소스는 누락될 수 있습니다.
이 도구는 디컴파일러가 아니며 호출자 cross-reference나 실행 경로를 자동 복원하지 않습니다.

## 2. 두 방향에서 함수 추적

### 오류 메시지에서 시작

1. 실제 메시지 원문을 검색하고 code cross-reference를 찾습니다.
2. 메시지를 표시하는 함수 직전 비교/조건 분기를 확인합니다.
3. 비교 대상이 USB 응답, 파일 ID, checksum, 로컬 설정 중 무엇인지 추적합니다.
4. 값의 생성 지점, 비교 폭/endianness, call stack을 기록합니다.
5. 분기를 강제로 바꾸기 전에, 복호화가 이 검사 전후 어느 쪽에 있는지 확인합니다.

### 송신 API에서 시작

1. import에서 발견한 USB 함수의 caller를 찾습니다.
2. 송신 buffer와 length의 생성자를 추적합니다.
3. 파일 읽기 → 변환 → packet framing → 송신 사이의 중간 buffer를 구분합니다.
4. 암호 라이브러리가 없으면 XOR/add/sub/shift/table lookup도 후보지만,
   명령 한두 개로 알고리즘을 확정하지 않습니다.
5. 이전 분석기의 `boundaries.json`과 실제 USB payload를 대조합니다.

## 3. 동적 확인 지점

아래는 Microsoft x64 ABI에서 함수 **진입 시점** 기준입니다.
호출 후에는 volatile register가 바뀔 수 있으므로 포인터와 요청 길이를 미리 기록합니다.

| 함수 | Buffer | 요청 Length | 관찰 시점 |
| --- | --- | --- | --- |
| WinUsb_WritePipe | R8 | R9D | 호출 직전/진입: 송신 예정 데이터 |
| WinUsb_ReadPipe | R8 | R9D | 완료 후: 실제 수신 길이만 사용 |
| WriteFile | RDX | R8D | handle이 대상 장비인지 확인 후 진입 |
| ReadFile | RDX | R8D | 장비 handle과 완료 후 실제 길이 확인 |

x86 stdcall 함수 진입 시 WinUsb_WritePipe/ReadPipe는 buffer=[ESP+0x0C],
length=[ESP+0x10]입니다. WriteFile/ReadFile은 buffer=[ESP+0x08], length=[ESP+0x0C]입니다.
함수 프롤로그 이후의 ESP나 다른 calling convention에는 그대로 적용하지 않습니다.

x64dbg의 `bp`는 API 이름 또는 주소에 breakpoint를 설정할 수 있습니다.
예를 들어 WinUSB 모듈이 로드되어 symbol이 해석되는 상태에서 `bp WinUsb_WritePipe`로 관찰할 수 있습니다.
import가 실제로 사용되는지, DLL wrapper를 거치는지 확인해야 합니다.

비동기 I/O에서는 API가 돌아왔다고 수신이 끝난 것이 아닙니다. ERROR_IO_PENDING이면
WinUsb_GetOverlappedResult/GetOverlappedResult 등의 완료 경로와 실제 transferred length를 확인합니다.
ReadFile은 파일 읽기에도 사용되므로 모든 ReadFile 버퍼를 장비 데이터라고 분류하지 않습니다.
이 저장소에는 breakpoint 자동 삽입이나 메모리 자동 덤프 기능이 아직 없습니다.

## 4. 관찰 결과에 따른 결정

| 근거 | 다음 구현 |
| --- | --- |
| 상태 검사 전에 변환 완료 | 해당 함수 출력 버퍼를 확보해 독립 디코더 후보 검증 |
| 상태 검사 후에만 변환 | 상태 반환값의 구조부터 검증하고 오프라인 규칙 작성 |
| USB 송신 버퍼가 평문 형식과 일치 | packet header 분리와 block 재조립 |
| 암호화 파일이 그대로 전송 | 장비 복호화 가능성 검토; PC 평문 존재 단정 금지 |
| 장비에서 키/계산 결과를 받음 | 단순 고정 응답 모사로는 충분하지 않을 수 있음 |
| 메시지 출력 전 USB 요청 없음 | 로컬 상태/파일 구조 판단 경로 우선 |

## AI 도구에 줄 조사 요청 예시

```text
이 프로그램의 파일 읽기에서 USB 송신까지 데이터 흐름을 조사하라.
먼저 architecture, CLR 여부, imports를 확인하라.
“이미 쓰여 있음” 메시지 또는 제공한 정확 문구의 cross-reference를 찾고
그 분기의 입력값이 어디서 생성되는지 추적하라.
WinUSB/HID/FTDI/libusb 또는 장비 handle에 연결된 I/O만 구분하라.
함수 이름, RVA, 호출 관계, buffer/length의 근거를 기록하라.
관찰한 사실과 가설을 분리하고, 가설마다 필요한 검증을 적어라.
암호 알고리즘이나 정상 응답 바이트를 근거 없이 만들지 마라.
이번 조사에서는 장비 쓰기, 응답 패치, 실행 파일 변경을 수행하지 마라.
```

## 제공할 결과

`pe_report.json`, USB 분석 `report.json`, 해당 분기의 pseudocode/assembly와 주소,
실제 메시지 발생 시점이 있으면 다음 구현을 좁힐 수 있습니다.
대상 EXE 또는 해당 분석 결과가 없으므로 지금은 실제 알고리즘이나 정상 응답값을 확정할 수 없습니다.

## 1차 자료

- [REA 공식 저장소](https://github.com/morluto/rea)
- [ILSpy 공식 저장소](https://github.com/icsharpcode/ILSpy)
- [Microsoft PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [WinUsb_WritePipe](https://learn.microsoft.com/en-us/windows/win32/api/winusb/nf-winusb-winusb_writepipe)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
- [x64dbg SetBPX](https://help.x64dbg.com/en/latest/commands/breakpoint-control/SetBPX.html)
