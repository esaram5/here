# USB Recovery Diagnostic

Windows USB 통신을 관찰하여 과거에 만든 암호화 파일의 복원 경로를 찾는 프로젝트입니다.
기존 장비 쓰기 프로그램이 표시하는 **“이미 쓰여 있음”** 메시지 전후의 통신을 수집하고,
PC에서 복호화하는지, 장비가 복호화하는지, 어느 함수에서 데이터를 확보할 수 있는지 분석합니다.

## 현재 상태

- v1.0 수집기 + v0.2 분석기: 결과 ZIP/PCAP/PCAPNG 분석, 스트림 추출, 반복 실행 비교, 오프라인 상태 기반 모사.
- [자동 테스트 32개 및 CLI 검증 통과](docs/VALIDATION.md). 실제 Windows 장비에서의 실행 검증은 아직 수행하지 않았습니다.
- 오프라인 응답 규칙 모사는 구현했습니다. 실제 USB 응답 교체, 메모리 덤프, 복호화 기능은 아직 없습니다.
- 알려진 API 이름 검색은 단서 수집이며 import table 분석이나 동적 호출 추적이 아닙니다.

## 결과 분석

[분석 및 모사 사용법](docs/ANALYSIS.md)을 참고하세요. 분석기는 Python 3.10+가 필요하며 추가 패키지는 없습니다.

```powershell
py -3 -m usb_recovery analyze results_....zip --out analysis_first
py -3 -m unittest discover -s tests -v
```

## EXE 리버싱 준비

USB 분석 이후 [리버싱 조사 절차와 도구 비교](docs/REVERSING.md)를 사용할 수 있습니다.
`inspect-pe`는 EXE를 실행하지 않고 PE/import/문자열 위치를 분석합니다.

```powershell
py -3 -m usb_recovery inspect-pe "C:\path\writer.exe" --out static_writer --needle "이미 쓰여 있음"
```

`Inspect.cmd` 위에 EXE를 드래그해도 됩니다. 실제 장비 응답 패치나 대상 프로그램 실행은 하지 않습니다.

## 파일

| 파일 | 역할 |
| --- | --- |
| `Run.cmd` | Windows 실행 진입점 |
| `Collect.ps1` | PowerShell 진단 및 캡처 스크립트 |
| `README_KO.txt` | 상세 실행 안내 |
| `README.md` | 프로젝트 개요 및 진행 계획 |
| `Analyze.cmd` | 결과 ZIP 분석 실행 |
| `Inspect.cmd` | EXE/DLL 정적 분석 실행 |
| `usb_recovery/` | Python 분석기 및 오프라인 모사 |
| `tests/`, `examples/` | 자동 테스트 및 가상 데이터 |

## 준비 및 실행

1. 저장소를 다운로드하거나 clone하여 쓰기 가능한 폴더에 둡니다.
2. Windows 10/11과 Windows PowerShell 5.1을 사용합니다. Python은 필요 없습니다.
3. USB 캡처에는 [Wireshark/TShark](https://www.wireshark.org/download.html)와
   [USBPcap](https://desowin.org/usbpcap/)이 필요합니다. 설치 후 요청되는 재부팅을 완료합니다.
4. 장비를 연결하고 `Run.cmd`를 우클릭하여 **관리자 권한으로 실행**합니다.
5. 기존 장비 쓰기 프로그램의 EXE를 선택합니다. 수집기는 이를 자동 실행하지 않습니다.
6. 암호화 입력 파일의 메타데이터 수집 여부를 선택합니다.
7. 대상 장비가 연결된 USBPcap 인터페이스와 캡처 시간(기본 45초)을 선택합니다.
8. 캡처 시작 안내 후 기존 프로그램을 직접 실행하고 “이미 쓰여 있음” 메시지를 재현합니다.
9. 메시지 원문과 발생 시점을 입력합니다. 결과 ZIP이 탐색기에 표시됩니다.

USBPcap 인터페이스가 여러 개라면 Wireshark의 USBPcap 설정에서 장비 목록과 root hub를 확인합니다.
잘못된 인터페이스를 선택하면 패킷이 존재하더라도 대상 장비 통신은 누락될 수 있습니다.
캡처 도구가 없어도 정보 수집만 진행할 수 있습니다.

## 결과 전달

생성되는 `results_날짜_시간_식별자.zip`을 분석 대화에 첨부합니다.
오류가 발생했을 때도 ZIP의 로그를 바탕으로 다음 단계를 정할 수 있습니다.

| 주요 결과 | 분석 용도 |
| --- | --- |
| `application.json`, `neighbor_files.json` | 프로그램 버전과 DLL 구성 |
| `api_name_hints.json`, `loaded_module_names.json` | 통신 API 후보 |
| `usb_devices.json`, `usb_drivers.json` | VID/PID 및 드라이버 |
| `capture.pcapng` | 실제 요청/응답 데이터 |
| `usb_frames.csv`, `packet_count.txt` | 프레임 요약과 캡처 상태 |
| `observations.json` | 메시지와 발생 시점 |
| `issues.json`, 오류 로그 | 실패 원인 |

일부 파일은 해당 단계를 건너뛰거나 실패하면 생성되지 않습니다.
EXE/DLL 원문과 입력 파일 전체는 ZIP에 포함하지 않습니다.
입력 파일을 선택한 경우 이름, 크기, SHA256, 앞 64바이트를 기록합니다.
USB 캡처에는 실제 페이로드와 같은 root hub의 다른 장비 통신이 포함될 수 있습니다.
장비 ID에는 일련번호가 들어갈 수 있습니다. 결과와 원본 데이터는 Git에 커밋하지 않습니다.
수집기는 네트워크로 결과를 업로드하지 않습니다.

## 분석 계획

1. 캡처가 대상 장비를 포함하는지 확인하고 endpoint와 전송 방향을 구분합니다.
2. “이미 쓰여 있음” 메시지 직전 요청/응답을 식별합니다.
3. PC 내부 판단인지 장비 응답에 따른 중단인지 구분합니다.
4. 동일 파일의 반복 실행을 비교하여 고정 필드와 세션/카운터 필드를 분리합니다.
5. 프로그램 통신 함수 경계에서 응답을 모사하고 송신 버퍼를 저장할 수 있는지 검토합니다.
6. 블록 번호, 주소, 길이, 체크섬을 확인하여 데이터 재조립 및 검증을 수행합니다.

정상 응답값은 실패 응답만 보고 임의로 확정하지 않습니다.
응답 모사를 구현할 경우 쓰기 단계 전체를 모사할지 검토하며, 실제 장비로 쓰기 요청을
그대로 전달하는 방식과 구분합니다. 현재 수집기는 응답을 바꾸지 않지만,
사용자가 직접 실행하는 기존 프로그램은 정상적인 쓰기 작업을 수행할 수 있습니다.

## 복원 성공 기준

- 추출한 데이터의 크기, 블록 순서, 주소 및 체크섬 등 검증 가능한 조건을 만족할 것.
- 파일과 전송 데이터의 차이만으로 복호화 성공이라 판단하지 않을 것.
- 장비에 쓰이는 데이터 복원과 원본 파일의 바이트 단위 복원을 구분할 것.
- PC 복호화 여부가 확인되지 않으면 USB 데이터가 평문이라고 가정하지 않을 것.

## 다음 실행 기록

- Windows 버전:
- 프로그램 이름/버전:
- 장비 이름 및 VID/PID:
- 선택한 USBPcap 인터페이스:
- 메시지 원문:
- 메시지 발생 시점:
- 결과 ZIP / 캡처 유무:
- 재현 횟수:
