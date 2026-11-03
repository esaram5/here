# 검증 기록

2026-11-04, Linux / Python 3 환경에서 실행했습니다.

- `python3 -m unittest discover -s tests -v`: 32개 통과.
- 가상 USBPcap PCAP → analyze CLI → report.json / streams 검증: 6프레임, OUT 15바이트, IN 2바이트.
- 명시적 가상 프로토콜 → simulate CLI: 최종 상태 done, 저장 payload `HELL`.
- PE32/PE32+ 합성 fixture → inspect-pe CLI: 실행 없이 보고서 생성.
- GNU objdump가 PE32 fixture의 winusb.dll / WinUsb_WritePipe import를 동일하게 해석함을 확인.

테스트 범위: 양쪽 byte order, timestamp 단위와 offset, PCAPNG 다중 section, 단순 packet block,
잘못된 길이/인터페이스, control stage, IRP 재사용, 제출/완료 중복, 전송 실패,
잘린 payload, ZIP 메타데이터와 다중 캡처 거부, byte 비교, 모사 상태/마스크/echo/범위,
PE 헤더/일반 import/ordinal/IAT fallback/CLR/문자열 위치/오류 경고.

실제 Windows 장비, 실제 수집 결과, batch launcher, Ghidra/IDA/REA 연동은 아직 검증하지 않았습니다.
실제 장비 프로토콜의 정상 응답값이나 복호화 알고리즘을 확인했다는 의미가 아닙니다.
