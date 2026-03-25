XML Network Scanner

XML 파일 기반으로 장비 목록을 불러와 네트워크 상태를 확인하는 간단한 스캐너입니다.
Ping만 사용하는 방식의 한계를 보완하기 위해 포트, 웹 응답, ARP 정보까지 함께 확인합니다.

주요 기능
XML 장비 목록 로드
IP / Hostname 기반 장비 관리 (추가, 수정, 삭제)
네트워크 상태 점검
Ping 체크
주요 포트 확인 (HTTP, HTTPS, RDP 등)
웹 서비스 여부 확인
ARP 캐시 기반 보조 판단
결과 테이블 UI 제공
CSV 내보내기
PyInstaller를 이용한 exe 빌드 지원
동작 방식

단순 Ping 결과만으로 판단하지 않고 아래 조건을 조합해서 상태를 판단합니다.

is_up = ping_ok or open_ports or arp_seen
Ping 실패해도 포트가 열려 있으면 UP으로 판단
같은 네트워크에서 ARP에 존재하면 장비 존재로 판단
실행 방법
python scanner.py
exe 빌드
build_exe_onedir.bat

빌드 결과:

dist/XMLNetworkScanner/XMLNetworkScanner.exe
사용 시 참고
포트 스캔이 포함되어 있어 보안 장비(IPS/NAC 등)에 로그가 남을 수 있음
내부 네트워크 점검 용도로 사용하는 것을 권장
대량 스캔 시 네트워크 부하가 발생할 수 있음
개발 환경
Python 3.12.9
Tkinter
ThreadPoolExecutor
PyInstaller
