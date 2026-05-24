# Game Security Research Toolkit
> [English](./README.md) | 한국어
게임 보안 연구 툴킷
한국어 | English

실제 치트 프로그램 리버스 엔지니어링 기반의 Windows x64 게임 보안 연구 툴킷

📋 프로젝트 개요
본 프로젝트는 제가 프리랜서로 활동하며 실제 유통되는 치트 프로그램들을 리버스 엔지니어링하며 학습한 기술적 메커니즘을 정리하고 코드로 직접 재구현해본 개인 연구 저장소입니다.

특정 솔루션에 대한 정답을 제시하기보다, "치트는 어떤 원리로 동작하는가?"를 파헤치기 위해 공격 코드를 분석 및 구현해보고, 다시 보안 엔진 개발자의 입장에서 "이걸 탐지하려면 어떤 로직이 필요할까?"를 깊이 고민하며 연구했던 과정들을 담고 있습니다.

분석 및 학습 과정
공격 기법 분석: 실제 배포된 치트 프로그램 리버싱 및 동작 원리 파악

취약점 식별: 게임 보안 시스템의 우회 가능 지점 분석 및 학습

방어 메커니즘 연구: 분석된 공격을 효과적으로 탐지하기 위한 로직 설계

⚠️ 법적 고지
본 코드는 교육 및 연구 목적으로만 제작되었습니다.

상업적 게임에 대한 무단 사용 금지

악의적 목적의 사용 절대 금지

연구자/개발자의 학습 목적으로만 사용

사용자의 책임 하에 활용

🎯 주요 기능
💉 Remote Manual Mapper (공격 기법 분석)
실제 치트 프로그램에서 사용하는 탐지 우회 기법의 원리 연구 및 구현

LoadLibrary 우회: API 호출 없이 DLL 메모리 매핑 메커니즘 분석

IAT/TLS/SEH 처리: 완전한 PE 로더 재구현을 통한 로딩 과정 이해

PE 헤더 제거: 메모리 상에서 흔적을 지우는 기법 연구

XOR 암호화: 디스크 기반 스캔 우회 분석

🛡️ Anti-Cheat (방어 메커니즘 설계)
분석된 공격 기법을 효과적으로 탐지하기 위한 방어 시스템 연구

메모리 무결성 검증: 코드 세그먼트 해시 검사 (.text/.rdata)

하드웨어 브레이크포인트 탐지: DR0-7 레지스터를 이용한 디버깅 탐지

인라인 Syscall 탐지: 비정상적인 시스템 콜 패턴 및 진입점 분석

DLL 인젝션 탐지: PEB 순회를 통한 미인증 모듈 감지

리턴 주소 검증: 스택 워킹(Stack Walking)을 통한 후킹 유무 판단

패턴 스캔 탐지: 메모리 읽기 시도에 대한 모니터링 로직

🪝 Hooking (공격 및 탐지 연구)
다양한 후킹 기법의 구현 방식과 그에 따른 탐지 방법 분석

JMP 후킹: 5/14 바이트 트램펄린 구조 이해

Syscall 기반 메모리 보호: ntdll 후킹을 우회하는 시스템 콜 분석

리턴 주소 스푸핑: 콜스택 은폐 원리 및 탐지 로직 연구

DirectX 11 Present 후킹: 렌더링 파이프라인 인터셉트 과정 분석

🔧 Utilities
고급 패턴 스캐닝 (IDA 스타일 패턴 분석)

인라인 Syscall 실행기 구현

PE 파일 구조 분석을 위한 파서

🔬 핵심 연구 기술
공격자의 관점 (Offensive)
Manual Mapping: PE 구조의 완벽한 이해와 메모리 직접 매핑 기술

SSDT 인덱스 추출: ntdll을 거치지 않는 커널 함수 호출 연구

API 후킹: IAT/Inline/Trampoline 기법의 원리 파악

Memory Protection Bypass: 메모리 보호 속성 변경을 통한 탐지 우회 연구

방어자의 관점 (Defensive)
Integrity Checking: CRC32/MD5 기반의 실시간 무결성 검증 설계

Stack Walking: 호출 경로 추적을 통한 비정상 실행 흐름 탐지

PEB/TEB 분석: 프로세스 및 스레드 환경 블록을 이용한 검증

Hardware Debugging Detection: DR 레지스터 모니터링을 통한 분석 방해 탐지

🏗️ 프로젝트 구조
RemoteManualMapper/    # [분석] 수동 DLL 인젝션 메커니즘
AntiCheat/             # [연구] 분석 기반 치트 탐지 시스템
Hook/                  # [분석] 다양한 후킹 및 우회 기법
Render/                # [분석] D3D11 렌더링 인터셉트 연구
syscall/               # [분석] 직접 시스템콜 호출 구조
Utils/                 # 공통 유틸리티 및 파서
🛠️ 빌드 및 환경
요구사항

Visual Studio 2019 이상

C++17 표준 이상

Windows SDK 10.0.19041.0 이상

Bash
git clone https://github.com/LeeGwan/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
💡 사용 예제 (연구용 시나리오)
DLL 인젝션 분석 (공격 시뮬레이션)
C++
RemoteManualMapper mapper;
auto result = mapper.InjectDll(targetPid, "payload.dll", true);
if (result.success) {
    std::cout << "Injection at: 0x" << std::hex << result.baseAddress;
}
안티치트 탐지 로직 검증 (방어)
C++
// 게임 초기화 시 보안 모듈 로드
AntiCheat::Initialize(GetModuleHandle(NULL));

// 주기적인 인젝션 모듈 검사
if (AntiCheat::DetectInjectedDll()) {
    // 탐지 시 처리 로직
    TerminateProcess(GetCurrentProcess(), -1);
}
🎓 학습 포인트
초급
PE 파일 구조의 심도 있는 이해

기본적인 DLL 인젝션 및 모듈 로딩 원리

중급
Manual Mapping의 상세 구현 프로세스 학습

Direct Syscall을 통한 시스템 함수 호출 이해

런타임 메모리 무결성 검증 설계

고급
Anti-Anti-Cheat 우회 기법의 원리와 한계 분석

커널 레벨 탐지 메커니즘 연구

실시간 코드 가상화 및 보호 기법으로의 확장 (연구 중)

🔐 보안 고려사항
본 연구를 실제 프로덕션 환경(상용 게임)에 적용할 경우 고려할 점:

커널 드라이버 기반의 더 깊은 보호 계층 필요

암호화 키 관리 및 네트워크 레벨 보안 결합

서버 사이드 검증 로직과의 유기적 연동

📝 라이선스
MIT License - 개인 학습 및 연구 목적으로만 활용해 주세요.

📬 연락처
프로젝트 관련 문의 및 기술 교류: [tlkj12@gmail.com]

⚡ 핵심 강조: 본 프로젝트는 실제 치트 프로그램 리버스 엔지니어링을 통해 얻은 공격자의 통찰과, 이를 방어하기 위해 연구한 보안 엔지니어의 로직을 한데 모은 기록입니다. 제가 리버싱을 공부하며 삽질했던 경험들이 다른 보안 연구자분들에게도 도움이 되길 바랍니다.

🎯 주요 관심사: #안티치트_개발 #리버스_엔지니어링 #게임_보안 #취약점_분석
