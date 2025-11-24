# 게임 보안 연구 툴킷
> 한국어 | [English](./README.en.md)

**실제 치트 프로그램 리버스 엔지니어링 기반**의 Windows x64 게임 보안 연구 툴킷

## 📋 프로젝트 개요

본 프로젝트는 **실제 게임 치트 프로그램들을 역공학 분석**하여 발견한 공격 기법들과, 이에 대응하는 **실전 방어 메커니즘**을 구현한 연구용 툴킷입니다.

### 연구 방법론
1. **공격 기법 분석**: 실제 배포된 치트 프로그램 리버싱 및 동작 원리 파악
2. **취약점 식별**: 게임 보안 시스템의 우회 가능 지점 분석
3. **방어 구현**: 분석된 공격에 대한 탐지/차단 메커니즘 개발
4. **검증**: 실제 공격 시나리오로 방어 효과 테스트

## ⚠️ 법적 고지

**본 코드는 교육 및 연구 목적으로만 제작되었습니다.**
- 상업적 게임에 대한 무단 사용 금지
- 악의적 목적의 사용 절대 금지
- 연구자/개발자의 학습 목적으로만 사용
- 사용자의 책임 하에 활용

## 🎯 주요 기능

### 💉 Remote Manual Mapper (공격 기법)
실제 치트 프로그램에서 사용하는 탐지 우회 기법 구현
- **LoadLibrary 우회**: API 호출 없이 DLL 메모리 매핑
- **IAT/TLS/SEH 처리**: 완전한 PE 로더 재구현
- **PE 헤더 제거**: 메모리 상에서 흔적 제거
- **XOR 암호화**: 디스크 스캔 우회

### 🛡️ Anti-Cheat (방어 메커니즘)
분석된 공격 기법에 대한 실전 탐지 시스템
- **메모리 무결성 검증**: 코드 세그먼트 해시 검사 (.text/.rdata)
- **하드웨어 브레이크포인트 탐지**: DR0-7 레지스터 검사
- **인라인 Syscall 탐지**: 비정상 시스템 콜 패턴 분석
- **DLL 인젝션 탐지**: PEB 순회로 불법 모듈 감지
- **리턴 주소 검증**: 스택 워킹으로 후킹 탐지
- **패턴 스캔 탐지**: 메모리 읽기 패턴 모니터링

### 🪝 Hooking (공격 기법)
다양한 후킹 기법 구현 및 분석
- **JMP 후킹**: 5/14 바이트 트램펄린
- **Syscall 기반 메모리 보호**: ntdll 우회
- **리턴 주소 스푸핑**: 콜스택 은폐
- **DirectX 11 Present 후킹**: 렌더링 파이프라인 인터셉트

### 🔧 Utilities
- 고급 패턴 스캐닝 (IDA 스타일)
- 인라인 Syscall 실행기
- PE 파일 파서

## 🔬 핵심 연구 기술

### 공격 기법 (Offensive)
- **Manual Mapping**: PE 구조 분석 및 직접 매핑
- **SSDT 인덱스 추출**: 커널 함수 직접 호출
- **API 후킹**: IAT/Inline/Trampoline 기법
- **Memory Protection Bypass**: VirtualProtect 우회

### 방어 기법 (Defensive)
- **Integrity Checking**: CRC32/MD5 기반 코드 무결성
- **Stack Walking**: 비정상 호출 경로 탐지
- **PEB/TEB 분석**: 프로세스 환경 블록 검증
- **Hardware Debugging Detection**: DR 레지스터 모니터링

## 🏗️ 프로젝트 구조

```
RemoteManualMapper/    # [공격] 수동 DLL 인젝션
AntiCheat/            # [방어] 치트 탐지 시스템
Hook/                 # [공격] 다양한 후킹 기법
Render/               # [공격] D3D11 렌더 후킹
syscall/              # [공격] 직접 시스템콜
Utils/                # 공통 유틸리티
```

## 🛠️ 빌드

**요구사항**
- Visual Studio 2019 이상
- C++17 표준
- Windows SDK 10.0.19041.0 이상

```bash
git clone https://github.com/yourusername/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
```

## 💡 사용 예제

### DLL 인젝션 (공격 시뮬레이션)
```cpp
RemoteManualMapper mapper;
auto result = mapper.InjectDll(targetPid, "payload.dll", true);
if (result.success) {
    std::cout << "Injection at: 0x" << std::hex << result.baseAddress;
}
```

### 안티치트 초기화 (방어)
```cpp
// 게임 시작 시 초기화
AntiCheat::Initialize(GetModuleHandle(NULL));

// 주기적 검사
if (AntiCheat::DetectInjectedDll()) {
    // 치트 탐지 처리
    TerminateProcess(GetCurrentProcess(), -1);
}
```

### 후킹 설치 및 탐지
```cpp
// [공격] 함수 후킹
void* trampoline = g_HookManager->install_jmp(targetFunc, hookFunc, 14);

// [방어] 후킹 탐지
if (AntiCheat::CheckInlineHook(targetFunc)) {
    // 후킹 감지됨
}
```

### 리턴 주소 스푸핑
```cpp
// [공격] 콜스택 은폐
auto result = ret_spoofing::Call<int>(targetFunc, arg1, arg2);

// [방어] 스택 워킹 검증
if (!AntiCheat::ValidateCallStack()) {
    // 비정상 호출 경로 탐지
}
```

## 📚 실전 분석 사례

본 프로젝트에 구현된 기법들은 다음과 같은 실제 치트 프로그램 분석을 기반으로 합니다:

- **메모리 조작 치트**: 패턴 스캔 → 값 변조
- **ESP/WH 치트**: DirectX 후킹 → 렌더링 조작
- **무반동 치트**: 코드 패치 → 물리 계산 우회
- **자동조준**: 엔티티 리스트 탐색 → 뷰매트릭스 연산

각 공격 기법에 대응하는 탐지 메커니즘을 함께 구현했습니다.

## 🎓 학습 포인트

### 초급
- PE 파일 구조 이해
- DLL 인젝션 원리
- 기본 후킹 개념

### 중급
- Manual Mapping 구현
- Syscall 직접 호출
- 메모리 무결성 검증

### 고급
- Anti-Anti-Cheat 우회 기법
- 커널 레벨 탐지
- 실시간 코드 보호

## 🔐 보안 고려사항

본 코드를 실제 프로덕션 환경에 사용할 경우:
- 커널 드라이버 기반 보호 필요
- 암호화 키 하드코딩 제거
- 네트워크 레벨 검증 추가
- 서버 사이드 검증 필수

## 📝 라이선스

MIT License - 교육 및 연구 목적으로만 사용 가능

## 🤝 기여

교육적 가치가 있는 새로운 기법 제안 환영
- 새로운 공격 패턴 분석
- 개선된 탐지 알고리즘
- 성능 최적화

## 📬 연락처

프로젝트 관련 문의: [이메일/GitHub Issues]

---

**⚡ 핵심 강조**: 본 프로젝트는 실제 치트 프로그램 리버스 엔지니어링을 통해 발견한 공격 기법과, 이에 대응하는 방어 메커니즘을 모두 포함합니다. 게임 보안 산업 종사자 및 연구자들의 학습 목적으로 제작되었습니다.

**🎯 대상 독자**: 안티치트 개발자, 게임 보안 연구자, 리버스 엔지니어
