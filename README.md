# 게임 보안 연구 툴킷

> 한국어 | [English](./README.en.md)

Windows x64 게임 보안 및 안티치트 연구용 툴킷

## ⚠️ 주의

**교육 및 연구 목적 전용.** 악용 금지.

## 주요 기능

### 💉 Remote Manual Mapper
- LoadLibrary 없이 DLL 매핑
- IAT/TLS/SEH 처리
- PE 헤더 제거
- XOR 암호화 지원

### 🛡️ Anti-Cheat
- 메모리 무결성 검증 (.text/.rdata 해시)
- 하드웨어 브레이크포인트 탐지
- 인라인 syscall 탐지
- DLL 인젝션 탐지 (PEB 순회)
- 리턴 주소 검증

### 🪝 Hooking
- JMP 후킹 (5/14 바이트)
- Syscall 기반 메모리 보호
- 리턴 주소 스푸핑
- DirectX 11 Present 후킹

### 🔧 Utilities
- 패턴 스캐닝
- 인라인 syscall 실행
- PE 파서

## 빌드
```bash
# Visual Studio 2019+ / C++17 / Windows SDK 10.0.19041.0+
git clone https://github.com/yourusername/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
```

## 사용 예제
```cpp
// DLL 인젝션
RemoteManualMapper mapper;
auto result = mapper.InjectDll(pid, "test.dll", true);

// 안티치트 초기화
AntiCheat::Initialize(GetModuleHandle(NULL));

// 후킹
void* trampoline = g_HookManager->install_jmp(target, hook, 14);

// 리턴 스푸핑
ret_spoofing::Call(targetFunc, arg1, arg2);
```

## 프로젝트 구조
```
RemoteManualMapper/    # DLL 인젝션
AntiCheat/            # 안티치트 탐지
Hook/                 # 후킹 시스템
Render/               # DirectX 후킹
syscall/              # 직접 syscall
```

## 핵심 기술

- PE 수동 매핑
- SSDT 인덱스 추출
- 트램펄린 후킹
- 스택 워킹
- PEB/TEB 순회

## 라이선스

MIT License

---

**교육 목적으로만 사용하세요.**