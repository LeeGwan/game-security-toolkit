# Game Security Research Toolkit

> [한국어](./README.md) | English

Windows x64 game security and anti-cheat research toolkit

## ⚠️ Warning

**Educational purposes only.** Do not misuse.

## Features

### 💉 Remote Manual Mapper
- Manual DLL mapping without LoadLibrary
- IAT/TLS/SEH processing
- PE header clearing
- XOR encryption support

### 🛡️ Anti-Cheat
- Memory integrity verification (.text/.rdata hash)
- Hardware breakpoint detection
- Inline syscall detection
- DLL injection detection (PEB traversal)
- Return address validation

### 🪝 Hooking
- JMP hooking (5/14 bytes)
- Syscall-based memory protection
- Return address spoofing
- DirectX 11 Present hook

### 🔧 Utilities
- Pattern scanning
- Inline syscall execution
- PE parser

## Build
```bash
# Visual Studio 2019+ / C++17 / Windows SDK 10.0.19041.0+
git clone https://github.com/yourusername/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
```

## Usage
```cpp
// DLL Injection
RemoteManualMapper mapper;
auto result = mapper.InjectDll(pid, "test.dll", true);

// Anti-Cheat Init
AntiCheat::Initialize(GetModuleHandle(NULL));

// Hooking
void* trampoline = g_HookManager->install_jmp(target, hook, 14);

// Return Spoofing
ret_spoofing::Call(targetFunc, arg1, arg2);
```

## Structure
```
RemoteManualMapper/    # DLL injection
AntiCheat/            # Anti-cheat detection
Hook/                 # Hooking system
Render/               # DirectX hooking
syscall/              # Direct syscalls
```

## Key Techniques

- Manual PE mapping
- SSDT index extraction
- Trampoline hooking
- Stack walking
- PEB/TEB traversal

## License

MIT License

---

**Educational purposes only.**