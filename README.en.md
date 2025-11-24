# Game Security Research Toolkit
> [한국어](./README.md) | English

**Windows x64 game security research toolkit based on real-world cheat reverse engineering**

## 📋 Project Overview

This project is a research toolkit that implements **offensive techniques discovered through reverse engineering actual game cheats** and **practical defensive mechanisms** to counter them.

### Research Methodology
1. **Attack Analysis**: Reverse engineering real-world distributed cheat programs and understanding their mechanisms
2. **Vulnerability Identification**: Analyzing bypass points in game security systems
3. **Defense Implementation**: Developing detection/prevention mechanisms against analyzed attacks
4. **Verification**: Testing defense effectiveness with real attack scenarios

## ⚠️ Legal Notice

**This code is created for educational and research purposes only.**
- Unauthorized use on commercial games is prohibited
- Any malicious use is strictly forbidden
- For learning purposes of researchers/developers only
- Use at your own responsibility

## 🎯 Key Features

### 💉 Remote Manual Mapper (Offensive Technique)
Implementation of detection bypass techniques used in real cheat programs
- **LoadLibrary Bypass**: DLL memory mapping without API calls
- **IAT/TLS/SEH Processing**: Complete PE loader reimplementation
- **PE Header Removal**: Removing traces in memory
- **XOR Encryption**: Disk scan evasion

### 🛡️ Anti-Cheat (Defensive Mechanism)
Practical detection system for analyzed attack techniques
- **Memory Integrity Verification**: Code segment hash checking (.text/.rdata)
- **Hardware Breakpoint Detection**: DR0-7 register inspection
- **Inline Syscall Detection**: Abnormal system call pattern analysis
- **DLL Injection Detection**: Detecting illegal modules via PEB traversal
- **Return Address Validation**: Hook detection through stack walking
- **Pattern Scan Detection**: Memory read pattern monitoring

### 🪝 Hooking (Offensive Technique)
Implementation and analysis of various hooking techniques
- **JMP Hooking**: 5/14-byte trampoline
- **Syscall-based Memory Protection**: ntdll bypass
- **Return Address Spoofing**: Call stack concealment
- **DirectX 11 Present Hook**: Rendering pipeline interception

### 🔧 Utilities
- Advanced pattern scanning (IDA-style)
- Inline syscall executor
- PE file parser

## 🔬 Core Research Techniques

### Offensive Techniques
- **Manual Mapping**: PE structure analysis and direct mapping
- **SSDT Index Extraction**: Direct kernel function calls
- **API Hooking**: IAT/Inline/Trampoline techniques
- **Memory Protection Bypass**: ZwProtectVirtualMemory evasion

### Defensive Techniques
- **Integrity Checking**: CRC32/MD5-based code integrity
- **Stack Walking**: Abnormal call path detection
- **PEB/TEB Analysis**: Process Environment Block verification
- **Hardware Debugging Detection**: DR register monitoring

## 🏗️ Project Structure

```
RemoteManualMapper/    # [Offensive] Manual DLL injection
AntiCheat/            # [Defensive] Cheat detection system
Hook/                 # [Offensive] Various hooking techniques
Render/               # [Offensive] D3D11 render hooking
syscall/              # [Offensive] Direct system calls
Utils/                # Common utilities
```

## 🛠️ Build

**Requirements**
- Visual Studio 2019 or later
- C++17 standard
- Windows SDK 10.0.19041.0 or later

```bash
git clone https://github.com/yourusername/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
```

## 💡 Usage Examples

### DLL Injection (Attack Simulation)
```cpp
RemoteManualMapper mapper;
auto result = mapper.InjectDll(targetPid, "payload.dll", true);
if (result.success) {
    std::cout << "Injection at: 0x" << std::hex << result.baseAddress;
}
```

### Anti-Cheat Initialization (Defense)
```cpp
// Initialize on game start
AntiCheat::Initialize(GetModuleHandle(NULL));

// Periodic checks
if (AntiCheat::DetectInjectedDll()) {
    // Handle cheat detection
    TerminateProcess(GetCurrentProcess(), -1);
}
```

### Hook Installation and Detection
```cpp
// [Offensive] Function hooking
void* trampoline = g_HookManager->install_jmp(targetFunc, hookFunc, 14);

// [Defensive] Hook detection
if (AntiCheat::CheckInlineHook(targetFunc)) {
    // Hook detected
}
```

### Return Address Spoofing
```cpp
// [Offensive] Call stack concealment
auto result = ret_spoofing::Call<int>(targetFunc, arg1, arg2);

// [Defensive] Stack walking validation
if (!AntiCheat::ValidateCallStack()) {
    // Abnormal call path detected
}
```

Detection mechanisms corresponding to each attack technique are implemented together.

## 🎓 Learning Points

### Beginner
- Understanding PE file structure
- DLL injection principles
- Basic hooking concepts

### Intermediate
- Manual mapping implementation
- Direct syscall invocation
- Memory integrity verification

### Advanced
- Anti-anti-cheat bypass techniques
- Kernel-level detection
- Real-time code protection

## 🔐 Security Considerations

When using this code in actual production environment:
- Kernel driver-based protection required
- Remove hardcoded encryption keys
- Add network-level verification
- Server-side validation mandatory

## 📝 License

MIT License - For educational and research purposes only

## 🤝 Contributing

Suggestions for new techniques with educational value are welcome
- New attack pattern analysis
- Improved detection algorithms
- Performance optimization

## 📬 Contact

Project inquiries: [tlkj12@gmail.com]

---

**⚡ Key Emphasis**: This project includes both offensive techniques discovered through reverse engineering real cheat programs and defensive mechanisms to counter them. Created for learning purposes of game security industry professionals and researchers.

**🎯 Target Audience**: Anti-cheat developers, game security researchers, reverse engineers
