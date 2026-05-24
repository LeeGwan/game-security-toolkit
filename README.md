# Game Security Research Toolkit
> English | [한국어](./README.kor.md)

A Windows x64 game security research toolkit built upon real-world cheat reverse engineering and analysis.

📋 Project Overview
This project is a personal research repository where I have documented and re-implemented the technical mechanisms learned through reverse engineering actual game cheat programs encountered during my freelance career.

Rather than presenting a "definitive guide," this project focuses on the journey of exploration: dissecting "How do cheats work?" by analyzing and writing offensive code, and then switching to the perspective of a security engine developer to research "What logic is required to detect this?"

Research & Learning Methodology
Attack Analysis: Reversing commercially distributed cheat programs to understand their core operational principles.

Vulnerability Identification: Analyzing and learning the bypass points within game security systems.

Defensive Research: Designing logic to effectively detect the analyzed attack vectors.

⚠️ Legal Notice
This code is for educational and research purposes only.

Unauthorized use on commercial games is strictly prohibited.

Any malicious use is strictly forbidden.

Intended solely for the learning purposes of researchers and developers.

Use at your own risk; the author assumes no responsibility.

🎯 Key Features
💉 Remote Manual Mapper (Offensive Analysis)
Research and implementation of detection bypass techniques used in real-world cheats.

LoadLibrary Bypass: Analyzing the mechanism of DLL memory mapping without API calls.

IAT/TLS/SEH Processing: Understanding the loading process through a complete PE loader re-implementation.

PE Header Removal: Researching techniques to erase traces from memory.

XOR Encryption: Analyzing disk-based scan evasion methods.

🛡️ Anti-Cheat (Defensive Design)
Researching defense systems to effectively detect the analyzed attack techniques.

Memory Integrity Verification: Code segment hash checking (.text/.rdata).

Hardware Breakpoint Detection: Debugging detection utilizing DR0-7 registers.

Inline Syscall Detection: Analyzing abnormal system call patterns and entry points.

DLL Injection Detection: Identifying unauthenticated modules via PEB traversal.

Return Address Validation: Determining the presence of hooks through Stack Walking.

Pattern Scan Detection: Implementing monitoring logic for unauthorized memory read attempts.

🪝 Hooking (Attack & Detection Research)
Analysis of various hooking implementation methods and their corresponding detection strategies.

JMP Hooking: Understanding 5/14-byte trampoline structures.

Syscall-based Memory Protection: Analyzing syscalls that bypass ntdll hooks.

Return Address Spoofing: Researching call stack concealment principles and detection logic.

DirectX 11 Present Hook: Analyzing the interception of the rendering pipeline.

🔧 Utilities
Advanced pattern scanning (IDA-style pattern analysis).

Inline Syscall executor implementation.

PE file parser for deep structural analysis.

🔬 Core Research Focus
Offensive Perspective
Manual Mapping: Direct mapping techniques based on a deep understanding of PE structures.

SSDT Index Extraction: Researching kernel function calls that bypass ntdll.

API Hooking: Mastering the principles of IAT, Inline, and Trampoline techniques.

Memory Protection Bypass: Researching evasion through runtime modification of memory protection attributes.

Defensive Perspective
Integrity Checking: Designing real-time verification based on CRC32/MD5.

Stack Walking: Detecting abnormal execution flows by tracing call paths.

PEB/TEB Analysis: Verification using Process and Thread Environment Blocks.

Hardware Debugging Detection: Monitoring DR registers to detect analysis attempts.

🏗️ Project Structure
RemoteManualMapper/    # [Analysis] Manual DLL injection mechanism
AntiCheat/             # [Research] Analysis-based cheat detection system
Hook/                  # [Analysis] Various hooking and bypass techniques
Render/                # [Analysis] D3D11 rendering interception research
syscall/               # [Analysis] Direct system call invocation structure
Utils/                 # Common utilities and parsers
🛠️ Build & Environment
Requirements

Visual Studio 2019 or later

C++17 Standard or later

Windows SDK 10.0.19041.0 or later

Bash
git clone https://github.com/LeeGwan/game-security-toolkit.git
cd game-security-toolkit
start GameSecurityToolkit.sln
💡 Usage Examples (Research Scenarios)
DLL Injection Analysis (Attack Simulation)
C++
RemoteManualMapper mapper;
auto result = mapper.InjectDll(targetPid, "payload.dll", true);
if (result.success) {
    std::cout << "Injection at: 0x" << std::hex << result.baseAddress;
}
Anti-Cheat Logic Verification (Defense)
C++
// Initialize security module on game start
AntiCheat::Initialize(GetModuleHandle(NULL));

// Periodic check for injected modules
if (AntiCheat::DetectInjectedDll()) {
    // Detection handling logic
    TerminateProcess(GetCurrentProcess(), -1);
}
🎓 Learning Milestones
Beginner
Deep understanding of the PE file structure.

Fundamentals of DLL injection and module loading.

Intermediate
Detailed implementation process of Manual Mapping.

Understanding system function calls via Direct Syscalls.

Designing runtime memory integrity verification.

Advanced
Analysis of Anti-Anti-Cheat bypass techniques and their limitations.

Research into kernel-level detection mechanisms.

Expanding into Code Virtualization (VM-based protection) analysis (Ongoing).

🔐 Security Considerations
Key factors when applying this research to a production environment:

Implementation of a deeper protection layer based on Kernel Drivers.

Management of encryption keys and integration with network-level security.

Mandatory synchronization with server-side validation logic.

📝 License
MIT License - Please use for personal learning and research purposes only.

📬 Contact
Project inquiries and technical exchange: [tlkj12@gmail.com]

⚡ Key Emphasis: This project is a collection of records documenting the attacker's insight gained through reverse engineering real-world cheats and the security engineer's logic developed to counter them. I hope the technical hurdles I overcame while studying reversing will be helpful to fellow security researchers.

🎯 Primary Interests: #AntiCheat_Development #Reverse_Engineering #Game_Security #Vulnerability_Analysis

**🎯 대상 독자**: 안티치트 개발자, 게임 보안 연구자, 리버스 엔지니어
