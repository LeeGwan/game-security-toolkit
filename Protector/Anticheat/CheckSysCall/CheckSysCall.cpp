#include "CheckSysCall.h"
#include <Windows.h>
#include <vector>
#include <thread>

/**
 * @brief Entry point for the syscall detection module.
 * Spawns a detached background thread to continuously monitor the process memory.
 */
void CheckSysCall::StartCheckSysCall()
{
    std::thread(DetectInlineSyscall).detach();
}

/**
 * @brief Continuous monitoring loop for inline syscall stubs.
 * Periodically scans the entire memory space to identify unauthorized syscall instructions.
 */
void CheckSysCall::DetectInlineSyscall()
{
    while (1)
    {
        if (ScanMemoryForSyscallStub())
        {
            // Immediate action upon detection to prevent security bypass
            MessageBoxA(NULL, "Unauthorized Direct Syscall Detected!", "AntiCheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
        // Polling interval to balance detection speed and CPU overhead
        Sleep(1000);
    }
}

/**
 * @brief Scans all committed executable memory regions for syscall patterns.
 * Explicitly excludes legitimate modules like ntdll.dll and win32u.dll to avoid false positives.
 * @return bool True if an illegal syscall stub is identified.
 */
bool CheckSysCall::ScanMemoryForSyscallStub()
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;
    
    // Resolve handles for modules allowed to contain syscall instructions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");

    // Iterate through the virtual address space
    while (VirtualQuery(address, &mbi, sizeof(mbi)) != 0)
    {
        // Skip scanning if the memory region belongs to trusted system modules
        if (mbi.AllocationBase == hNtdll || mbi.AllocationBase == hWin32u)
        {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }

        // Only scan regions that are committed and have execution permissions (potential shellcode/mapped DLLs)
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            BYTE* buffer = new BYTE[mbi.RegionSize];

            __try
            {
                // Snapshot the memory region for pattern analysis
                memcpy(buffer, mbi.BaseAddress, mbi.RegionSize);

                if (ContainsSyscallInstruction(buffer, mbi.RegionSize))
                {
                    char buf[500];
                    sprintf_s(buf, "Violation: Found illegal syscall stub at: 0x%p\n", mbi.BaseAddress);
                    MessageBoxA(NULL, buf, "Integrity Violation", MB_OK | MB_ICONERROR);
                    
                    delete[] buffer;
                    return true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                // Handle potential access violations during memory copy/scan
                delete[] buffer;
            }

            delete[] buffer;
        }

        // Advance to the next memory region
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return false;
}

/**
 * @brief Performs signature-based scanning for the x64 syscall prologue.
 * Target Pattern: mov r10, rcx; mov eax, [index]; syscall; ret
 * @param memory Pointer to the buffer containing memory snapshot.
 * @param size Size of the buffer.
 * @return bool True if the signature matches.
 */
bool CheckSysCall::ContainsSyscallInstruction(BYTE* memory, SIZE_T size)
{
    // Signature for x64 syscall stub: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...) 
    // Followed by 0F 05 C3 (syscall; ret)
    const char* syscallPattern = "4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3";

    /**
     * @brief Helper lambda to convert a hex string pattern to a byte vector.
     * Supports wildcards (??).
     */
    auto pattern_to_byte = [](const char* pattern) -> std::vector<int>
    {
        std::vector<int> bytes;
        const char* start = pattern;
        const char* end = pattern + strlen(pattern);
        
        for (const char* current = start; current < end; ++current)
        {
            if (*current == ' ') continue;
            if (*current == '?')
            {
                bytes.push_back(-1); // Wildcard marker
                if (*(current + 1) == '?') ++current;
            }
            else
            {
                bytes.push_back(strtoul(current, const_cast<char**>(&current), 16));
            }
        }
        return bytes;
    };

    auto patternBytes = pattern_to_byte(syscallPattern);
    size_t patternSize = patternBytes.size();

    // Standard pattern matching algorithm
    for (SIZE_T i = 0; i < size - patternSize; i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternSize; j++)
        {
            if (patternBytes[j] != -1 && memory[i + j] != patternBytes[j])
            {
                found = false;
                break;
            }
        }

        if (found)
            return true;
    }

    return false;
}
