#include "CheckSysCall.h"
#include <Windows.h>

#include <vector>
#include <thread>
void CheckSysCall::StartCheckSysCall()
{
    std::thread(DetectInlineSyscall).detach();
}
void CheckSysCall::DetectInlineSyscall()
{
    while (1)
    {
        if (ScanMemoryForSyscallStub())
        {

            MessageBoxA(NULL, "Memory integrity check failed!", "AntiCheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
        Sleep(1000);
        
    }
    return;
}
// Scan executable memory for syscall patterns (excluding ntdll/win32u)
bool CheckSysCall::ScanMemoryForSyscallStub()
{
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hWin32u = GetModuleHandleA("win32u.dll");
    //ntdll.dll win32u.dll 을제외한 sys 특정 패턴을 체크
    while (VirtualQuery(address, &mbi, sizeof(mbi)) != 0)
    {
        if (mbi.AllocationBase == hNtdll || mbi.AllocationBase == hWin32u)
        {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            BYTE* buffer = new BYTE[mbi.RegionSize];

            __try
            {
                memcpy(buffer, mbi.BaseAddress, mbi.RegionSize);

                if (ContainsSyscallInstruction(buffer, mbi.RegionSize))
                {
                    char buf[500];
                    sprintf_s(buf,"Found syscall stub at: 0x%p\n", mbi.BaseAddress);
                    MessageBoxA(NULL, buf, "Integrity Violation", MB_OK | MB_ICONERROR);
                    delete[] buffer;
                    return true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                delete[] buffer;
            }

            delete[] buffer;
        }

        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    return false;
}

bool CheckSysCall::ContainsSyscallInstruction(BYTE* memory, SIZE_T size)
{
    const char* syscallPattern = "4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3";

    auto pattern_to_byte = [](const char* pattern) -> std::vector<int>
        {
            std::vector<int> bytes;
            const char* start = pattern;
            const char* end = pattern + strlen(pattern);
            for (const char* current = start; current < end; ++current)
            {
                if (*current == '?')
                {
                    ++current;
                    if (*current == '?') ++current;
                    bytes.push_back(-1);
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
