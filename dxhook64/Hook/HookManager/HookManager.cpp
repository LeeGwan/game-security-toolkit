#include "HookManager.h"
#include "../ret_spoofing/ret_spoofing.h"

// Global unique pointer for the HookManager singleton instance
std::unique_ptr<HookManager> g_HookManager = std::make_unique<HookManager>();

/**
 * @brief Constructor: Initializes the inline syscall module for stealth memory operations.
 */
HookManager::HookManager()
{
    syscall = inline_syscall{ };
}

HookManager::~HookManager()
{
}

/**
 * @brief Wrapper for VirtualProtect that uses direct syscalls (ZwProtectVirtualMemory).
 * This bypasses user-mode hooks placed on the standard VirtualProtect API by security solutions.
 */
void HookManager::sys_VirtualProtect(LPVOID lpAddress, SIZE_T* dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    PVOID baseAddress = lpAddress;
    // Direct syscall invocation to bypass EDR/Anti-Cheat monitoring
    syscall.invoke<NTSTATUS>("ZwProtectVirtualMemory", GetCurrentProcess(), &baseAddress, dwSize, flNewProtect, lpflOldProtect);
}

/**
 * @brief High-level API to install a JMP hook at a target address.
 * @param target The original function address to hook.
 * @param hook The detour function address.
 * @param size Number of bytes to overwrite (must be at least 5 for rel32 or 14 for abs64).
 * @return void* Pointer to the trampoline (original code + jump back).
 */
void* HookManager::install_jmp(void* target, void* hook, size_t size)
{
    std::vector<byte> ogBytes{ };
    uintptr_t ogPageAddr{ };

    uintptr_t retAddr = Inlinehook(target, hook, size, &ogBytes, &ogPageAddr);
    return (PVOID)retAddr;
}

/**
 * @brief Core Inline Hooking logic for x64 architecture.
 * Implements both relative (5-byte) and absolute (14-byte) JMP redirection.
 */
uintptr_t HookManager::Inlinehook(void* src, void* dest, size_t size, std::vector<byte>* ogBytes, uintptr_t* og_page_addr)
{
    const DWORD MinLen5 = 5;   // Minimum length for a relative 32-bit JMP
    const DWORD MinLen14 = 14; // Minimum length for an absolute 64-bit JMP

    // Validation: Ensure the overwrite size is sufficient for at least a relative JMP
    if (size < MinLen5) return NULL;

    /**
     * Allocate the Trampoline.
     * The trampoline contains:
     * 1. The original bytes from the source function.
     * 2. An absolute JMP back to (src + size) to resume original execution.
     */
    void* pTrampoline = VirtualAlloc(0, size + MinLen14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTrampoline) return NULL;

    // Change memory protection of the target function using stealth syscall
    DWORD dwOld = 0;
    size_t tmpsize = size;
    sys_VirtualProtect(src, &tmpsize, PAGE_EXECUTE_READWRITE, &dwOld);

    // Backup and copy original bytes to the trampoline
    memcpy(pTrampoline, src, size);

    // Setup 'Jump Back' inside the trampoline (Absolute 64-bit JMP)
    BYTE* trampolineJmp = (BYTE*)pTrampoline + size;
    trampolineJmp[0] = 0xFF;  // JMP opcode
    trampolineJmp[1] = 0x25;  // [RIP+0] addressing
    *(DWORD*)(trampolineJmp + 2) = 0x00000000;
    *(DWORD64*)(trampolineJmp + 6) = (DWORD64)src + size;

    // Calculate relative offset for 32-bit JMP optimization
    INT64 relativeOffset = (INT64)dest - ((INT64)src + 5);

    /**
     * CASE 1: 32-bit Relative JMP (5 Bytes)
     * Used if the destination is within a 2GB range of the source.
     */
    if (relativeOffset >= INT_MIN && relativeOffset <= INT_MAX)
    {
        BYTE* hookJmp = (BYTE*)src;
        hookJmp[0] = 0xE9;  // JMP rel32 opcode
        *(INT32*)(hookJmp + 1) = (INT32)relativeOffset;

        // NOP out remaining bytes to maintain instruction alignment
        for (int i = 5; i < size; i++)
            hookJmp[i] = 0x90;
    }
    /**
     * CASE 2: 64-bit Absolute JMP (14 Bytes)
     * Used for far jumps (greater than 2GB range).
     */
    else
    {
        BYTE* hookJmp = (BYTE*)src;
        hookJmp[0] = 0xFF;  // JMP opcode
        hookJmp[1] = 0x25;  // [RIP+0] addressing
        *(DWORD*)(hookJmp + 2) = 0x00000000;
        *(DWORD64*)(hookJmp + 6) = (DWORD64)dest;

        // NOP out remaining bytes
        for (int i = 14; i < size; i++)
            hookJmp[i] = 0x90;
    }

    // Restore original memory protection to avoid easy detection by integrity checks
    tmpsize = size;
    sys_VirtualProtect(src, &tmpsize, dwOld, &dwOld);

    return (uintptr_t)pTrampoline;
}
