#include "CheckRet_Addr.h"
#include <Windows.h>      
#include <dbghelp.h>    
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

/**
 * @brief Validates the call stack by performing a manual stack walk to detect spoofed return addresses.
 * * This function captures the current thread context and iterates through the stack frames.
 * It specifically checks if any return address points to a known 'gadget' used in return address
 * spoofing (e.g., JMP [RBX]) or resides in non-executable memory.
 * * @param max_depth The maximum number of stack frames to traverse for validation.
 * @return bool Returns true if the stack appears legitimate; false if an anomaly is detected.
 */
PROTECTOR_API bool CheckRet_Addr::CheckReturnAddress(int max_depth)
{
    static bool initialized = false;
    if (!initialized) {
        // Initialize the symbol handler for stack walking
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        initialized = true;
    }

    UINT64 Ret_Addr;
    BYTE* ret;
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;

    // Capture the register state of the current thread
    RtlCaptureContext(&context);

    // Initialize the stack frame structure for x64 architecture
    STACKFRAME64 frame = { 0 };
    frame.AddrPC.Offset = context.Rip;     // Instruction Pointer
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;  // Base Pointer (not strictly used in x64 but good for compatibility)
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;  // Stack Pointer
    frame.AddrStack.Mode = AddrModeFlat;

    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    // Skip the first frame (the current function: CheckReturnAddress)
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread,
        &frame, &context, NULL,
        SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        return false;
    }

    // Traverse the stack up to the specified depth
    for (int i = 0; i < max_depth; i++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread,
            &frame, &context, NULL,
            SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            break;
        }

        Ret_Addr = frame.AddrReturn.Offset;
    
        if (Ret_Addr == 0) {
            break;
        }
      
        // 1. Verify Memory Protection of the Return Address
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)Ret_Addr, &mbi, sizeof(mbi)))
        {
            bool canExecute = (mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE);

            // Anomaly: Return address pointing to a non-executable memory region
            if (!canExecute)
            {
                return false;
            }
        }

        // 2. Anomaly Detection: Detect Gadget-based Return Address Spoofing
        ret = (BYTE*)Ret_Addr;
        
        /**
         * Identification of the 'FF 23' gadget (jmp qword ptr [rbx]).
         * If the return address points exactly to this instruction, it indicates
         * that the call stack has been tampered with to hide the real caller.
         */
        if (*(ret) == 0xff && *(ret + 1) == 0x23)
        {
            return false;
        }
    }

    return true;
}
