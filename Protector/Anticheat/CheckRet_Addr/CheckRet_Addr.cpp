#include "CheckRet_Addr.h"
#include <Windows.h>      
#include <dbghelp.h>    
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
PROTECTOR_API bool CheckRet_Addr::CheckReturnAddress(int max_depth)
{
    static bool initialized = false;
    if (!initialized) {
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        initialized = true;
    }
    UINT64 Ret_Addr;
    BYTE* ret;
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    STACKFRAME64 frame = { 0 };
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;

    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    // 첫 번째 프레임 스킵 (현재 함수 CheckReturnAddress)
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread,
        &frame, &context, NULL,
        SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        return false;
    }

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
      
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((LPCVOID)Ret_Addr, &mbi, sizeof(mbi));
        bool canExecute = (mbi.Protect & PAGE_EXECUTE) ||
            (mbi.Protect & PAGE_EXECUTE_READ) ||
            (mbi.Protect & PAGE_EXECUTE_READWRITE);
        if (!canExecute)
        {
            return false;
        }
        ret = (BYTE*)Ret_Addr;
        //추후 여러 가젯
        if (*(ret) == 0xff && *(ret + 1) == 0x23)
        {
            return false;
        }
     
       
    }

    return true;
}
