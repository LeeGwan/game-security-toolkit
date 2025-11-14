#include "CheckHWBP.h"
#include<thread>
void CheckHWBP::Initialize_CheckHWBP()
{

    std::thread(StartCheckHWBP).detach();
}

returns CheckHWBP::CheckAllThreads(DWORD processId)
{
    //타겟 모듈의 쓰레드를 모두 가져와 Dr0~DR3 값이 있는지 체크
    if (processId == 0)
        processId = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return returns::Error;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32))
    {
        CloseHandle(hSnapshot);
        return returns::Error;
    }

    do
    {
        if (te32.th32OwnerProcessID == processId)
        {
            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (!hThread)
                continue;

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;  

            if (GetThreadContext(hThread, &ctx))
            {
                bool HasBreakpoint = (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);

                if (HasBreakpoint)
                {
                    CloseHandle(hThread);
                    CloseHandle(hSnapshot);
                    return returns::FIND;
                }
            }

            CloseHandle(hThread);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);
    return returns::NOT;
}

void CheckHWBP::StartCheckHWBP()
{
    returns result;
    while (1)
    {
        result=CheckAllThreads(GetCurrentProcessId());
        if (result == returns::FIND)
        {
            MessageBoxA(NULL, "Find HardWareBreakPoint!!!", "AntiCheat", MB_OK | MB_ICONERROR);
            ExitProcess(0);
        }
    }
}
