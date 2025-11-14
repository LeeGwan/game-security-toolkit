// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include <Windows.h>
#include "AntiCheat/AntiCheat.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, [](LPVOID param) -> DWORD {
            HMODULE hTargetModule = GetModuleHandleA(NULL);
            AntiCheat::Initialize(hTargetModule);
            return 0;
            }, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

