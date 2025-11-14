#include <Windows.h>
#include "Render/Render.h"
void on_attach(HMODULE hModule)
{
    Render Renders;
    if (Renders.Render_hooks())
    {
        MessageBoxA(NULL, "HOOK SUCCESSED", "", 0); return;
    }
    else
        MessageBoxA(NULL, "HOOK Faild", "", 0);
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(lpReserved);
    DisableThreadLibraryCalls(hModule);
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)on_attach, hModule, NULL, NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

