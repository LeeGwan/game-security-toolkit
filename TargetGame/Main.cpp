#include "Gui/Application/Application.h"

#include <windows.h>

int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nShowCmd)
{

    Application app;
    if (!app.Initialize())
    {
        MessageBoxW(nullptr, L"애플리케이션 초기화 실패!", L"오류", MB_OK | MB_ICONERROR);
        return -1;
    }
    app.Run();
    app.Shutdown();

    return 0;
}