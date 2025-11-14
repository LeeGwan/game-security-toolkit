#pragma once
#include "../Window/Window.h"
#include "../D3DRenderer/D3DRenderer.h"
#include "../ImGuiManager/ImGuiManager.h"

typedef bool (*CheckReturnAddressFunc)(int);
static CheckReturnAddressFunc CheckFunc;
class Application
{
public:
    Application();
    ~Application();

    bool Initialize();
    void Run();
    void Shutdown();
    void x64RetHookingTest();
private:
    void Update();
    void Render();
    void RenderUI();
    

    static void OnWindowResize(int width, int height, void* userData);

private:
    Window m_window;
    D3DRenderer m_renderer;
    ImGuiManager m_imguiManager;
    HMODULE m_AntiModule;
   
    bool m_showAnotherWindow;
    bool m_running;

};