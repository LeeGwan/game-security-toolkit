#include "Application.h"
#include "imgui.h"
#include <fstream>
#include <filesystem>
#include <string>

Application::Application()
    : m_running(false)
    , m_showAnotherWindow(false)
    , m_AntiModule(nullptr)
    
{
    CheckFunc = nullptr;
}

Application::~Application()
{
    Shutdown();
}

bool Application::Initialize()
{

    if (!m_window.Create(L"ImGui + DirectX 11 Application", 1280, 720))
    {
        return false;
    }


    if (!m_renderer.Initialize(m_window.GetHandle()))
    {
        return false;
    }

    // ImGui 초기화
    if (!m_imguiManager.Initialize(
        m_window.GetHandle(),
        m_renderer.GetDevice(),
        m_renderer.GetDeviceContext()))
    {
        return false;
    }

   
    m_window.SetResizeCallback(OnWindowResize, this);

  
    m_window.Show();

    m_running = true;
    return true;
}

void Application::Run()
{
    while (m_running && m_window.ProcessMessages())
    {
        Update();
        Render();
    }
}

void Application::Shutdown()
{
    m_imguiManager.Shutdown();
    m_renderer.Shutdown();
    m_window.Destroy();
    if(m_AntiModule)
    FreeLibrary(m_AntiModule);
}

void Application::Update()
{
  
}

void Application::Render()
{

    m_renderer.BeginFrame();


    m_imguiManager.BeginFrame();


    RenderUI();


    m_imguiManager.EndFrame();


    m_imguiManager.Render();

    m_renderer.EndFrame();
}

void Application::RenderUI()
{
    ImGui::SetNextWindowSize(ImVec2(500, 400), 0);
        ImGui::Begin(u8"시스템 정보");
        std::wstring pidstr=std::wstring(L"현재 프로세스pid : ") + std::to_wstring(GetCurrentProcessId());
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0,
            pidstr.c_str(), (int)pidstr.size(),
            nullptr, 0, nullptr, nullptr);
        std::string result(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0,
            pidstr.c_str(), (int)pidstr.size(),
            result.data(), sizeNeeded, nullptr, nullptr);
        ImGui::Text(result.c_str());

        ImGui::Text(u8"DirectX 11 렌더러 사용 중");
        if (m_renderer.GetDevice())
        {
            ImGui::Text(u8"DirectX 디바이스: 초기화 완료");
        }
        // Load anti-cheat module button
        ImGui::SetCursorPos(ImVec2(150, 150));
        if (!m_AntiModule)
        {
            if (ImGui::Button(u8"안티치트모듈 로드"))
            {
                std::filesystem::path currentPath = std::filesystem::current_path();
                std::wstring font_path = currentPath.wstring() + L"\\Protector.dll";
                m_AntiModule = LoadLibraryW(font_path.c_str());
                CheckFunc =(CheckReturnAddressFunc)GetProcAddress(m_AntiModule, "?CheckReturnAddress@CheckRet_Addr@@CA_NH@Z");

            }
        }
        else
        {
            ImGui::Button(u8"안티치트모듈 작동중");
        }
        ImGui::SetCursorPos(ImVec2(150, 250));
        if (ImGui::Button(u8"x64RetHookingTest 호출"))
        {
            x64RetHookingTest();
        }
        ImGui::End();
    
}
// Test return address validation
void Application::x64RetHookingTest()
{

    if (CheckFunc&&!CheckFunc(4))
    {
        MessageBoxA(NULL, "Find RetHooking", "AntiCheat", MB_OK | MB_ICONERROR);
        ExitProcess(0);
    }
    MessageBoxA(NULL, "x64RetHookingTest", "", 0);
}


void Application::OnWindowResize(int width, int height, void* userData)
{
    Application* app = static_cast<Application*>(userData);
    if (app)
    {
        app->m_renderer.ResizeBuffers(width, height);
    }
}