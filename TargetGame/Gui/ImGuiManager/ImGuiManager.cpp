#include "ImGuiManager.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include <codecvt>
ImGuiManager::ImGuiManager()
    : m_initialized(false)
{
}

ImGuiManager::~ImGuiManager()
{
    Shutdown();
}

bool ImGuiManager::Initialize(HWND hWnd, ID3D11Device* device, ID3D11DeviceContext* deviceContext)
{

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    ImFont* font = io.Fonts->AddFontFromFileTTF("C:\\Users\\lee\\source\\repos\\TargetGame\\TargetGame\\fonts\\gulim.ttc", 18.0f, NULL, io.Fonts->GetGlyphRangesKorean());
  
    ImGui::StyleColorsDark();

    if (!ImGui_ImplWin32_Init(hWnd))
        return false;

    if (!ImGui_ImplDX11_Init(device, deviceContext))
    {
        ImGui_ImplWin32_Shutdown();
        return false;
    }

    m_initialized = true;
    return true;
}

void ImGuiManager::Shutdown()
{
    if (m_initialized)
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        m_initialized = false;
    }
}

void ImGuiManager::BeginFrame()
{
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
}

void ImGuiManager::EndFrame()
{
    ImGui::Render();
}

void ImGuiManager::Render()
{
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

void ImGuiManager::RenderUI()
{
   
}