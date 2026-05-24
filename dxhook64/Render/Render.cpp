#include "Render.h"
#include <d3d11.h>
#include <d3dx11.h>
#include <d3d9types.h>
#include "../Hook/HookManager/HookManager.h"
#include "DirectX.h"
#include "../Imgui/imgui_impl_dx11.h"
#include"../Imgui/imgui_impl_win32.h"
#include "../Hook/FindSig/FindSig.h"
#include "../Hook/ret_spoofing/ret_spoofing.h"
#include <string>

/**
 * @brief Constructor: Initializes signature scanning and return address spoofing.
 */
Render::Render()
{
    O_DX11Present = nullptr;

    // Locate the target function for the return address spoofing validation test
    x64RetHookingTest_addr = (uintptr_t)FindSig::find_pattern(nullptr, "48 89 4C 24 ? 55 57 48 81 EC ? ? ? ? 48 8D 6C 24 ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 90 48 83 3D ? ? ? ? ?");
    
    if (!x64RetHookingTest_addr)
    {
        MessageBoxA(NULL, "Failed to locate x64RetHookingTest_addr", "Error", MB_ICONERROR);
        return;
    }

    // Initialize the return address spoofing module (resolve gadgets)
    ret_spoofing::Initialize();
}

/**
 * @brief Hooks the DX11 Present function by creating a dummy device to resolve the VTable.
 * @return bool True if the hook was successfully installed.
 */
bool Render::Render_hooks()
{
    // Configure a dummy swap chain to retrieve the IDXGISwapChain VTable
    DXGI_SWAP_CHAIN_DESC sd{ 0 };
    sd.BufferCount = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.OutputWindow = GetDesktopWindow();
    sd.Windowed = true;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    sd.SampleDesc.Count = 1;

    ID3D11Device* pDevice = nullptr;
    IDXGISwapChain* pSwapChain = nullptr;

    // Create a temporary device to extract the VTable address
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &sd, &pSwapChain, &pDevice, nullptr, nullptr);
    if (FAILED(hr))
        return false;

    // Extract the VTable from the SwapChain instance
    PDWORD64* pSwapChainVT = reinterpret_cast<PDWORD64*>(pSwapChain);
    pSwapChainVT = *reinterpret_cast<PDWORD64**>(pSwapChainVT);

    // IDXGISwapChain::Present is located at index 8 of the VTable
    // Install a JMP hook (14-byte trampoline for x64) to redirect to our handler
    O_DX11Present = reinterpret_cast<DX11Present_t>(g_HookManager->install_jmp(reinterpret_cast<void*>(pSwapChainVT[8]), reinterpret_cast<void*>(&Render::DX11PresentCallee), 14));
    
    // Cleanup temporary resources
    pDevice->Release();
    pSwapChain->Release();

    if (O_DX11Present) return true;
    return false;
}

/**
 * @brief Hooked Present function handler. Renders the ImGui overlay on the game screen.
 */
long __stdcall Render::DX11PresentCallee(IDXGISwapChain* pThis, UINT syncInterval, UINT flags)
{
    // Initialize DirectX resources upon the first call
    if (!hwndInitialized)
    {
        g_DirectX->swap_chain = pThis;
        pThis->GetDevice(__uuidof(g_DirectX->dx11_device), reinterpret_cast<void**>(&g_DirectX->dx11_device));

        // Create RenderTargetView for ImGui drawing
        ID3D11Texture2D* pBackBuffer;
        pThis->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        g_DirectX->dx11_device->CreateRenderTargetView(pBackBuffer, NULL, &g_DirectX->render_target_view);
        pBackBuffer->Release();

        DXGI_SWAP_CHAIN_DESC sd;
        pThis->GetDesc(&sd);

        // Subclass the window to intercept input messages (WndProc)
        g_DirectX->hwnd = sd.OutputWindow;
        O_WndProc = (WNDPROC)SetWindowLongPtr(g_DirectX->hwnd, GWLP_WNDPROC, (LONG_PTR)WndProcCallee);

        hwndInitialized = true;
    }

    // Initialize ImGui context and backend
    if (!imguiInitialized && hwndInitialized)
    {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO(); (void)io;

        ImGui::StyleColorsDark();

        ImGui_ImplWin32_Init(g_DirectX->hwnd);
        ID3D11DeviceContext* context;
        g_DirectX->dx11_device->GetImmediateContext(&context);
        ImGui_ImplDX11_Init(g_DirectX->dx11_device, context);

        imguiInitialized = true;
    }

    // Main UI rendering loop
    if (imguiInitialized)
    {
        ID3D11DeviceContext* pContext = nullptr;
        g_DirectX->dx11_device->GetImmediateContext(&pContext);
        
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Research Overlay Window
        ImGui::SetNextWindowSize(ImVec2(250, 150), ImGuiCond_FirstUseEver);
        ImGui::Begin("Research Toolkit - Debug");
        ImGui::Text("DX11 Hook Status: Active");

        // Trigger Return Address Spoofing Test
        if(ImGui::Button("Execute Ret_Spoofing Test"))
        {
            if (x64RetHookingTest_addr)
            {
                using Func_t = void(*)();  
                auto func = reinterpret_cast<Func_t>(x64RetHookingTest_addr);
                
                // Invoke target function with spoofed return address to bypass stack-walking
                ret_spoofing::Call(func);
            }
        }

        ImGui::End();

        // Finalize rendering for the current frame
        ImGui::Render();
        pContext->OMSetRenderTargets(1, &g_DirectX->render_target_view, NULL);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        if (pContext) pContext->Release();
    }

    // Call the original Present function to maintain the rendering chain
    return O_DX11Present(pThis, syncInterval, flags);
}

/**
 * @brief Window message handler for ImGui input processing.
 */
LRESULT __stdcall Render::WndProcCallee(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Pass input messages to ImGui (keyboard/mouse support)
    ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
    
    // Pass execution to the original WndProc
    return CallWindowProc(O_WndProc, hwnd, uMsg, wParam, lParam);
}
