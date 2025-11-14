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
#include<string>
Render::Render()
{
	O_DX11Present = nullptr;
	// Find target function for return spoofing test
	x64RetHookingTest_addr = (uintptr_t)FindSig::find_pattern(nullptr, "48 89 4C 24 ? 55 57 48 81 EC ? ? ? ? 48 8D 6C 24 ? 48 8D 0D ? ? ? ? E8 ? ? ? ? 90 48 83 3D ? ? ? ? ?");
	if (!x64RetHookingTest_addr)
	{
		MessageBoxA(NULL, "faild x64RetHookingTest_addr", "", 0);
		return;
	}
	ret_spoofing::Initialize();
}

bool Render::Render_hooks()
{
	// Create dummy swap chain to get vtable
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

	HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0, D3D11_SDK_VERSION, &sd, &pSwapChain, &pDevice, nullptr, nullptr);
	if (FAILED(hr))
		return false;
	PDWORD64* pSwapChainVT = reinterpret_cast<PDWORD64*>(pSwapChain);
	pSwapChainVT = *reinterpret_cast<PDWORD64**>(pSwapChainVT);
	O_DX11Present = reinterpret_cast<DX11Present_t>(g_HookManager->install_jmp(reinterpret_cast<void*>(pSwapChainVT[8]), reinterpret_cast<void*>(&Render::DX11PresentCallee), 14));
	if (O_DX11Present)return true;

	return false;
}

long __stdcall Render::DX11PresentCallee(IDXGISwapChain* pThis, UINT syncInterval, UINT flags)
{
	// Initialize DirectX resources
	if (!hwndInitialized)
	{
		
		g_DirectX->swap_chain = pThis;
		pThis->GetDevice(__uuidof(g_DirectX->dx11_device), reinterpret_cast<void**>(&g_DirectX->dx11_device));

		ID3D11Texture2D* pBackBuffer;
		pThis->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
		g_DirectX->dx11_device->CreateRenderTargetView(pBackBuffer, NULL, &g_DirectX->render_target_view);
		pBackBuffer->Release();

		DXGI_SWAP_CHAIN_DESC sd;
		pThis->GetDesc(&sd);

		// Hook WndProc
		g_DirectX->hwnd = sd.OutputWindow;
		O_WndProc = (WNDPROC)SetWindowLongPtr(g_DirectX->hwnd, GWLP_WNDPROC, (LONG_PTR)WndProcCallee);

		hwndInitialized = true;
	

	}
	// Initialize ImGui
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
	// Render ImGui
	if (imguiInitialized)
	{
		ID3D11DeviceContext* pContext = nullptr;
		g_DirectX->dx11_device->GetImmediateContext(&pContext);
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		ImGui::SetNextWindowSize(ImVec2(200, 200), 0);
		ImGui::Begin("Hoooking");
		ImGui::Text("Successed");
		if(ImGui::Button("start ret_spoofing"))
		{
			if (x64RetHookingTest_addr)
			{
				using Func_t = void(*)();  
				auto func = reinterpret_cast<Func_t>(x64RetHookingTest_addr);
				// Call with return address spoofing
				ret_spoofing::Call(func);
				
			}
			
		}

		ImGui::End();

		ImGui::Render();
		pContext->OMSetRenderTargets(1, &g_DirectX->render_target_view, NULL);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

		if (pContext) pContext->Release();
	}
	return O_DX11Present(pThis, syncInterval, flags);
}

LRESULT __stdcall Render::WndProcCallee(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	ImGui_ImplWin32_WndProcHandler(hwnd, uMsg, wParam, lParam);
	return CallWindowProc(O_WndProc, hwnd, uMsg, wParam, lParam);
}
