#pragma once
#include "Imgui/imgui.h"
#include <memory>
#include <Windows.h>
class IDXGISwapChain;
class ID3D11Device;
class ID3D11RenderTargetView;
// DirectX 11 resources container
class DirectX
{
public:
	void initialize();
	IDXGISwapChain* swap_chain;
	ID3D11Device* dx11_device;
	ID3D11RenderTargetView* render_target_view;
	HWND hwnd;

};
extern std::unique_ptr<DirectX> g_DirectX;

