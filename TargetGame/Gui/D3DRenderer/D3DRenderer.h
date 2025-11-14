#pragma once
#include <d3d11.h>
#include <windows.h>

class D3DRenderer
{
public:
    D3DRenderer();
    ~D3DRenderer();

    bool Initialize(HWND hWnd);
    void Shutdown();

    void BeginFrame();
    void EndFrame();
    void ResizeBuffers(UINT width, UINT height);

    ID3D11Device* GetDevice() const { return m_pDevice; }
    ID3D11DeviceContext* GetDeviceContext() const { return m_pDeviceContext; }

private:
    bool CreateDevice(HWND hWnd);
    void CreateRenderTarget();
    void CleanupRenderTarget();

private:
    ID3D11Device* m_pDevice;
    ID3D11DeviceContext* m_pDeviceContext;
    IDXGISwapChain* m_pSwapChain;
    ID3D11RenderTargetView* m_pRenderTargetView;
};