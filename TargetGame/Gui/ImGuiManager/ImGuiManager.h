#pragma once
#include <windows.h>
#include <d3d11.h>

class ImGuiManager
{
public:
    ImGuiManager();
    ~ImGuiManager();

    bool Initialize(HWND hWnd, ID3D11Device* device, ID3D11DeviceContext* deviceContext);
    void Shutdown();

    void BeginFrame();
    void EndFrame();
    void Render();


    virtual void RenderUI();

private:
    bool m_initialized;
};