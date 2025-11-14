#include "D3DRenderer.h"
#include <stdexcept>

D3DRenderer::D3DRenderer()
    : m_pDevice(nullptr)
    , m_pDeviceContext(nullptr)
    , m_pSwapChain(nullptr)
    , m_pRenderTargetView(nullptr)
{
}

D3DRenderer::~D3DRenderer()
{
    Shutdown();
}

bool D3DRenderer::Initialize(HWND hWnd)
{
    return CreateDevice(hWnd);
}

void D3DRenderer::Shutdown()
{
    CleanupRenderTarget();

    if (m_pSwapChain)
    {
        m_pSwapChain->Release();
        m_pSwapChain = nullptr;
    }

    if (m_pDeviceContext)
    {
        m_pDeviceContext->Release();
        m_pDeviceContext = nullptr;
    }

    if (m_pDevice)
    {
        m_pDevice->Release();
        m_pDevice = nullptr;
    }
}

void D3DRenderer::BeginFrame()
{
    const float clear_color_with_alpha[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
    m_pDeviceContext->OMSetRenderTargets(1, &m_pRenderTargetView, nullptr);
    m_pDeviceContext->ClearRenderTargetView(m_pRenderTargetView, clear_color_with_alpha);
}

void D3DRenderer::EndFrame()
{
    m_pSwapChain->Present(1, 0); 
}

void D3DRenderer::ResizeBuffers(UINT width, UINT height)
{
    if (m_pDevice == nullptr || width == 0 || height == 0)
        return;

    CleanupRenderTarget();
    m_pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
    CreateRenderTarget();
}

bool D3DRenderer::CreateDevice(HWND hWnd)
{

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
#ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_0,
    };

    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        createDeviceFlags,
        featureLevelArray,
        2,
        D3D11_SDK_VERSION,
        &sd,
        &m_pSwapChain,
        &m_pDevice,
        &featureLevel,
        &m_pDeviceContext
    );

    if (FAILED(hr))
        return false;

    CreateRenderTarget();

    return true;
}

void D3DRenderer::CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    m_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));

    if (pBackBuffer)
    {
        m_pDevice->CreateRenderTargetView(pBackBuffer, nullptr, &m_pRenderTargetView);
        pBackBuffer->Release();
    }
}

void D3DRenderer::CleanupRenderTarget()
{
    if (m_pRenderTargetView)
    {
        m_pRenderTargetView->Release();
        m_pRenderTargetView = nullptr;
    }
}