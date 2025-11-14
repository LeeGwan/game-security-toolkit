#pragma once
#include <Windows.h> 
class IDXGISwapChain;

typedef unsigned int        UINT;

class Render
{
public:
    Render();
    bool Render_hooks();
    typedef long(__stdcall* DX11Present_t)(IDXGISwapChain*, UINT, UINT);

    // Hook callbacks
    static long __stdcall DX11PresentCallee(IDXGISwapChain* pThis, UINT syncInterval, UINT flags);
    static LRESULT __stdcall WndProcCallee(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

    // Original functions
    static inline DX11Present_t O_DX11Present = nullptr;
    static inline WNDPROC O_WndProc = nullptr;
    // Initialization flags
    static inline bool hwndInitialized = false;
    static inline bool imguiInitialized = false;
    // Test address for return spoofing
    static inline uintptr_t x64RetHookingTest_addr = 0;

};

