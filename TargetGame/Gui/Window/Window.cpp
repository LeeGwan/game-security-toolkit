#include "Window.h"
#include "imgui.h"
#include "imgui_impl_win32.h"
#include <string>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

Window::Window()
    : m_hWnd(nullptr)
    , m_width(0)
    , m_height(0)
    , m_shouldClose(false)
    , m_resizeCallback(nullptr)
    , m_callbackUserData(nullptr)
{
    memset(&m_wc, 0, sizeof(WNDCLASSEXW));
}

Window::~Window()
{
    Destroy();
}

bool Window::Create(const wchar_t* title, int width, int height)
{
    m_width = width;
    m_height = height;
    memset(&m_wc, 0, sizeof(WNDCLASSEXW));
    std::wstring ClassName = L"Test";
    m_wc.cbSize = sizeof(WNDCLASSEXW);
    m_wc.style = CS_CLASSDC;
    m_wc.lpfnWndProc = WindowProc;
    m_wc.cbClsExtra = 0L;
    m_wc.cbWndExtra = 0L;
    m_wc.hInstance = GetModuleHandle(NULL);
    m_wc.hIcon = NULL;
    m_wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    m_wc.hbrBackground = NULL;
    m_wc.lpszMenuName = NULL;
    m_wc.lpszClassName = ClassName.c_str();
    m_wc.hIconSm = NULL;
 
    if (!RegisterClassExW(&m_wc))
        return false;


    m_hWnd = CreateWindowW(
        m_wc.lpszClassName,
        ClassName.c_str(),
        WS_OVERLAPPEDWINDOW,
        0, 0,
        width,
        height,
        NULL,
        NULL,
        m_wc.hInstance,
        NULL
    );
    DWORD ERRORs = GetLastError();

    if (!m_hWnd)
        return false;

    return true;
}

void Window::Destroy()
{
    if (m_hWnd)
    {
        DestroyWindow(m_hWnd);
        m_hWnd = nullptr;
    }

    if (m_wc.lpszClassName)
    {
        UnregisterClassW(m_wc.lpszClassName, m_wc.hInstance);
    }
}

void Window::Show()
{
    if (m_hWnd)
    {
        ShowWindow(m_hWnd, SW_SHOWDEFAULT);
        UpdateWindow(m_hWnd);
    }
}

bool Window::ProcessMessages()
{
    MSG msg;
    while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

        if (msg.message == WM_QUIT)
        {
            m_shouldClose = true;
            return false;
        }
    }

    return !m_shouldClose;
}

void Window::SetResizeCallback(ResizeCallback callback, void* userData)
{
    m_resizeCallback = callback;
    m_callbackUserData = userData;
}

LRESULT CALLBACK Window::WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static bool isMinimized = false;
    static bool isDragging = false;
    static POINT dragStartPoint;
    static POINT windowStartPoint;

    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {

    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;

        if (wParam == SC_MINIMIZE) // Minimize the window
        {
            ::ShowWindow(hWnd, SW_MINIMIZE);
            isMinimized = true;
            return 0;
        }
        break;
    case WM_ENTERSIZEMOVE:
        isMinimized = false;
        ::ShowWindow(hWnd, SW_RESTORE);
        return 0;
    case WM_EXITSIZEMOVE:
        return 0;
    case WM_NCHITTEST:
    {
        // Handle hit-testing for resizing and moving the window
        LRESULT hitTest = DefWindowProc(hWnd, WM_NCHITTEST, wParam, lParam);
        if (hitTest == HTCAPTION || hitTest == HTSYSMENU)
            return HTCAPTION;
        else
            return hitTest;
    }
    case WM_CLOSE:


        ::DestroyWindow(hWnd); // Close the window
        return 0;
    case WM_DESTROY:


        ::PostQuitMessage(0);
        return 0;
    case WM_LBUTTONDOWN:
    {
        if (!isMinimized)
        {
            POINT cursorPos;
            GetCursorPos(&cursorPos);
            windowStartPoint.x = cursorPos.x;
            windowStartPoint.y = cursorPos.y;
            RECT windowRect;
            GetWindowRect(hWnd, &windowRect);
            dragStartPoint.x = cursorPos.x - windowRect.left;
            dragStartPoint.y = cursorPos.y - windowRect.top;

            isDragging = true;
        }
    }
    return 0;
    case WM_LBUTTONUP:
    {
        isDragging = false;
        ReleaseCapture();
    }
    return 0;
    case WM_MOUSEMOVE:
    {
        if (!isMinimized && isDragging)
        {
            POINT cursorPos;
            GetCursorPos(&cursorPos);
            SetWindowPos(hWnd, nullptr,
                cursorPos.x - dragStartPoint.x,
                cursorPos.y - dragStartPoint.y,
                0, 0,
                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
    return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

LRESULT Window::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{

    if (ImGui_ImplWin32_WndProcHandler(m_hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED)
        {
            m_width = (UINT)LOWORD(lParam);
            m_height = (UINT)HIWORD(lParam);

            if (m_resizeCallback)
            {
                m_resizeCallback(m_width, m_height, m_callbackUserData);
            }
        }
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // ALT 키 비활성화
            return 0;
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(m_hWnd, msg, wParam, lParam);
}