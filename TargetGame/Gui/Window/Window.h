#pragma once
#include <windows.h>

class Window
{
public:
    Window();
    ~Window();

    bool Create(const wchar_t* title, int width, int height);
    void Destroy();
    void Show();
    bool ProcessMessages();

    HWND GetHandle() const { return m_hWnd; }
    int GetWidth() const { return m_width; }
    int GetHeight() const { return m_height; }


    using ResizeCallback = void(*)(int width, int height, void* userData);
    void SetResizeCallback(ResizeCallback callback, void* userData);

private:
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hWnd;
    WNDCLASSEXW m_wc;
    int m_width;
    int m_height;
    bool m_shouldClose;

    ResizeCallback m_resizeCallback;
    void* m_callbackUserData;
};