#pragma once
/*
 * ZeroPhase EDR — DirectX11 + ImGui Renderer
 *
 * Properly handles window resize by recreating the swap chain
 * back buffer and render target at the new resolution.
 */

#ifndef ZEROPHASE_GUI_RENDERER_HPP
#define ZEROPHASE_GUI_RENDERER_HPP

#include <d3d11.h>
#include <dxgi.h>
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

#include "../imgui/imgui.h"
#include "../imgui/backends/imgui_impl_win32.h"
#include "../imgui/backends/imgui_impl_dx11.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace zerophase {
namespace gui {

class GuiRenderer {
public:
    bool initialize(HINSTANCE hInstance) {
        hInstance_ = hInstance;
        s_instance = this;          // static ptr for WndProc

        // Load icons at exact sizes using LoadImage for crisp rendering
        HICON iconBig = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(101),
            IMAGE_ICON, 48, 48, LR_DEFAULTCOLOR);   // taskbar + alt-tab
        HICON iconSmall = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(101),
            IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);   // title bar
        if (!iconBig) iconBig = LoadIcon(nullptr, IDI_SHIELD);
        if (!iconSmall) iconSmall = iconBig;

        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = WndProc;
        wc.hInstance      = hInstance;
        wc.hCursor        = LoadCursor(nullptr, IDC_ARROW);
        wc.lpszClassName  = L"ZeroPhaseEDR";
        wc.hIcon          = iconBig;    // taskbar, alt-tab
        wc.hIconSm        = iconSmall;  // title bar
        RegisterClassExW(&wc);

        hwnd_ = CreateWindowExW(
            0, L"ZeroPhaseEDR",
            L"ZeroPhase EDR — Endpoint Detection & Response",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 1440, 900,
            nullptr, nullptr, hInstance, nullptr);
        if (!hwnd_) return false;

        // Also set icons on the window directly (ensures taskbar picks them up)
        SendMessage(hwnd_, WM_SETICON, ICON_BIG,   (LPARAM)iconBig);
        SendMessage(hwnd_, WM_SETICON, ICON_SMALL,  (LPARAM)iconSmall);

        if (!createDevice()) { cleanup(); return false; }

        ShowWindow(hwnd_, SW_SHOWDEFAULT);
        UpdateWindow(hwnd_);

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.IniFilename = nullptr;

        ImGui_ImplWin32_Init(hwnd_);
        ImGui_ImplDX11_Init(device_, context_);

        initialized_ = true;
        return true;
    }

    void shutdown() {
        if (!initialized_) return;
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        cleanupDevice();
        if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; }
        s_instance = nullptr;
        initialized_ = false;
    }

    bool processEvents() {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) { shouldClose_ = true; return false; }
        }
        return !shouldClose_;
    }

    void beginFrame() {
        // ── Handle pending resize ──
        if (resizePending_) {
            resizePending_ = false;
            if (rtv_) { rtv_->Release(); rtv_ = nullptr; }
            swapChain_->ResizeBuffers(0, resizeW_, resizeH_,
                DXGI_FORMAT_UNKNOWN, 0);
            createRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
    }

    void endFrame() {
        ImGui::Render();
        const float clear[4] = { 0.953f, 0.957f, 0.965f, 1.0f };
        context_->OMSetRenderTargets(1, &rtv_, nullptr);
        context_->ClearRenderTargetView(rtv_, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        swapChain_->Present(1, 0);
    }

    bool shouldClose() const { return shouldClose_; }
    HWND getHwnd() const { return hwnd_; }
    ID3D11Device* getDevice() const { return device_; }

private:
    bool createDevice() {
        DXGI_SWAP_CHAIN_DESC sd = {};
        sd.BufferCount              = 2;
        sd.BufferDesc.Width         = 0;   // match window
        sd.BufferDesc.Height        = 0;
        sd.BufferDesc.Format        = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate   = {60, 1};
        sd.BufferUsage              = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow             = hwnd_;
        sd.SampleDesc.Count         = 1;
        sd.Windowed                 = TRUE;
        sd.SwapEffect               = DXGI_SWAP_EFFECT_DISCARD;
        sd.Flags                    = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

        UINT flags = 0;
        D3D_FEATURE_LEVEL fl;
        D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
        if (FAILED(D3D11CreateDeviceAndSwapChain(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                levels, 2, D3D11_SDK_VERSION,
                &sd, &swapChain_, &device_, &fl, &context_)))
            return false;

        createRenderTarget();
        return true;
    }

    void createRenderTarget() {
        ID3D11Texture2D* buf = nullptr;
        swapChain_->GetBuffer(0, IID_PPV_ARGS(&buf));
        if (buf) {
            device_->CreateRenderTargetView(buf, nullptr, &rtv_);
            buf->Release();
        }
    }

    void cleanupDevice() {
        if (rtv_)       { rtv_->Release();       rtv_ = nullptr; }
        if (swapChain_) { swapChain_->Release();  swapChain_ = nullptr; }
        if (context_)   { context_->Release();    context_ = nullptr; }
        if (device_)    { device_->Release();     device_ = nullptr; }
    }

    void cleanup() { cleanupDevice(); if (hwnd_) { DestroyWindow(hwnd_); hwnd_ = nullptr; } }

    // ── Window procedure — handles WM_SIZE to trigger swap chain resize ──
    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg) {
        case WM_SIZE:
            if (s_instance && s_instance->device_ && wParam != SIZE_MINIMIZED) {
                s_instance->resizeW_ = (UINT)LOWORD(lParam);
                s_instance->resizeH_ = (UINT)HIWORD(lParam);
                s_instance->resizePending_ = true;
            }
            return 0;

        case WM_GETMINMAXINFO: {
            // Enforce minimum window size
            LPMINMAXINFO mmi = (LPMINMAXINFO)lParam;
            mmi->ptMinTrackSize.x = 1024;
            mmi->ptMinTrackSize.y = 600;
            return 0;
        }

        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;  // disable ALT menu
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }

    // ── Static instance pointer for the C-style WndProc ──
    static inline GuiRenderer* s_instance = nullptr;

    HINSTANCE hInstance_   = nullptr;
    HWND hwnd_             = nullptr;
    ID3D11Device* device_  = nullptr;
    ID3D11DeviceContext* context_   = nullptr;
    IDXGISwapChain* swapChain_     = nullptr;
    ID3D11RenderTargetView* rtv_   = nullptr;

    bool initialized_     = false;
    bool shouldClose_     = false;

    // Resize state — deferred to beginFrame so we're not in the middle of rendering
    bool resizePending_   = false;
    UINT resizeW_         = 0;
    UINT resizeH_         = 0;
};

} // namespace gui
} // namespace zerophase

#endif
