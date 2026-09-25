/*
 * ZeroPhase EDR — GUI Entry Point
 */

#include "native.hpp"
#include "resource.h"
#include "gui/renderer.hpp"
#include "gui/theme.hpp"
#include "gui/auto_scanner.hpp"
#include "gui/dashboard.hpp"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    native::enablePrivilege(SE_DEBUG_NAME);
    native::NativeApi::instance();

    zerophase::gui::GuiRenderer renderer;
    if (!renderer.initialize(hInstance)) {
        MessageBoxW(nullptr, L"Failed to initialize DirectX11.",
            L"ZeroPhase EDR", MB_OK | MB_ICONERROR);
        return 1;
    }

    zerophase::gui::ApplyZeroPhaseTheme();

    // ── Fonts ──
    ImGuiIO& io = ImGui::GetIO();
    const char* segoe    = "C:\\Windows\\Fonts\\segoeui.ttf";
    const char* segoeb   = "C:\\Windows\\Fonts\\segoeuib.ttf";

    zerophase::gui::g_fontMain  = io.Fonts->AddFontFromFileTTF(segoe,  14.0f);
    zerophase::gui::g_fontBold  = io.Fonts->AddFontFromFileTTF(segoeb, 14.0f);
    zerophase::gui::g_fontTitle = io.Fonts->AddFontFromFileTTF(segoeb, 20.0f);
    zerophase::gui::g_fontSmall = io.Fonts->AddFontFromFileTTF(segoe,  12.0f);
    zerophase::gui::g_fontBig   = io.Fonts->AddFontFromFileTTF(segoeb, 28.0f);

    if (!zerophase::gui::g_fontMain) {
        ImFontConfig cfg; cfg.SizePixels = 14.0f;
        io.Fonts->AddFontDefault(&cfg);
    }

    zerophase::gui::AutoScanner scanner;
    scanner.start();

    zerophase::gui::Dashboard dashboard(scanner);

    // Clear color matches PageBg (#F3F4F6)
    while (renderer.processEvents()) {
        renderer.beginFrame();
        dashboard.render();
        renderer.endFrame();
    }

    scanner.stop();
    renderer.shutdown();
    return 0;
}
