#pragma once
/*
 * ZeroPhase EDR — Clean Enterprise Theme
 *
 * Light background, flat design, thin borders, muted professional palette.
 * Color is reserved for data — severity, charts, status indicators.
 * Everything else is white/gray. No gradients, no glow, no animation fluff.
 */

#ifndef ZEROPHASE_GUI_THEME_HPP
#define ZEROPHASE_GUI_THEME_HPP

#include "../imgui/imgui.h"

namespace zerophase {
namespace gui {

inline ImFont* g_fontMain   = nullptr;  // 14px body
inline ImFont* g_fontBold   = nullptr;  // 14px bold
inline ImFont* g_fontTitle  = nullptr;  // 22px bold headings
inline ImFont* g_fontSmall  = nullptr;  // 12px captions
inline ImFont* g_fontBig    = nullptr;  // 32px stat numbers

namespace colors {
    // ── Backgrounds ────────────────────────────────
    inline ImVec4 White       = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    inline ImVec4 PageBg      = ImVec4(0.953f, 0.957f, 0.965f, 1.0f); // #F3F4F6
    inline ImVec4 CardBg      = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    inline ImVec4 SidebarBg   = ImVec4(0.157f, 0.173f, 0.212f, 1.0f); // #282C36 dark sidebar
    inline ImVec4 SidebarHov  = ImVec4(0.200f, 0.220f, 0.270f, 1.0f);
    inline ImVec4 TopBarBg    = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);

    // ── Borders ────────────────────────────────────
    inline ImVec4 Border      = ImVec4(0.878f, 0.886f, 0.906f, 1.0f); // #E0E2E7
    inline ImVec4 BorderLight = ImVec4(0.922f, 0.929f, 0.941f, 1.0f); // #EBEDF0

    // ── Text ───────────────────────────────────────
    inline ImVec4 TextDark    = ImVec4(0.118f, 0.129f, 0.165f, 1.0f); // #1E212A
    inline ImVec4 TextBody    = ImVec4(0.263f, 0.282f, 0.337f, 1.0f); // #434856
    inline ImVec4 TextMuted   = ImVec4(0.478f, 0.502f, 0.565f, 1.0f); // #7A8090
    inline ImVec4 TextLight   = ImVec4(0.620f, 0.643f, 0.702f, 1.0f); // #9EA4B3
    inline ImVec4 TextWhite   = ImVec4(0.96f, 0.96f, 0.97f, 1.0f);

    // ── Severity (muted, professional) ─────────────
    inline ImVec4 Severe      = ImVec4(0.839f, 0.188f, 0.192f, 1.0f); // #D63031  red
    inline ImVec4 High        = ImVec4(0.925f, 0.482f, 0.161f, 1.0f); // #EC7B29  orange
    inline ImVec4 Elevated    = ImVec4(0.925f, 0.722f, 0.161f, 1.0f); // #ECB829  yellow
    inline ImVec4 Moderate    = ImVec4(0.204f, 0.592f, 0.863f, 1.0f); // #3497DC  blue
    inline ImVec4 Low         = ImVec4(0.298f, 0.686f, 0.314f, 1.0f); // #4CAF50  green

    // ── Status ─────────────────────────────────────
    inline ImVec4 Protected   = ImVec4(0.157f, 0.710f, 0.337f, 1.0f); // #28B556
    inline ImVec4 AtRisk      = ImVec4(0.839f, 0.188f, 0.192f, 1.0f);

    // ── Accent (from the ZP logo — used sparingly) ─
    inline ImVec4 Accent      = ImVec4(0.173f, 0.529f, 0.906f, 1.0f); // #2C87E7
    inline ImVec4 AccentLight = ImVec4(0.173f, 0.529f, 0.906f, 0.10f);

    // ── Chart palette ──────────────────────────────
    inline ImU32 ChartBlue    = IM_COL32(44, 135, 231, 255);
    inline ImU32 ChartTeal    = IM_COL32(38, 188, 176, 255);
    inline ImU32 ChartGreen   = IM_COL32(76, 175, 80, 255);
    inline ImU32 ChartOrange  = IM_COL32(236, 123, 41, 255);
    inline ImU32 ChartRed     = IM_COL32(214, 48, 49, 255);
    inline ImU32 ChartPurple  = IM_COL32(142, 68, 173, 255);
    inline ImU32 ChartGray    = IM_COL32(149, 165, 180, 200);
}

inline void ApplyZeroPhaseTheme() {
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding    = 0.0f;   // Crisp edges
    s.ChildRounding     = 6.0f;   // Slight card rounding
    s.FrameRounding     = 4.0f;
    s.PopupRounding     = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.GrabRounding      = 3.0f;
    s.TabRounding       = 4.0f;

    s.WindowPadding     = ImVec2(0, 0);
    s.FramePadding      = ImVec2(8, 5);
    s.ItemSpacing       = ImVec2(8, 6);
    s.ItemInnerSpacing  = ImVec2(6, 4);
    s.ScrollbarSize     = 8.0f;
    s.GrabMinSize       = 8.0f;

    s.WindowBorderSize  = 0.0f;
    s.ChildBorderSize   = 1.0f;
    s.FrameBorderSize   = 0.0f;
    s.PopupBorderSize   = 1.0f;

    ImVec4* c = s.Colors;

    c[ImGuiCol_WindowBg]             = colors::PageBg;
    c[ImGuiCol_ChildBg]              = colors::CardBg;
    c[ImGuiCol_PopupBg]              = colors::White;
    c[ImGuiCol_Border]               = colors::Border;
    c[ImGuiCol_BorderShadow]         = ImVec4(0,0,0,0);

    c[ImGuiCol_Text]                 = colors::TextBody;
    c[ImGuiCol_TextDisabled]         = colors::TextLight;

    c[ImGuiCol_FrameBg]              = ImVec4(0.95f, 0.95f, 0.96f, 1.0f);
    c[ImGuiCol_FrameBgHovered]       = ImVec4(0.92f, 0.93f, 0.95f, 1.0f);
    c[ImGuiCol_FrameBgActive]        = ImVec4(0.90f, 0.91f, 0.93f, 1.0f);

    c[ImGuiCol_TitleBg]              = colors::White;
    c[ImGuiCol_TitleBgActive]        = colors::White;
    c[ImGuiCol_TitleBgCollapsed]     = colors::White;
    c[ImGuiCol_MenuBarBg]            = colors::White;

    c[ImGuiCol_ScrollbarBg]          = ImVec4(0.97f, 0.97f, 0.98f, 1.0f);
    c[ImGuiCol_ScrollbarGrab]        = ImVec4(0.82f, 0.84f, 0.87f, 1.0f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.72f, 0.74f, 0.78f, 1.0f);
    c[ImGuiCol_ScrollbarGrabActive]  = ImVec4(0.62f, 0.64f, 0.68f, 1.0f);

    c[ImGuiCol_CheckMark]            = colors::Accent;
    c[ImGuiCol_SliderGrab]           = colors::Accent;
    c[ImGuiCol_SliderGrabActive]     = colors::Accent;

    c[ImGuiCol_Button]               = ImVec4(0.94f, 0.95f, 0.96f, 1.0f);
    c[ImGuiCol_ButtonHovered]        = ImVec4(0.90f, 0.91f, 0.93f, 1.0f);
    c[ImGuiCol_ButtonActive]         = ImVec4(0.85f, 0.86f, 0.88f, 1.0f);

    c[ImGuiCol_Header]               = colors::AccentLight;
    c[ImGuiCol_HeaderHovered]        = ImVec4(0.17f, 0.53f, 0.91f, 0.15f);
    c[ImGuiCol_HeaderActive]         = ImVec4(0.17f, 0.53f, 0.91f, 0.20f);

    c[ImGuiCol_Separator]            = colors::BorderLight;
    c[ImGuiCol_SeparatorHovered]     = colors::Accent;
    c[ImGuiCol_SeparatorActive]      = colors::Accent;

    c[ImGuiCol_Tab]                  = ImVec4(0.96f, 0.96f, 0.97f, 1.0f);
    c[ImGuiCol_TabHovered]           = colors::AccentLight;
    c[ImGuiCol_TabSelected]          = colors::AccentLight;

    c[ImGuiCol_TableHeaderBg]        = ImVec4(0.96f, 0.96f, 0.97f, 1.0f);
    c[ImGuiCol_TableBorderStrong]    = colors::Border;
    c[ImGuiCol_TableBorderLight]     = colors::BorderLight;
    c[ImGuiCol_TableRowBg]           = ImVec4(0,0,0,0);
    c[ImGuiCol_TableRowBgAlt]        = ImVec4(0.975f, 0.977f, 0.985f, 1.0f);

    c[ImGuiCol_PlotLines]            = colors::Accent;
    c[ImGuiCol_PlotHistogram]        = colors::Accent;
    c[ImGuiCol_ModalWindowDimBg]     = ImVec4(0, 0, 0, 0.35f);
}

inline ImVec4 getSeverityColor(int sev) {
    switch (sev) {
        case 4: return colors::Severe;
        case 3: return colors::High;
        case 2: return colors::Elevated;
        case 1: return colors::Moderate;
        default: return colors::Low;
    }
}
inline const char* getSeverityName(int sev) {
    switch (sev) {
        case 4: return "Severe"; case 3: return "High"; case 2: return "Elevated";
        case 1: return "Moderate"; default: return "Low";
    }
}

} // namespace gui
} // namespace zerophase

#endif
