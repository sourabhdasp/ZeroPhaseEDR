#pragma once
/*
 * ZeroPhase EDR — Premium Responsive Dashboard
 *
 * All layout is proportional (% of available space).
 * Real pie charts, bar charts, trend lines via ImDrawList.
 * Interactive hover states and tooltips.
 */

#ifndef ZEROPHASE_GUI_DASHBOARD_HPP
#define ZEROPHASE_GUI_DASHBOARD_HPP

#include "theme.hpp"
#include "auto_scanner.hpp"
#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace zerophase {
namespace gui {

enum class DashPage { Home, Alerts, Processes, Scan, Settings };

class Dashboard {
public:
    Dashboard(AutoScanner& sc) : sc_(sc) {}

    void render() {
        auto st = sc_.getStatus();
        auto alerts = sc_.getAlerts();
        int unack = sc_.getUnacknowledgedCount();

        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos);
        ImGui::SetNextWindowSize(vp->WorkSize);
        ImGui::Begin("##R", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        float totalW = ImGui::GetContentRegionAvail().x;
        float totalH = ImGui::GetContentRegionAvail().y;
        float sbW = totalW * 0.155f;
        if (sbW < 180) sbW = 180;
        if (sbW > 240) sbW = 240;

        // sidebar
        ImGui::PushStyleColor(ImGuiCol_ChildBg, colors::SidebarBg);
        ImGui::BeginChild("##sb", ImVec2(sbW, totalH), false);
        drawSidebar(sbW, totalH, st, unack);
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::SameLine(0, 0);

        float contentW = totalW - sbW;
        ImGui::PushStyleColor(ImGuiCol_ChildBg, colors::PageBg);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(contentW * 0.02f, 16));
        ImGui::BeginChild("##ct", ImVec2(contentW, totalH), false);

        switch (pg_) {
            case DashPage::Home:      drawHome(st, alerts); break;
            case DashPage::Alerts:    drawAlerts(alerts); break;
            case DashPage::Processes: drawProcesses(); break;
            case DashPage::Scan:      drawScan(st); break;
            case DashPage::Settings:  drawSettings(st); break;
        }

        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        ImGui::End();
    }

private:
    // ================================================================
    //  SIDEBAR
    // ================================================================
    void drawSidebar(float w, float h, const ProtectionStatus& st, int unack) {
        float pad = w * 0.08f;
        ImGui::SetCursorPos(ImVec2(pad, pad));

        if (g_fontBold) ImGui::PushFont(g_fontBold);
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextWhite);
        ImGui::Text("ZeroPhase");
        ImGui::PopStyleColor();
        if (g_fontBold) ImGui::PopFont();

        ImGui::SetCursorPosX(pad);
        if (g_fontSmall) ImGui::PushFont(g_fontSmall);
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextLight);
        ImGui::Text("EDR v1.0");
        ImGui::PopStyleColor();
        if (g_fontSmall) ImGui::PopFont();

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + h * 0.015f);

        // status pill
        {
            ImVec2 p(ImGui::GetWindowPos().x + pad, ImGui::GetCursorScreenPos().y);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            float pw = w - pad * 2;
            ImU32 bg = st.isProtected ? IM_COL32(40,167,69,35) : IM_COL32(214,48,49,35);
            ImU32 tc = st.isProtected ? IM_COL32(72,199,110,255) : IM_COL32(240,80,80,255);
            dl->AddRectFilled(p, ImVec2(p.x + pw, p.y + 28), bg, 14.0f);
            dl->AddCircleFilled(ImVec2(p.x + 13, p.y + 14), 4, tc);
            dl->AddText(ImVec2(p.x + 24, p.y + 6), tc,
                st.isProtected ? "Protected" : "At Risk");
            ImGui::Dummy(ImVec2(0, 36));
        }

        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + h * 0.01f);

        // nav
        auto nav = [&](const char* lbl, DashPage pg, int badge = 0) {
            bool sel = (pg_ == pg);
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();

            if (sel) {
                dl->AddRectFilled(p, ImVec2(p.x + 3, p.y + 30),
                    ImGui::ColorConvertFloat4ToU32(colors::Accent));
                dl->AddRectFilled(p, ImVec2(p.x + w, p.y + 30), IM_COL32(255,255,255,10));
            }

            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0,0,0,0));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1,1,1,0.06f));
            ImGui::PushStyleColor(ImGuiCol_Text, sel ? colors::TextWhite : ImVec4(0.6f,0.63f,0.7f,1));
            ImGui::SetCursorPosX(pad);
            if (ImGui::Button(lbl, ImVec2(w - pad * 2, 30))) pg_ = pg;
            ImGui::PopStyleColor(3);

            if (badge > 0) {
                char bb[8]; snprintf(bb, sizeof(bb), "%d", badge);
                float tw = ImGui::CalcTextSize(bb).x;
                ImVec2 bp(p.x + w - pad - tw - 14, p.y + 6);
                dl->AddRectFilled(bp, ImVec2(bp.x + tw + 10, bp.y + 18),
                    ImGui::ColorConvertFloat4ToU32(colors::Severe), 9.0f);
                dl->AddText(ImVec2(bp.x + 5, bp.y + 2), IM_COL32(255,255,255,255), bb);
            }
        };

        nav("Dashboard", DashPage::Home);
        nav("Alerts", DashPage::Alerts, unack);
        nav("Processes", DashPage::Processes);
        nav("Scan", DashPage::Scan);
        nav("Settings", DashPage::Settings);

        // bottom
        ImGui::SetCursorPosY(h - 44);
        if (g_fontSmall) ImGui::PushFont(g_fontSmall);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.42f,0.45f,0.52f,1));
        ImGui::SetCursorPosX(pad);
        ImGui::Text("Scans %d", st.totalScans);
        ImGui::SetCursorPosX(pad);
        double up = sc_.getUptimeSeconds();
        ImGui::Text("Up %02d:%02d:%02d", (int)(up/3600), ((int)up%3600)/60, (int)up%60);
        ImGui::PopStyleColor();
        if (g_fontSmall) ImGui::PopFont();
    }

    // ================================================================
    //  HOME
    // ================================================================
    void drawHome(const ProtectionStatus& st, const std::vector<AlertEvent>& alerts) {
        title("Dashboard");
        float W = ImGui::GetContentRegionAvail().x;
        float gap = W * 0.01f;
        if (gap < 8) gap = 8;

        // ── row 1: stat cards (responsive 5 columns) ──
        float cw = (W - gap * 4) / 5;
        statCard("PROCESSES", std::to_string(st.processCount).c_str(), nullptr, cw);
        ImGui::SameLine(0, gap);
        statCard("SCANS", std::to_string(st.totalScans).c_str(), nullptr, cw);
        ImGui::SameLine(0, gap);
        statCard("DETECTIONS", std::to_string(st.totalFindings).c_str(), nullptr, cw);
        ImGui::SameLine(0, gap);
        statCard("CRITICAL", std::to_string(st.criticalFindings).c_str(),
            st.criticalFindings > 0 ? &colors::Severe : &colors::Protected, cw);
        ImGui::SameLine(0, gap);
        statCard("HIGH", std::to_string(st.highFindings).c_str(),
            st.highFindings > 0 ? &colors::High : nullptr, cw);

        ImGui::Spacing(); ImGui::Spacing();

        // ── row 2: charts row — 3 panels ──
        float r2h = ImGui::GetContentRegionAvail().y * 0.42f;
        if (r2h < 180) r2h = 180;
        float leftW  = W * 0.38f;
        float midW   = W * 0.32f - gap;
        float rightW = W * 0.30f - gap;

        // Severity Breakdown (horizontal bars)
        cardBegin("SEVERITY BREAKDOWN", leftW, r2h);
        {
            auto sc = sc_.getSeverityCounts();
            const char* names[] = {"Severe","High","Elevated","Moderate","Low"};
            int vals[] = {sc.severe, sc.high, sc.elevated, sc.moderate, sc.low};
            ImVec4 cols[] = {colors::Severe, colors::High, colors::Elevated, colors::Moderate, colors::Low};
            int mx = 1;
            for (int i = 0; i < 5; i++) if (vals[i] > mx) mx = vals[i];

            float barArea = leftW - 120;
            if (barArea < 60) barArea = 60;
            for (int i = 0; i < 5; i++) {
                ImGui::PushStyleColor(ImGuiCol_Text, colors::TextBody);
                ImGui::Text("%-10s", names[i]);
                ImGui::PopStyleColor();
                ImGui::SameLine(85);
                ImVec2 bp = ImGui::GetCursorScreenPos();
                float bw = (vals[i] > 0) ? (barArea * vals[i] / mx) : 0;
                ImDrawList* dl = ImGui::GetWindowDrawList();
                // track bg
                dl->AddRectFilled(bp, ImVec2(bp.x + barArea, bp.y + 14),
                    IM_COL32(230,232,238,255), 3.0f);
                // value bar
                if (bw > 0)
                    dl->AddRectFilled(bp, ImVec2(bp.x + bw, bp.y + 14),
                        ImGui::ColorConvertFloat4ToU32(cols[i]), 3.0f);
                // hover tooltip
                if (ImGui::IsMouseHoveringRect(bp, ImVec2(bp.x + barArea, bp.y + 14))) {
                    ImGui::BeginTooltip();
                    ImGui::Text("%s: %d", names[i], vals[i]);
                    ImGui::EndTooltip();
                }
                ImGui::Dummy(ImVec2(barArea, 16));
                ImGui::SameLine(leftW - 32);
                if (g_fontBold) ImGui::PushFont(g_fontBold);
                ImGui::PushStyleColor(ImGuiCol_Text, cols[i]);
                ImGui::Text("%d", vals[i]);
                ImGui::PopStyleColor();
                if (g_fontBold) ImGui::PopFont();
                ImGui::Spacing();
            }
        }
        cardEnd();

        ImGui::SameLine(0, gap);

        // Detection Sources (pie chart)
        cardBegin("DETECTION SOURCES", midW, r2h);
        {
            auto src = sc_.getSourceCounts();
            ImU32 pieColors[] = {colors::ChartBlue, colors::ChartTeal, colors::ChartGreen,
                                 colors::ChartOrange, colors::ChartRed, colors::ChartPurple, colors::ChartGray};

            float radius = (std::min(midW, r2h) - 80) * 0.35f;
            if (radius < 40) radius = 40;
            ImVec2 center(ImGui::GetCursorScreenPos().x + midW * 0.35f,
                          ImGui::GetCursorScreenPos().y + (r2h - 60) * 0.45f);
            ImDrawList* dl = ImGui::GetWindowDrawList();

            int total = 0;
            std::vector<std::pair<std::string, int>> entries;
            for (const auto& [k,v] : src) { entries.push_back({k,v}); total += v; }
            if (total == 0) { entries.push_back({"None", 1}); total = 1; }

            // draw donut
            float startAngle = -M_PI / 2;
            float inner = radius * 0.55f;
            for (size_t i = 0; i < entries.size(); i++) {
                float sweep = 2.0f * M_PI * entries[i].second / total;
                ImU32 col = pieColors[i % 7];
                int segs = (int)(sweep / (M_PI/30)) + 4;
                // outer arc
                for (int s = 0; s < segs; s++) {
                    float a0 = startAngle + sweep * s / segs;
                    float a1 = startAngle + sweep * (s + 1) / segs;
                    ImVec2 p0(center.x + cosf(a0)*inner, center.y + sinf(a0)*inner);
                    ImVec2 p1(center.x + cosf(a0)*radius, center.y + sinf(a0)*radius);
                    ImVec2 p2(center.x + cosf(a1)*radius, center.y + sinf(a1)*radius);
                    ImVec2 p3(center.x + cosf(a1)*inner, center.y + sinf(a1)*inner);
                    dl->AddQuadFilled(p0, p1, p2, p3, col);
                }
                startAngle += sweep;
            }
            // center circle (donut hole)
            dl->AddCircleFilled(center, inner - 2, IM_COL32(255,255,255,255), 32);
            // center text
            char ctxt[16]; snprintf(ctxt, sizeof(ctxt), "%d", total);
            ImVec2 ts = ImGui::CalcTextSize(ctxt);
            dl->AddText(ImVec2(center.x - ts.x/2, center.y - ts.y/2),
                ImGui::ColorConvertFloat4ToU32(colors::TextDark), ctxt);

            // legend
            float lx = midW * 0.68f;
            float ly = ImGui::GetCursorScreenPos().y + 4;
            for (size_t i = 0; i < entries.size() && i < 6; i++) {
                ImVec2 lp(ImGui::GetWindowPos().x + lx, ly + i * 20);
                dl->AddRectFilled(lp, ImVec2(lp.x + 10, lp.y + 10), pieColors[i % 7], 2.0f);
                char lb[64]; snprintf(lb, sizeof(lb), "%s (%d)", entries[i].first.c_str(), entries[i].second);
                dl->AddText(ImVec2(lp.x + 16, lp.y - 2),
                    ImGui::ColorConvertFloat4ToU32(colors::TextBody), lb);
            }
            ImGui::Dummy(ImVec2(0, r2h - 70));
        }
        cardEnd();

        ImGui::SameLine(0, gap);

        // Scan Trend (bar chart)
        cardBegin("SCAN TREND", rightW, r2h);
        {
            auto hist = sc_.getScanHistory();
            float chartH = r2h - 80;
            if (chartH < 60) chartH = 60;
            float chartW = rightW - 40;

            ImVec2 origin(ImGui::GetCursorScreenPos().x + 8, ImGui::GetCursorScreenPos().y + chartH);
            ImDrawList* dl = ImGui::GetWindowDrawList();

            int maxF = 1;
            for (const auto& h : hist) if (h.findings > maxF) maxF = h.findings;

            if (hist.size() >= 2) {
                float barW = chartW / hist.size() - 2;
                if (barW < 3) barW = 3;

                // grid lines
                for (int g = 0; g <= 4; g++) {
                    float y = origin.y - chartH * g / 4;
                    dl->AddLine(ImVec2(origin.x, y), ImVec2(origin.x + chartW, y),
                        IM_COL32(230,232,238,255));
                }

                // bars
                for (size_t i = 0; i < hist.size(); i++) {
                    float x = origin.x + i * (chartW / hist.size());
                    float h = (hist[i].findings > 0) ? (chartH * hist[i].findings / maxF) : 0;
                    ImVec2 p0(x + 1, origin.y);
                    ImVec2 p1(x + barW, origin.y - h);
                    dl->AddRectFilled(p0, p1, colors::ChartBlue, 2.0f);

                    // hover
                    if (ImGui::IsMouseHoveringRect(ImVec2(p1.x - barW, p1.y), p0)) {
                        dl->AddRectFilled(p0, p1, IM_COL32(44,135,231,180), 2.0f);
                        ImGui::BeginTooltip();
                        ImGui::Text("Findings: %d", hist[i].findings);
                        ImGui::Text("Processes: %d", hist[i].processes);
                        ImGui::Text("Scan: %.0f ms", hist[i].timeMs);
                        ImGui::EndTooltip();
                    }
                }

                // trend line
                for (size_t i = 1; i < hist.size(); i++) {
                    float x0 = origin.x + (i-1) * (chartW / hist.size()) + barW/2;
                    float x1 = origin.x + i * (chartW / hist.size()) + barW/2;
                    float y0 = origin.y - chartH * hist[i-1].findings / maxF;
                    float y1 = origin.y - chartH * hist[i].findings / maxF;
                    dl->AddLine(ImVec2(x0,y0), ImVec2(x1,y1), colors::ChartTeal, 2.0f);
                    dl->AddCircleFilled(ImVec2(x1,y1), 3, colors::ChartTeal);
                }
            } else {
                ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
                ImGui::Text("Collecting data...");
                ImGui::PopStyleColor();
            }
            ImGui::Dummy(ImVec2(0, chartH + 8));
        }
        cardEnd();

        ImGui::Spacing(); ImGui::Spacing();

        // ── row 3: alerts table ──
        float tableH = ImGui::GetContentRegionAvail().y - 4;
        if (tableH < 80) tableH = 80;
        cardBegin("RECENT ALERTS", W, tableH);
        {
            if (alerts.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
                ImGui::Text("No alerts detected. Endpoint is clean.");
                ImGui::PopStyleColor();
            } else if (ImGui::BeginTable("##ha", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
                ImVec2(0, ImGui::GetContentRegionAvail().y)))
            {
                ImGui::TableSetupColumn("Severity", 0, 0.10f);
                ImGui::TableSetupColumn("Source",   0, 0.10f);
                ImGui::TableSetupColumn("Process",  0, 0.18f);
                ImGui::TableSetupColumn("Title",    0, 0.52f);
                ImGui::TableSetupColumn("MITRE",    0, 0.10f);
                ImGui::TableHeadersRow();
                for (int i = (int)alerts.size()-1; i >= 0; i--) {
                    const auto& a = alerts[i];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); sevDot(a.severity);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
                    ImGui::Text("%s", a.source.c_str()); ImGui::PopStyleColor();
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%s", a.processName.c_str());
                    ImGui::TableSetColumnIndex(3); ImGui::TextWrapped("%s", a.title.c_str());
                    ImGui::TableSetColumnIndex(4);
                    if (!a.mitreId.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, colors::Accent);
                        ImGui::Text("%s", a.mitreId.c_str()); ImGui::PopStyleColor();
                    }
                }
                ImGui::EndTable();
            }
        }
        cardEnd();
    }

    // ================================================================
    //  ALERTS
    // ================================================================
    void drawAlerts(const std::vector<AlertEvent>& alerts) {
        title("Alerts");
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
        ImGui::Text("%zu total  |  %d new", alerts.size(), sc_.getUnacknowledgedCount());
        ImGui::PopStyleColor();
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 130);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.17f,0.53f,0.91f,1));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f,0.58f,0.95f,1));
        ImGui::PushStyleColor(ImGuiCol_Text, colors::White);
        if (ImGui::Button("Acknowledge All", ImVec2(140, 28))) sc_.acknowledgeAll();
        ImGui::PopStyleColor(3);
        ImGui::Spacing();

        if (ImGui::BeginTable("##at", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0, ImGui::GetContentRegionAvail().y - 4)))
        {
            ImGui::TableSetupScrollFreeze(0,1);
            ImGui::TableSetupColumn("Severity", 0, 0.09f);
            ImGui::TableSetupColumn("Source", 0, 0.09f);
            ImGui::TableSetupColumn("PID", 0, 0.06f);
            ImGui::TableSetupColumn("Process", 0, 0.16f);
            ImGui::TableSetupColumn("Title", 0, 0.50f);
            ImGui::TableSetupColumn("MITRE", 0, 0.10f);
            ImGui::TableHeadersRow();
            for (int i = (int)alerts.size()-1; i >= 0; i--) {
                const auto& a = alerts[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); sevDot(a.severity);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%s", a.source.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%u", a.pid);
                ImGui::TableSetColumnIndex(3); ImGui::Text("%s", a.processName.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::PushStyleColor(ImGuiCol_Text, a.acknowledged ? colors::TextLight : colors::TextDark);
                ImGui::TextWrapped("%s", a.title.c_str()); ImGui::PopStyleColor();
                ImGui::TableSetColumnIndex(5);
                if (!a.mitreId.empty()) {
                    ImGui::PushStyleColor(ImGuiCol_Text, colors::Accent);
                    ImGui::Text("%s", a.mitreId.c_str()); ImGui::PopStyleColor();
                }
            }
            ImGui::EndTable();
        }
    }

    // ================================================================
    //  PROCESSES
    // ================================================================
    void drawProcesses() {
        title("Processes");
        auto procs = sc_.getProcessSnapshot();
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
        ImGui::Text("%zu active", procs.size()); ImGui::PopStyleColor();
        ImGui::SameLine(0, 20);
        static char filt[128] = "";
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x * 0.25f);
        ImGui::InputTextWithHint("##pf", "Search...", filt, sizeof(filt));
        ImGui::Spacing();

        if (ImGui::BeginTable("##pt", 7,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp,
            ImVec2(0, ImGui::GetContentRegionAvail().y - 4)))
        {
            ImGui::TableSetupScrollFreeze(0,1);
            ImGui::TableSetupColumn("PID", 0, 0.07f);
            ImGui::TableSetupColumn("PPID", 0, 0.07f);
            ImGui::TableSetupColumn("Name", 0, 0.30f);
            ImGui::TableSetupColumn("Session", 0, 0.07f);
            ImGui::TableSetupColumn("Threads", 0, 0.08f);
            ImGui::TableSetupColumn("Memory", 0, 0.12f);
            ImGui::TableSetupColumn("Integrity", 0, 0.10f);
            ImGui::TableHeadersRow();

            std::string fs = filt;
            std::transform(fs.begin(), fs.end(), fs.begin(), ::tolower);
            for (const auto& p : procs) {
                std::string nm = native::wstringToString(p.imageName);
                if (!fs.empty()) {
                    std::string lo = nm; std::transform(lo.begin(),lo.end(),lo.begin(),::tolower);
                    if (lo.find(fs) == std::string::npos) continue;
                }
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::Text("%u", p.pid);
                ImGui::TableSetColumnIndex(1); ImGui::Text("%u", p.parentPid);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%s", nm.empty()?"[System]":nm.c_str());
                ImGui::TableSetColumnIndex(3); ImGui::Text("%u", p.sessionId);
                ImGui::TableSetColumnIndex(4); ImGui::Text("%u", p.threadCount);
                ImGui::TableSetColumnIndex(5); ImGui::Text("%s", native::formatSize(p.workingSetSize).c_str());
                ImGui::TableSetColumnIndex(6);
                ImVec4 ic = colors::TextMuted;
                if (p.integrityLevel=="System") ic = ImVec4(0.55f,0.35f,0.70f,1);
                else if (p.integrityLevel=="High") ic = colors::High;
                else if (p.integrityLevel=="Low"||p.integrityLevel=="Untrusted") ic = colors::Severe;
                ImGui::PushStyleColor(ImGuiCol_Text,ic);
                ImGui::Text("%s",p.integrityLevel.c_str());
                ImGui::PopStyleColor();
            }
            ImGui::EndTable();
        }
    }

    // ================================================================
    //  SCAN
    // ================================================================
    void drawScan(const ProtectionStatus& st) {
        title("Scan Controls");
        float bw = 170, bh = 34;
        if (!sc_.isRunning()) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f,0.65f,0.38f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f,0.72f,0.42f,1));
            ImGui::PushStyleColor(ImGuiCol_Text, colors::White);
            if (ImGui::Button("Start Protection", ImVec2(bw,bh))) sc_.start();
            ImGui::PopStyleColor(3);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.78f,0.20f,0.22f,1));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f,0.25f,0.27f,1));
            ImGui::PushStyleColor(ImGuiCol_Text, colors::White);
            if (ImGui::Button("Stop Protection", ImVec2(bw,bh))) sc_.stop();
            ImGui::PopStyleColor(3);
            ImGui::SameLine(0,10);
            if (sc_.isPaused()) { if (ImGui::Button("Resume",ImVec2(90,bh))) sc_.resume(); }
            else { if (ImGui::Button("Pause",ImVec2(90,bh))) sc_.pause(); }
        }
        ImGui::Spacing(); ImGui::Spacing();

        float W = ImGui::GetContentRegionAvail().x;
        float gap = 10;
        float cw = (W - gap*2) / 3;
        statCard("TOTAL SCANS", std::to_string(st.totalScans).c_str(), nullptr, cw);
        ImGui::SameLine(0,gap);
        statCard("DETECTIONS", std::to_string(st.totalFindings).c_str(), nullptr, cw);
        ImGui::SameLine(0,gap);
        statCard("CRITICAL", std::to_string(st.criticalFindings).c_str(),
            st.criticalFindings>0 ? &colors::Severe : &colors::Protected, cw);
        ImGui::Spacing(); ImGui::Spacing();

        cardBegin("SCHEDULE", W, 0);
        infoRow("Light scan", "Every 5s — Process + CmdLine");
        infoRow("Full scan",  "Every 30s — adds Syscall check");
        infoRow("Deep scan",  "Every 5min — adds Injection + Memory");
        cardEnd();
    }

    // ================================================================
    //  SETTINGS
    // ================================================================
    void drawSettings(const ProtectionStatus& st) {
        title("Settings");
        PROCESS_MEMORY_COUNTERS_EX pmc={}; pmc.cb=sizeof(pmc);
        GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&pmc,sizeof(pmc));

        float W = ImGui::GetContentRegionAvail().x;
        cardBegin("EDR INFORMATION", W, 0);
        infoRow("Version","1.0.0  (User-Mode Agent)");
        char pid[16]; snprintf(pid,sizeof(pid),"%u",GetCurrentProcessId());
        infoRow("PID", pid);
        infoRow("Memory", native::formatSize(pmc.WorkingSetSize).c_str());
        cardEnd();
        ImGui::Spacing();
        cardBegin("MODULES", W, 0);
        const char* mods[]={"Process","Thread","Memory","DLL","CmdLine",
            "Injection","Syscall","Kernel","Detection","Forensics","Production"};
        for (int i=0;i<11;i++){
            ImGui::PushStyleColor(ImGuiCol_Text,colors::Protected);
            ImGui::Text("Active"); ImGui::PopStyleColor();
            ImGui::SameLine(56); ImGui::Text("Phase %d — %s",i+1,mods[i]);
        }
        cardEnd();
    }

    // ================================================================
    //  Primitives
    // ================================================================
    void title(const char* t) {
        if (g_fontTitle) ImGui::PushFont(g_fontTitle);
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextDark);
        ImGui::Text("%s",t); ImGui::PopStyleColor();
        if (g_fontTitle) ImGui::PopFont();
        ImGui::Spacing();
    }

    void cardBegin(const char* hdr, float w, float h) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, colors::CardBg);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14,10));
        ImGui::BeginChild(hdr, ImVec2(w, h > 0 ? h : 0), true);
        if (g_fontSmall) ImGui::PushFont(g_fontSmall);
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
        ImGui::Text("%s",hdr); ImGui::PopStyleColor();
        if (g_fontSmall) ImGui::PopFont();
        ImGui::Spacing();
    }
    void cardEnd() {
        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();
    }

    void statCard(const char* label, const char* value, const ImVec4* vc, float w) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, colors::CardBg);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14,8));
        ImGui::BeginChild(label, ImVec2(w, 68), true);
        if (g_fontSmall) ImGui::PushFont(g_fontSmall);
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
        ImGui::Text("%s",label); ImGui::PopStyleColor();
        if (g_fontSmall) ImGui::PopFont();
        if (g_fontBig) ImGui::PushFont(g_fontBig);
        ImGui::PushStyleColor(ImGuiCol_Text, vc ? *vc : colors::TextDark);
        ImGui::Text("%s",value); ImGui::PopStyleColor();
        if (g_fontBig) ImGui::PopFont();
        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();
    }

    void infoRow(const char* l, const char* v) {
        ImGui::PushStyleColor(ImGuiCol_Text, colors::TextMuted);
        ImGui::Text("%s",l); ImGui::PopStyleColor();
        ImGui::SameLine(150);
        ImGui::Text("%s",v);
    }

    void sevDot(int sev) {
        ImVec4 c = getSeverityColor(sev);
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddCircleFilled(
            ImVec2(p.x+5, p.y+8), 4, ImGui::ColorConvertFloat4ToU32(c));
        ImGui::Dummy(ImVec2(12,0)); ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, c);
        ImGui::Text("%s", getSeverityName(sev)); ImGui::PopStyleColor();
    }

    AutoScanner& sc_;
    DashPage pg_ = DashPage::Home;
};

} // namespace gui
} // namespace zerophase

#endif
