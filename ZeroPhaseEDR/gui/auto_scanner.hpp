#pragma once
/*
 * ZeroPhase EDR - Automatic Background Scanner
 *
 * Runs all intelligence modules on a schedule and feeds
 * alerts to the GUI in real-time.
 */

#ifndef ZEROPHASE_AUTO_SCANNER_HPP
#define ZEROPHASE_AUTO_SCANNER_HPP

#include "../native.hpp"
#include "../process_intelligence/process_info.hpp"
#include "../process_intelligence/process_database.hpp"
#include "../process_intelligence/lineage_detector.hpp"
#include "../commandline_intelligence/commandline_info.hpp"
#include "../commandline_intelligence/commandline_analyzer.hpp"
#include "../commandline_intelligence/commandline_database.hpp"
#include "../syscall_intelligence/syscall_detector.hpp"
#include "../injection_intelligence/injection_detector.hpp"
#include "../memory_intelligence/memory_info.hpp"
#include "../memory_intelligence/entropy_analysis.hpp"
#include "../dll_intelligence/dll_info.hpp"
#include "../kernel_intelligence/kernel_info.hpp"

namespace zerophase {
namespace gui {

// ============================================================================
// Alert Event — unified alert from any scanner module
// ============================================================================
struct AlertEvent {
    DWORD  id            = 0;
    int    severity      = 0;   // 0=Info, 1=Low, 2=Med, 3=High, 4=Critical
    std::string source;         // "Process", "CmdLine", "Injection", etc.
    DWORD  pid           = 0;
    std::string processName;
    std::string title;
    std::string description;
    std::string mitreId;
    std::chrono::system_clock::time_point timestamp;
    bool   acknowledged  = false;
};

// ============================================================================
// Protection Status
// ============================================================================
struct ProtectionStatus {
    bool   isProtected     = true;
    int    totalScans      = 0;
    int    totalFindings   = 0;
    int    criticalFindings= 0;
    int    highFindings    = 0;
    int    activeThreats   = 0;
    int    processCount    = 0;
    std::string scanMode   = "Idle";
    std::string lastScanTime;
    double lastScanDurationMs = 0;
    std::chrono::steady_clock::time_point startTime;
};

// ============================================================================
// Auto Scanner
// ============================================================================
class AutoScanner {
public:
    AutoScanner() {
        status_.startTime = std::chrono::steady_clock::now();
    }

    ~AutoScanner() { stop(); }

    // Start/stop background scanning
    void start() {
        if (running_.load()) return;
        running_.store(true);
        scanThread_ = std::thread(&AutoScanner::scanLoop, this);
    }

    void stop() {
        running_.store(false);
        if (scanThread_.joinable()) scanThread_.join();
    }

    void pause()  { paused_.store(true); }
    void resume() { paused_.store(false); }
    bool isRunning() const { return running_.load(); }
    bool isPaused() const { return paused_.load(); }

    // Get alerts (thread-safe)
    std::vector<AlertEvent> getAlerts() const {
        std::lock_guard lock(alertMutex_);
        return std::vector<AlertEvent>(alerts_.begin(), alerts_.end());
    }

    int getUnacknowledgedCount() const {
        std::lock_guard lock(alertMutex_);
        int count = 0;
        for (const auto& a : alerts_) if (!a.acknowledged) count++;
        return count;
    }

    void acknowledgeAlert(DWORD id) {
        std::lock_guard lock(alertMutex_);
        for (auto& a : alerts_) if (a.id == id) { a.acknowledged = true; break; }
    }

    void acknowledgeAll() {
        std::lock_guard lock(alertMutex_);
        for (auto& a : alerts_) a.acknowledged = true;
    }

    // Get protection status
    ProtectionStatus getStatus() const {
        std::lock_guard lock(statusMutex_);
        return status_;
    }

    // Get uptime in seconds
    double getUptimeSeconds() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(now - status_.startTime).count();
    }

    // Get recent process list for the GUI
    std::vector<process_intelligence::ProcessInfo> getProcessSnapshot() const {
        std::lock_guard lock(dataMutex_);
        return processSnapshot_;
    }

    // Scan history for trend chart (last 30 data points)
    struct ScanPoint { int findings; int processes; double timeMs; };
    std::vector<ScanPoint> getScanHistory() const {
        std::lock_guard lock(dataMutex_);
        return scanHistory_;
    }

    // Severity counts for pie chart
    struct SeverityCounts { int severe=0; int high=0; int elevated=0; int moderate=0; int low=0; };
    SeverityCounts getSeverityCounts() const {
        std::lock_guard lock(alertMutex_);
        SeverityCounts sc;
        for (const auto& a : alerts_) {
            switch(a.severity) {
                case 4: sc.severe++; break;
                case 3: sc.high++; break;
                case 2: sc.elevated++; break;
                case 1: sc.moderate++; break;
                default: sc.low++; break;
            }
        }
        return sc;
    }

    // Source counts for donut chart
    std::map<std::string, int> getSourceCounts() const {
        std::lock_guard lock(alertMutex_);
        std::map<std::string, int> counts;
        for (const auto& a : alerts_) counts[a.source]++;
        return counts;
    }

private:
    void scanLoop() {
        int cycle = 0;
        // Initial scan
        runLightScan();

        while (running_.load()) {
            // Sleep in 100ms increments so we can stop quickly
            for (int i = 0; i < 50 && running_.load(); i++) {  // 5 second light cycle
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!running_.load()) return;
            }
            if (paused_.load()) continue;

            cycle++;

            if (cycle % 6 == 0) {
                // Every 30s: full scan
                runFullScan();
            } else if (cycle % 60 == 0) {
                // Every 5 min: deep scan
                runDeepScan();
            } else {
                // Every 5s: light scan
                runLightScan();
            }
        }
    }

    void runLightScan() {
        try {
            auto t0 = std::chrono::steady_clock::now();
            setStatus("Light Scan");

            // Process scan + lineage
            auto events = processDb_.update();
            auto lineageAlerts = lineageDetector_.analyzeAll(processDb_);

            for (const auto& a : lineageAlerts) {
                addAlert(static_cast<int>(a.riskLevel), "Process",
                    a.childPid, native::wstringToString(a.childName),
                    "Lineage Anomaly", a.description, "");
            }

            // Command line scan
            cmdDb_.update();
            auto suspicious = cmdDb_.getSuspicious();
            for (const auto& cmd : suspicious) {
                std::string tech = cmd.techniques.empty() ? "Suspicious Command" : cmd.techniques[0].techniqueName;
                std::string mid = cmd.techniques.empty() ? "" : cmd.techniques[0].techniqueId;
                addAlert(static_cast<int>(cmd.riskLevel), "CmdLine",
                    cmd.pid, native::wstringToString(cmd.imageName),
                    tech, native::wstringToString(cmd.commandLine).substr(0, 200), mid);
            }

            // Update process snapshot for GUI
            {
                std::lock_guard lock(dataMutex_);
                processSnapshot_ = processDb_.getAll();
            }

            auto t1 = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(t1 - t0).count();

            {
                std::lock_guard lock(statusMutex_);
                status_.totalScans++;
                status_.processCount = static_cast<int>(processDb_.activeCount());
                status_.lastScanDurationMs = elapsed;
                status_.lastScanTime = native::getCurrentTimestamp();
                status_.scanMode = "Protected";
                status_.isProtected = (status_.criticalFindings == 0);
            }
            // Record history point
            {
                std::lock_guard lock(dataMutex_);
                ScanPoint sp;
                sp.findings = static_cast<int>(suspicious.size() + lineageAlerts.size());
                sp.processes = static_cast<int>(processDb_.activeCount());
                sp.timeMs = elapsed;
                scanHistory_.push_back(sp);
                if (scanHistory_.size() > 60) scanHistory_.erase(scanHistory_.begin());
            }
        } catch (...) {}
    }

    void runFullScan() {
        try {
            auto t0 = std::chrono::steady_clock::now();
            setStatus("Full Scan");

            // Light scan first
            runLightScan();

            // Syscall integrity (self)
            zerophase::syscall_intelligence::SyscallDetector syscallDet;
            auto sysResult = syscallDet.scanProcess(GetCurrentProcessId());
            if (sysResult.hookedCount > 0) {
                addAlert(2, "Syscall", GetCurrentProcessId(), "ZeroPhaseEDR.exe",
                    "Syscall Hooks Detected",
                    std::to_string(sysResult.hookedCount) + " hooked Nt functions", "T1562");
            }

            auto t1 = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(t1 - t0).count();

            std::lock_guard lock(statusMutex_);
            status_.lastScanDurationMs = elapsed;
            status_.scanMode = "Protected";
        } catch (...) {}
    }

    void runDeepScan() {
        try {
            setStatus("Deep Scan");
            runFullScan();

            // Injection scan on user-session processes (sample up to 20)
            zerophase::injection_intelligence::InjectionDetector injDet;
            auto procs = processDb_.getAll();
            int scanned = 0;
            for (const auto& proc : procs) {
                if (scanned >= 20) break;
                if (proc.sessionId == 0) continue; // Skip session 0

                auto result = injDet.scanProcess(proc.pid);
                for (const auto& f : result.findings) {
                    if (static_cast<int>(f.riskLevel) >= 3) { // HIGH+
                        addAlert(static_cast<int>(f.riskLevel), "Injection",
                            proc.pid, native::wstringToString(proc.imageName),
                            injection_intelligence::injectionTypeToString(f.type),
                            f.description, f.mitreId);
                    }
                }
                scanned++;
                if (!running_.load()) return;
            }

            std::lock_guard lock(statusMutex_);
            status_.scanMode = "Protected";
        } catch (...) {}
    }

    void setStatus(const std::string& mode) {
        std::lock_guard lock(statusMutex_);
        status_.scanMode = mode;
    }

    void addAlert(int severity, const std::string& source, DWORD pid,
                  const std::string& procName, const std::string& title,
                  const std::string& desc, const std::string& mitre) {
        // Deduplicate: don't add if same pid+title exists in last 100 alerts
        std::lock_guard lock(alertMutex_);
        for (auto it = alerts_.rbegin(); it != alerts_.rend(); ++it) {
            if (it->pid == pid && it->title == title && it->source == source)
                return; // Already exists
        }

        AlertEvent alert;
        alert.id = nextAlertId_++;
        alert.severity = severity;
        alert.source = source;
        alert.pid = pid;
        alert.processName = procName;
        alert.title = title;
        alert.description = desc;
        alert.mitreId = mitre;
        alert.timestamp = std::chrono::system_clock::now();

        alerts_.push_back(alert);
        if (alerts_.size() > 1000) alerts_.pop_front();

        // Update finding counts
        {
            std::lock_guard slock(statusMutex_);
            status_.totalFindings++;
            if (severity >= 4) status_.criticalFindings++;
            if (severity >= 3) status_.highFindings++;
            status_.activeThreats = getUnacknowledgedCountUnsafe();
            status_.isProtected = (status_.criticalFindings == 0);
        }
    }

    int getUnacknowledgedCountUnsafe() const {
        int count = 0;
        for (const auto& a : alerts_) if (!a.acknowledged) count++;
        return count;
    }

    std::vector<ScanPoint> scanHistory_;

    // Scanner instances (own copies, not shared with main)
    process_intelligence::ProcessDatabase processDb_;
    process_intelligence::LineageDetector lineageDetector_;
    commandline_intelligence::CommandLineDatabase cmdDb_;

    // Thread safety
    mutable std::mutex alertMutex_;
    mutable std::mutex statusMutex_;
    mutable std::mutex dataMutex_;

    // State
    std::deque<AlertEvent> alerts_;
    DWORD nextAlertId_ = 1;
    ProtectionStatus status_;
    std::vector<process_intelligence::ProcessInfo> processSnapshot_;

    // Threading
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::thread scanThread_;
};

} // namespace gui
} // namespace zerophase

#endif // ZEROPHASE_AUTO_SCANNER_HPP
