#pragma once
/*
 * ZeroPhase EDR - Thread Intelligence: Thread Monitor
 *
 * Background thread that periodically scans for thread changes,
 * detects newly created/terminated threads, and generates alerts
 * for suspicious thread activity.
 */

#ifndef ZEROPHASE_THREAD_MONITOR_HPP
#define ZEROPHASE_THREAD_MONITOR_HPP

#include "thread_database.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Monitor alert for suspicious threads
// ============================================================================
struct ThreadAlert {
    DWORD  threadId;
    DWORD  ownerPid;
    std::wstring ownerImageName;
    PVOID  startAddress;
    ThreadRiskLevel riskLevel;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Thread Monitor
// ============================================================================
class ThreadMonitor {
public:
    using AlertCallback = std::function<void(const ThreadAlert&)>;

    ThreadMonitor(ThreadDatabase& db);
    ~ThreadMonitor();

    // Start/stop monitoring
    bool start(int intervalMs = 5000);
    void stop();
    bool isRunning() const { return running_.load(); }

    // Set callback for alerts
    void setAlertCallback(AlertCallback cb) { alertCallback_ = std::move(cb); }

    // Manual single scan (useful for on-demand analysis)
    std::vector<ThreadAlert> scanOnce();

    // Scan a specific process
    std::vector<ThreadAlert> scanProcess(DWORD pid);

    // Statistics
    int scanCount() const { return scanCount_.load(); }
    int alertCount() const { return alertCount_.load(); }

private:
    void monitorLoop();
    std::vector<ThreadAlert> generateAlerts(const std::vector<ThreadEvent>& events);

    ThreadDatabase& db_;
    AlertCallback alertCallback_;

    std::atomic<bool> running_{false};
    std::thread monitorThread_;
    int intervalMs_ = 5000;

    std::atomic<int> scanCount_{0};
    std::atomic<int> alertCount_{0};
};

} // namespace thread_intelligence
} // namespace zerophase

#endif // ZEROPHASE_THREAD_MONITOR_HPP
