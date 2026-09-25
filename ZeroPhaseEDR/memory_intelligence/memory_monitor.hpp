#pragma once
/*
 * ZeroPhase EDR - Memory Intelligence: Memory Monitor
 *
 * Periodic scanner that monitors memory regions for changes,
 * detects new executable allocations, protection changes,
 * and content modifications in watched processes.
 */

#ifndef ZEROPHASE_MEMORY_MONITOR_HPP
#define ZEROPHASE_MEMORY_MONITOR_HPP

#include "memory_database.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Memory alert
// ============================================================================
struct MemoryAlert {
    DWORD  pid;
    PVOID  baseAddress;
    SIZE_T regionSize;
    MemoryRiskLevel riskLevel;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Memory Monitor
// ============================================================================
class MemoryMonitor {
public:
    using AlertCallback = std::function<void(const MemoryAlert&)>;

    MemoryMonitor(MemoryDatabase& db);
    ~MemoryMonitor();

    // Add/remove PIDs to watch
    void watchProcess(DWORD pid);
    void unwatchProcess(DWORD pid);
    void watchAllUserProcesses();  // Watch all session > 0 processes

    // Manual scan
    std::vector<MemoryAlert> scanWatched(bool deepScan = false);
    std::vector<MemoryAlert> scanProcess(DWORD pid, bool deepScan = false);

    // Alert callback
    void setAlertCallback(AlertCallback cb) { alertCallback_ = std::move(cb); }

    // Statistics
    int scanCount() const { return scanCount_.load(); }
    int alertCount() const { return alertCount_.load(); }
    size_t watchedCount() const;

private:
    std::vector<MemoryAlert> eventsToAlerts(const std::vector<MemoryEvent>& events);

    MemoryDatabase& db_;
    AlertCallback alertCallback_;

    mutable std::mutex watchMutex_;
    std::set<DWORD> watchedPids_;

    std::atomic<int> scanCount_{0};
    std::atomic<int> alertCount_{0};
};

} // namespace memory_intelligence
} // namespace zerophase

#endif // ZEROPHASE_MEMORY_MONITOR_HPP
