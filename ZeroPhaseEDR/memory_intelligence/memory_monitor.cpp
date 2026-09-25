/*
 * ZeroPhase EDR - Memory Intelligence: Memory Monitor Implementation
 */

#include "memory_monitor.hpp"

namespace zerophase {
namespace memory_intelligence {

MemoryMonitor::MemoryMonitor(MemoryDatabase& db) : db_(db) {}
MemoryMonitor::~MemoryMonitor() {}

void MemoryMonitor::watchProcess(DWORD pid) {
    std::lock_guard lock(watchMutex_);
    watchedPids_.insert(pid);
}

void MemoryMonitor::unwatchProcess(DWORD pid) {
    std::lock_guard lock(watchMutex_);
    watchedPids_.erase(pid);
}

void MemoryMonitor::watchAllUserProcesses() {
    // Enumerate processes in session > 0 (user sessions)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    std::lock_guard lock(watchMutex_);
    if (Process32FirstW(snap, &pe)) {
        do {
            // Skip system processes (PID 0, 4)
            if (pe.th32ProcessID > 4) {
                watchedPids_.insert(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

size_t MemoryMonitor::watchedCount() const {
    std::lock_guard lock(watchMutex_);
    return watchedPids_.size();
}

std::vector<MemoryAlert> MemoryMonitor::scanProcess(DWORD pid, bool deepScan) {
    auto events = db_.updateProcess(pid, deepScan);
    scanCount_++;
    auto alerts = eventsToAlerts(events);
    alertCount_ += static_cast<int>(alerts.size());

    if (alertCallback_) {
        for (const auto& alert : alerts) {
            alertCallback_(alert);
        }
    }
    return alerts;
}

std::vector<MemoryAlert> MemoryMonitor::scanWatched(bool deepScan) {
    std::vector<DWORD> pids;
    {
        std::lock_guard lock(watchMutex_);
        pids.assign(watchedPids_.begin(), watchedPids_.end());
    }

    std::vector<MemoryAlert> allAlerts;
    for (DWORD pid : pids) {
        auto alerts = scanProcess(pid, deepScan);
        allAlerts.insert(allAlerts.end(), alerts.begin(), alerts.end());
    }
    return allAlerts;
}

std::vector<MemoryAlert> MemoryMonitor::eventsToAlerts(const std::vector<MemoryEvent>& events) {
    std::vector<MemoryAlert> alerts;
    for (const auto& evt : events) {
        if (evt.riskLevel != MemoryRiskLevel::None) {
            MemoryAlert alert;
            alert.pid = evt.pid;
            alert.baseAddress = evt.baseAddress;
            alert.regionSize = evt.regionSize;
            alert.riskLevel = evt.riskLevel;
            alert.description = evt.description;
            alert.timestamp = evt.timestamp;
            alerts.push_back(std::move(alert));
        }
    }
    return alerts;
}

} // namespace memory_intelligence
} // namespace zerophase
