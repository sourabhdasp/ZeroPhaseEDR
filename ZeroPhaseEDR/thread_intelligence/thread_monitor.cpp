/*
 * ZeroPhase EDR - Thread Intelligence: Thread Monitor Implementation
 *
 * Periodic scanner that detects thread lifecycle events and generates
 * alerts for suspicious threads (injection indicators).
 */

#include "thread_monitor.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Constructor / Destructor
// ============================================================================
ThreadMonitor::ThreadMonitor(ThreadDatabase& db) : db_(db) {}

ThreadMonitor::~ThreadMonitor() {
    stop();
}

// ============================================================================
// Start background monitoring
// ============================================================================
bool ThreadMonitor::start(int intervalMs) {
    if (running_.load()) return false;

    intervalMs_ = intervalMs;
    running_.store(true);
    monitorThread_ = std::thread(&ThreadMonitor::monitorLoop, this);
    return true;
}

// ============================================================================
// Stop monitoring
// ============================================================================
void ThreadMonitor::stop() {
    running_.store(false);
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
}

// ============================================================================
// Monitor loop (runs in background thread)
// ============================================================================
void ThreadMonitor::monitorLoop() {
    while (running_.load()) {
        scanOnce();

        // Sleep in small increments so we can stop quickly
        int slept = 0;
        while (slept < intervalMs_ && running_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            slept += 100;
        }
    }
}

// ============================================================================
// Single scan
// ============================================================================
std::vector<ThreadAlert> ThreadMonitor::scanOnce() {
    auto events = db_.updateAll();
    scanCount_++;

    auto alerts = generateAlerts(events);
    alertCount_ += static_cast<int>(alerts.size());

    // Fire callbacks
    if (alertCallback_) {
        for (const auto& alert : alerts) {
            alertCallback_(alert);
        }
    }

    return alerts;
}

// ============================================================================
// Scan a specific process
// ============================================================================
std::vector<ThreadAlert> ThreadMonitor::scanProcess(DWORD pid) {
    auto events = db_.updateForProcess(pid);
    scanCount_++;

    auto alerts = generateAlerts(events);
    alertCount_ += static_cast<int>(alerts.size());

    if (alertCallback_) {
        for (const auto& alert : alerts) {
            alertCallback_(alert);
        }
    }

    return alerts;
}

// ============================================================================
// Generate alerts from thread events
// ============================================================================
std::vector<ThreadAlert> ThreadMonitor::generateAlerts(const std::vector<ThreadEvent>& events) {
    std::vector<ThreadAlert> alerts;

    for (const auto& evt : events) {
        // Alert on new threads with risk
        if (evt.type == ThreadEventType::Created && evt.riskLevel != ThreadRiskLevel::None) {
            ThreadAlert alert;
            alert.threadId = evt.threadId;
            alert.ownerPid = evt.ownerPid;
            alert.ownerImageName = evt.ownerImageName;
            alert.startAddress = evt.startAddress;
            alert.riskLevel = evt.riskLevel;
            alert.timestamp = evt.timestamp;

            // Get the full thread info for a better description
            auto threadOpt = db_.getByThreadId(evt.threadId);
            if (threadOpt) {
                std::string reasons;
                for (size_t i = 0; i < threadOpt->riskReasons.size(); i++) {
                    if (i > 0) reasons += "; ";
                    reasons += threadOpt->riskReasons[i];
                }
                alert.description = "Suspicious thread created: " + reasons;
            } else {
                alert.description = "Suspicious new thread detected";
            }

            alerts.push_back(std::move(alert));
        }
    }

    return alerts;
}

} // namespace thread_intelligence
} // namespace zerophase
