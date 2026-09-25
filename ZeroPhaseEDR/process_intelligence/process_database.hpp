#pragma once
/*
 * ZeroPhase EDR - Process Intelligence: Process Database
 *
 * Thread-safe in-memory database of all observed processes.
 * Supports:
 * - Fast lookup by PID
 * - Parent-child relationship tracking
 * - Process lifecycle events (create/exit)
 * - Periodic snapshot diffing to detect new/terminated processes
 */

#ifndef ZEROPHASE_PROCESS_DATABASE_HPP
#define ZEROPHASE_PROCESS_DATABASE_HPP

#include "process_info.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Process lifecycle event
// ============================================================================
enum class ProcessEventType {
    Created,
    Terminated,
    Updated,
};

struct ProcessEvent {
    ProcessEventType type;
    DWORD  pid;
    DWORD  parentPid;
    std::wstring imageName;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Process Database
// ============================================================================
class ProcessDatabase {
public:
    ProcessDatabase() = default;

    // Take a full snapshot and diff against existing state
    // Returns events for new/terminated processes
    std::vector<ProcessEvent> update();

    // Lookups (thread-safe)
    std::optional<ProcessInfo> getByPid(DWORD pid) const;
    std::vector<ProcessInfo> getAll() const;
    std::vector<ProcessInfo> getByParentPid(DWORD parentPid) const;
    std::vector<ProcessInfo> getByName(const std::wstring& name) const;
    std::vector<DWORD> getChildPids(DWORD parentPid) const;

    // Statistics
    size_t activeCount() const;
    size_t totalObserved() const;

    // Lifecycle events
    const std::vector<ProcessEvent>& recentEvents() const {
        std::shared_lock lock(mutex_);
        return recentEvents_;
    }

    // Display
    void displayDatabase() const;
    void displayNew() const;
    void displayTerminated() const;

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<DWORD, ProcessInfo> processes_;     // Active processes
    std::unordered_map<DWORD, ProcessInfo> terminated_;    // Recently terminated
    std::vector<ProcessEvent> recentEvents_;
    size_t totalObserved_ = 0;
    int updateCount_ = 0;
};

} // namespace process_intelligence
} // namespace zerophase

#endif // ZEROPHASE_PROCESS_DATABASE_HPP
