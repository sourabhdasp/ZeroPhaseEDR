#pragma once
/*
 * ZeroPhase EDR - Thread Intelligence: Thread Database
 *
 * Thread-safe in-memory database of all observed threads.
 * Tracks thread lifecycle, detects new/terminated threads,
 * and maintains per-process thread summaries.
 */

#ifndef ZEROPHASE_THREAD_DATABASE_HPP
#define ZEROPHASE_THREAD_DATABASE_HPP

#include "thread_info.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Thread lifecycle event
// ============================================================================
enum class ThreadEventType {
    Created,
    Terminated,
    Updated,
};

struct ThreadEvent {
    ThreadEventType type;
    DWORD  threadId;
    DWORD  ownerPid;
    std::wstring ownerImageName;
    PVOID  startAddress;
    ThreadRiskLevel riskLevel;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Per-process thread summary
// ============================================================================
struct ProcessThreadSummary {
    DWORD  pid                = 0;
    std::wstring imageName;
    DWORD  totalThreads       = 0;
    DWORD  suspiciousThreads  = 0;
    DWORD  suspendedThreads   = 0;
    DWORD  unresolvedThreads  = 0;  // Threads with unresolved start addresses
    ThreadRiskLevel highestRisk = ThreadRiskLevel::None;
};

// ============================================================================
// Thread Database
// ============================================================================
class ThreadDatabase {
public:
    ThreadDatabase() = default;

    // Take a full snapshot and diff against known state
    std::vector<ThreadEvent> updateForProcess(DWORD pid);
    std::vector<ThreadEvent> updateAll();

    // Lookups
    std::optional<ThreadInfo> getByThreadId(DWORD tid) const;
    std::vector<ThreadInfo> getByOwnerPid(DWORD pid) const;
    std::vector<ThreadInfo> getAll() const;
    std::vector<ThreadInfo> getSuspicious() const;

    // Summaries
    ProcessThreadSummary getProcessSummary(DWORD pid) const;
    std::vector<ProcessThreadSummary> getAllProcessSummaries() const;

    // Statistics
    size_t activeCount() const;
    size_t totalObserved() const;
    size_t suspiciousCount() const;

    // Events
    const std::vector<ThreadEvent>& recentEvents() const;

    // Display
    void displayThreadsForProcess(DWORD pid) const;
    void displaySuspiciousThreads() const;
    void displayProcessSummaries() const;
    void displayRecentEvents(int maxEvents = 50) const;

private:
    mutable std::shared_mutex mutex_;

    // Active threads: key = TID
    std::unordered_map<DWORD, ThreadInfo> threads_;

    // Recently terminated threads
    std::unordered_map<DWORD, ThreadInfo> terminated_;

    // Events
    std::vector<ThreadEvent> recentEvents_;

    size_t totalObserved_ = 0;
    int updateCount_ = 0;
};

} // namespace thread_intelligence
} // namespace zerophase

#endif // ZEROPHASE_THREAD_DATABASE_HPP
