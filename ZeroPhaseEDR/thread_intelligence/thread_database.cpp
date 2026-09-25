/*
 * ZeroPhase EDR - Thread Intelligence: Thread Database Implementation
 *
 * Maintains a live database of threads, detects new/terminated threads,
 * generates events, and provides suspicious thread queries.
 */

#include "thread_database.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Update threads for a specific process
// ============================================================================
std::vector<ThreadEvent> ThreadDatabase::updateForProcess(DWORD pid) {
    auto snapshot = snapshotProcessThreads(pid);
    std::vector<ThreadEvent> events;
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);
    updateCount_++;

    // Build set of currently alive TIDs for this process
    std::set<DWORD> currentTids;
    for (const auto& t : snapshot) {
        currentTids.insert(t.threadId);
    }

    // Detect new threads and update existing
    for (auto& t : snapshot) {
        auto it = threads_.find(t.threadId);
        if (it == threads_.end()) {
            // New thread
            t.isNew = (updateCount_ > 1);
            threads_[t.threadId] = t;
            totalObserved_++;

            if (t.isNew) {
                ThreadEvent evt;
                evt.type = ThreadEventType::Created;
                evt.threadId = t.threadId;
                evt.ownerPid = t.ownerPid;
                evt.ownerImageName = t.ownerImageName;
                evt.startAddress = t.win32StartAddress;
                evt.riskLevel = t.riskLevel;
                evt.timestamp = now;
                events.push_back(evt);
            }
        } else {
            // Update existing thread
            auto& existing = it->second;
            existing.threadState = t.threadState;
            existing.waitReason = t.waitReason;
            existing.priority = t.priority;
            existing.contextSwitches = t.contextSwitches;
            existing.waitTime = t.waitTime;
            existing.kernelTime = t.kernelTime;
            existing.userTime = t.userTime;
            existing.lastUpdated = now;
            existing.isNew = false;
        }
    }

    // Detect terminated threads for this process
    std::vector<DWORD> goneTids;
    for (const auto& [tid, info] : threads_) {
        if (info.ownerPid == pid && currentTids.find(tid) == currentTids.end()) {
            goneTids.push_back(tid);

            ThreadEvent evt;
            evt.type = ThreadEventType::Terminated;
            evt.threadId = tid;
            evt.ownerPid = pid;
            evt.ownerImageName = info.ownerImageName;
            evt.startAddress = info.win32StartAddress;
            evt.riskLevel = info.riskLevel;
            evt.timestamp = now;
            events.push_back(evt);
        }
    }

    for (DWORD tid : goneTids) {
        auto it = threads_.find(tid);
        if (it != threads_.end()) {
            it->second.isAlive = false;
            terminated_[tid] = std::move(it->second);
            threads_.erase(it);
        }
    }

    // Keep recent events bounded
    recentEvents_.insert(recentEvents_.end(), events.begin(), events.end());
    if (recentEvents_.size() > 2000) {
        recentEvents_.erase(recentEvents_.begin(),
            recentEvents_.begin() + (recentEvents_.size() - 2000));
    }

    return events;
}

// ============================================================================
// Update all threads system-wide
// ============================================================================
std::vector<ThreadEvent> ThreadDatabase::updateAll() {
    auto snapshot = snapshotAllThreads();
    std::vector<ThreadEvent> events;
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);
    updateCount_++;

    std::set<DWORD> currentTids;
    for (const auto& t : snapshot) {
        currentTids.insert(t.threadId);
    }

    for (auto& t : snapshot) {
        auto it = threads_.find(t.threadId);
        if (it == threads_.end()) {
            t.isNew = (updateCount_ > 1);
            threads_[t.threadId] = t;
            totalObserved_++;

            if (t.isNew) {
                ThreadEvent evt;
                evt.type = ThreadEventType::Created;
                evt.threadId = t.threadId;
                evt.ownerPid = t.ownerPid;
                evt.ownerImageName = t.ownerImageName;
                evt.startAddress = t.win32StartAddress;
                evt.riskLevel = t.riskLevel;
                evt.timestamp = now;
                events.push_back(evt);
            }
        } else {
            auto& existing = it->second;
            existing.threadState = t.threadState;
            existing.waitReason = t.waitReason;
            existing.priority = t.priority;
            existing.contextSwitches = t.contextSwitches;
            existing.waitTime = t.waitTime;
            existing.kernelTime = t.kernelTime;
            existing.userTime = t.userTime;
            existing.lastUpdated = now;
            existing.isNew = false;
        }
    }

    std::vector<DWORD> goneTids;
    for (const auto& [tid, info] : threads_) {
        if (currentTids.find(tid) == currentTids.end()) {
            goneTids.push_back(tid);
            ThreadEvent evt;
            evt.type = ThreadEventType::Terminated;
            evt.threadId = tid;
            evt.ownerPid = info.ownerPid;
            evt.ownerImageName = info.ownerImageName;
            evt.startAddress = info.win32StartAddress;
            evt.riskLevel = info.riskLevel;
            evt.timestamp = now;
            events.push_back(evt);
        }
    }

    for (DWORD tid : goneTids) {
        auto it = threads_.find(tid);
        if (it != threads_.end()) {
            it->second.isAlive = false;
            terminated_[tid] = std::move(it->second);
            threads_.erase(it);
        }
    }

    // Trim terminated to last 5000
    if (terminated_.size() > 5000) {
        auto it = terminated_.begin();
        while (terminated_.size() > 4000 && it != terminated_.end()) {
            it = terminated_.erase(it);
        }
    }

    recentEvents_.insert(recentEvents_.end(), events.begin(), events.end());
    if (recentEvents_.size() > 2000) {
        recentEvents_.erase(recentEvents_.begin(),
            recentEvents_.begin() + (recentEvents_.size() - 2000));
    }

    return events;
}

// ============================================================================
// Lookups
// ============================================================================
std::optional<ThreadInfo> ThreadDatabase::getByThreadId(DWORD tid) const {
    std::shared_lock lock(mutex_);
    auto it = threads_.find(tid);
    if (it != threads_.end()) return it->second;
    return std::nullopt;
}

std::vector<ThreadInfo> ThreadDatabase::getByOwnerPid(DWORD pid) const {
    std::shared_lock lock(mutex_);
    std::vector<ThreadInfo> result;
    for (const auto& [tid, info] : threads_) {
        if (info.ownerPid == pid) result.push_back(info);
    }
    return result;
}

std::vector<ThreadInfo> ThreadDatabase::getAll() const {
    std::shared_lock lock(mutex_);
    std::vector<ThreadInfo> result;
    result.reserve(threads_.size());
    for (const auto& [tid, info] : threads_) {
        result.push_back(info);
    }
    return result;
}

std::vector<ThreadInfo> ThreadDatabase::getSuspicious() const {
    std::shared_lock lock(mutex_);
    std::vector<ThreadInfo> result;
    for (const auto& [tid, info] : threads_) {
        if (info.riskLevel != ThreadRiskLevel::None) {
            result.push_back(info);
        }
    }
    // Sort by risk score descending
    std::sort(result.begin(), result.end(),
        [](const ThreadInfo& a, const ThreadInfo& b) { return a.riskScore > b.riskScore; });
    return result;
}

// ============================================================================
// Summaries
// ============================================================================
ProcessThreadSummary ThreadDatabase::getProcessSummary(DWORD pid) const {
    std::shared_lock lock(mutex_);
    ProcessThreadSummary summary;
    summary.pid = pid;

    for (const auto& [tid, info] : threads_) {
        if (info.ownerPid != pid) continue;

        if (summary.imageName.empty())
            summary.imageName = info.ownerImageName;

        summary.totalThreads++;

        if (info.riskLevel != ThreadRiskLevel::None)
            summary.suspiciousThreads++;
        if (info.isSuspended)
            summary.suspendedThreads++;
        if (info.startAddressResolved && !info.startInLoadedModule)
            summary.unresolvedThreads++;

        if (static_cast<int>(info.riskLevel) > static_cast<int>(summary.highestRisk))
            summary.highestRisk = info.riskLevel;
    }

    return summary;
}

std::vector<ProcessThreadSummary> ThreadDatabase::getAllProcessSummaries() const {
    std::shared_lock lock(mutex_);

    // Group by PID
    std::map<DWORD, ProcessThreadSummary> byPid;
    for (const auto& [tid, info] : threads_) {
        auto& summary = byPid[info.ownerPid];
        summary.pid = info.ownerPid;
        if (summary.imageName.empty())
            summary.imageName = info.ownerImageName;

        summary.totalThreads++;
        if (info.riskLevel != ThreadRiskLevel::None) summary.suspiciousThreads++;
        if (info.isSuspended) summary.suspendedThreads++;
        if (info.startAddressResolved && !info.startInLoadedModule) summary.unresolvedThreads++;
        if (static_cast<int>(info.riskLevel) > static_cast<int>(summary.highestRisk))
            summary.highestRisk = info.riskLevel;
    }

    std::vector<ProcessThreadSummary> result;
    for (auto& [pid, summary] : byPid) {
        result.push_back(std::move(summary));
    }
    // Sort by suspicious count descending
    std::sort(result.begin(), result.end(),
        [](const ProcessThreadSummary& a, const ProcessThreadSummary& b) {
            return a.suspiciousThreads > b.suspiciousThreads;
        });
    return result;
}

// ============================================================================
// Statistics
// ============================================================================
size_t ThreadDatabase::activeCount() const {
    std::shared_lock lock(mutex_);
    return threads_.size();
}

size_t ThreadDatabase::totalObserved() const {
    std::shared_lock lock(mutex_);
    return totalObserved_;
}

size_t ThreadDatabase::suspiciousCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [tid, info] : threads_) {
        if (info.riskLevel != ThreadRiskLevel::None) count++;
    }
    return count;
}

const std::vector<ThreadEvent>& ThreadDatabase::recentEvents() const {
    // Note: caller should hold read lock or be aware of potential races
    return recentEvents_;
}

// ============================================================================
// Display functions
// ============================================================================
void ThreadDatabase::displayThreadsForProcess(DWORD pid) const {
    std::shared_lock lock(mutex_);
    auto threads = getByOwnerPid(pid);

    std::cout << "\n=== Thread Database: PID " << pid << " ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;
    printf("  %-8s %-8s %-18s %-6s %-14s %-20s %s\n",
        "TID", "PID", "Start Address", "Prio", "State", "Module", "Risk");
    std::cout << std::string(110, '-') << std::endl;

    for (const auto& t : threads) {
        t.displayCompact();
    }
    std::cout << "\n  Total: " << threads.size() << " threads" << std::endl;
}

void ThreadDatabase::displaySuspiciousThreads() const {
    auto suspicious = getSuspicious();

    std::cout << "\n=== Suspicious Threads ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    if (suspicious.empty()) {
        std::cout << "  [+] No suspicious threads detected." << std::endl;
        return;
    }

    std::cout << "  [!] " << suspicious.size() << " suspicious thread(s):" << std::endl << std::endl;
    for (const auto& t : suspicious) {
        t.display();
        std::cout << std::endl;
    }
}

void ThreadDatabase::displayProcessSummaries() const {
    auto summaries = getAllProcessSummaries();

    std::cout << "\n=== Thread Summary by Process ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;
    printf("  %-8s %-6s %-6s %-6s %-6s %-10s %s\n",
        "PID", "Thds", "Susp", "Suspd", "Unres", "Risk", "Image");
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& s : summaries) {
        printf("  %-8u %-6u %-6u %-6u %-6u %-10s %ls\n",
            s.pid, s.totalThreads, s.suspiciousThreads,
            s.suspendedThreads, s.unresolvedThreads,
            threadRiskToString(s.highestRisk),
            s.imageName.c_str());
    }
    std::cout << "\n  Total: " << summaries.size() << " processes, "
              << activeCount() << " threads" << std::endl;
}

void ThreadDatabase::displayRecentEvents(int maxEvents) const {
    std::shared_lock lock(mutex_);

    std::cout << "\n=== Recent Thread Events ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    if (recentEvents_.empty()) {
        std::cout << "  (no events since monitoring started)" << std::endl;
        return;
    }

    int start = (int)recentEvents_.size() - maxEvents;
    if (start < 0) start = 0;

    for (int i = start; i < (int)recentEvents_.size(); i++) {
        const auto& evt = recentEvents_[i];
        const char* typeStr = "";
        switch (evt.type) {
            case ThreadEventType::Created:    typeStr = "[+] CREATED"; break;
            case ThreadEventType::Terminated: typeStr = "[-] TERMINATED"; break;
            case ThreadEventType::Updated:    typeStr = "[~] UPDATED"; break;
        }
        printf("  %s TID %u in PID %u (%ls)",
            typeStr, evt.threadId, evt.ownerPid,
            evt.ownerImageName.c_str());
        if (evt.riskLevel != ThreadRiskLevel::None)
            printf(" [%s]", threadRiskToString(evt.riskLevel));
        printf("\n");
    }
}

} // namespace thread_intelligence
} // namespace zerophase
