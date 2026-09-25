/*
 * ZeroPhase EDR - Process Intelligence: Process Database Implementation
 *
 * Maintains a live database of processes, detects new/terminated processes
 * on each update cycle, and tracks parent-child relationships.
 */

#include "process_database.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Update: Snapshot system and diff against known state
// ============================================================================
std::vector<ProcessEvent> ProcessDatabase::update() {
    auto snapshot = snapshotAllProcesses();
    std::vector<ProcessEvent> events;
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);
    updateCount_++;

    // Build set of currently running PIDs
    std::set<DWORD> currentPids;
    for (const auto& proc : snapshot) {
        currentPids.insert(proc.pid);
    }

    // Detect new processes and update existing ones
    for (auto& proc : snapshot) {
        auto it = processes_.find(proc.pid);
        if (it == processes_.end()) {
            // New process
            proc.isNew = (updateCount_ > 1); // Don't flag initial scan as "new"
            processes_[proc.pid] = proc;
            totalObserved_++;

            if (proc.isNew) {
                ProcessEvent evt;
                evt.type = ProcessEventType::Created;
                evt.pid = proc.pid;
                evt.parentPid = proc.parentPid;
                evt.imageName = proc.imageName;
                evt.timestamp = now;
                events.push_back(evt);
            }
        } else {
            // Update existing
            auto& existing = it->second;
            existing.threadCount = proc.threadCount;
            existing.handleCount = proc.handleCount;
            existing.workingSetSize = proc.workingSetSize;
            existing.privateBytes = proc.privateBytes;
            existing.virtualSize = proc.virtualSize;
            existing.cycleTime = proc.cycleTime;
            existing.userTime = proc.userTime;
            existing.kernelTime = proc.kernelTime;
            existing.lastUpdated = now;
            existing.isNew = false;

            size_t newHash = existing.computeStateHash();
            if (newHash != existing.lastStateHash) {
                existing.lastStateHash = newHash;
                // Could emit an Updated event here for significant changes
            }
        }
    }

    // Detect terminated processes
    std::vector<DWORD> gonePids;
    for (const auto& [pid, info] : processes_) {
        if (currentPids.find(pid) == currentPids.end()) {
            gonePids.push_back(pid);

            ProcessEvent evt;
            evt.type = ProcessEventType::Terminated;
            evt.pid = pid;
            evt.parentPid = info.parentPid;
            evt.imageName = info.imageName;
            evt.timestamp = now;
            events.push_back(evt);
        }
    }

    // Move terminated processes to terminated_ map
    for (DWORD pid : gonePids) {
        auto it = processes_.find(pid);
        if (it != processes_.end()) {
            it->second.isAlive = false;
            terminated_[pid] = std::move(it->second);
            processes_.erase(it);
        }
    }

    // Build child PID lists
    for (auto& [pid, info] : processes_) {
        info.childPids.clear();
    }
    for (const auto& [pid, info] : processes_) {
        auto parentIt = processes_.find(info.parentPid);
        if (parentIt != processes_.end()) {
            parentIt->second.childPids.push_back(pid);
        }
    }

    // Keep only recent events (last 1000)
    recentEvents_.insert(recentEvents_.end(), events.begin(), events.end());
    if (recentEvents_.size() > 1000) {
        recentEvents_.erase(recentEvents_.begin(),
            recentEvents_.begin() + (recentEvents_.size() - 1000));
    }

    return events;
}

// ============================================================================
// Lookups
// ============================================================================
std::optional<ProcessInfo> ProcessDatabase::getByPid(DWORD pid) const {
    std::shared_lock lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) return it->second;
    return std::nullopt;
}

std::vector<ProcessInfo> ProcessDatabase::getAll() const {
    std::shared_lock lock(mutex_);
    std::vector<ProcessInfo> result;
    result.reserve(processes_.size());
    for (const auto& [pid, info] : processes_) {
        result.push_back(info);
    }
    return result;
}

std::vector<ProcessInfo> ProcessDatabase::getByParentPid(DWORD parentPid) const {
    std::shared_lock lock(mutex_);
    std::vector<ProcessInfo> result;
    for (const auto& [pid, info] : processes_) {
        if (info.parentPid == parentPid) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<ProcessInfo> ProcessDatabase::getByName(const std::wstring& name) const {
    std::shared_lock lock(mutex_);
    std::vector<ProcessInfo> result;
    // Case-insensitive match
    std::wstring lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    for (const auto& [pid, info] : processes_) {
        std::wstring lowerImage = info.imageName;
        std::transform(lowerImage.begin(), lowerImage.end(), lowerImage.begin(), ::towlower);
        if (lowerImage.find(lowerName) != std::wstring::npos) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<DWORD> ProcessDatabase::getChildPids(DWORD parentPid) const {
    std::shared_lock lock(mutex_);
    auto it = processes_.find(parentPid);
    if (it != processes_.end()) return it->second.childPids;
    return {};
}

size_t ProcessDatabase::activeCount() const {
    std::shared_lock lock(mutex_);
    return processes_.size();
}

size_t ProcessDatabase::totalObserved() const {
    std::shared_lock lock(mutex_);
    return totalObserved_;
}

// ============================================================================
// Display functions
// ============================================================================
void ProcessDatabase::displayDatabase() const {
    std::shared_lock lock(mutex_);
    std::cout << "\n=== Process Database ===" << std::endl;
    std::cout << "  Active: " << processes_.size()
              << "  Terminated: " << terminated_.size()
              << "  Total observed: " << totalObserved_
              << "  Updates: " << updateCount_ << std::endl;
    std::cout << std::string(120, '-') << std::endl;

    printf("  %-8s %-8s %-6s %-6s %-4s %-10s %-8s %-5s %s\n",
        "PID", "PPID", "Thds", "Hndls", "Sess", "Integrity", "Elevated", "WoW64", "Image");
    std::cout << std::string(120, '-') << std::endl;

    // Sort by PID for display
    std::vector<const ProcessInfo*> sorted;
    for (const auto& [pid, info] : processes_) {
        sorted.push_back(&info);
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const ProcessInfo* a, const ProcessInfo* b) { return a->pid < b->pid; });

    for (const auto* p : sorted) {
        printf("  %-8u %-8u %-6u %-6u %-4u %-10s %-8s %-5s %ls%s\n",
            p->pid, p->parentPid, p->threadCount, p->handleCount,
            p->sessionId, p->integrityLevel.c_str(),
            p->isElevated ? "YES" : "No",
            p->isWow64 ? "YES" : "No",
            p->imageName.c_str(),
            p->isNew ? " [NEW]" : "");
    }
}

void ProcessDatabase::displayNew() const {
    std::shared_lock lock(mutex_);
    std::cout << "\n=== Recently Created Processes ===" << std::endl;
    int count = 0;
    for (const auto& evt : recentEvents_) {
        if (evt.type == ProcessEventType::Created) {
            std::cout << "  [+] PID " << evt.pid << " (PPID " << evt.parentPid
                      << ") " << native::wstringToString(evt.imageName) << std::endl;
            count++;
        }
    }
    if (count == 0) std::cout << "  (none since monitoring started)" << std::endl;
}

void ProcessDatabase::displayTerminated() const {
    std::shared_lock lock(mutex_);
    std::cout << "\n=== Recently Terminated Processes ===" << std::endl;
    int count = 0;
    for (const auto& evt : recentEvents_) {
        if (evt.type == ProcessEventType::Terminated) {
            std::cout << "  [-] PID " << evt.pid << " "
                      << native::wstringToString(evt.imageName) << std::endl;
            count++;
        }
    }
    if (count == 0) std::cout << "  (none since monitoring started)" << std::endl;
}

} // namespace process_intelligence
} // namespace zerophase
