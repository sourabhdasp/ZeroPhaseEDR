/*
 * ZeroPhase EDR - Memory Intelligence: Memory Database Implementation
 *
 * Tracks memory regions per process, detects changes in protection,
 * new executable allocations, and content modifications.
 */

#include "memory_database.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Update: scan a process and diff against known state
// ============================================================================
std::vector<MemoryEvent> MemoryDatabase::updateProcess(DWORD pid, bool deepScan) {
    auto snapshot = enumerateProcessMemory(pid, deepScan);
    std::vector<MemoryEvent> events;
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);
    updateCount_++;

    auto& regions = processRegions_[pid];

    // Build set of current base addresses
    std::set<ULONG_PTR> currentAddrs;
    for (const auto& r : snapshot) {
        currentAddrs.insert(reinterpret_cast<ULONG_PTR>(r.baseAddress));
    }

    // Detect new regions and changes
    for (auto& r : snapshot) {
        ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(r.baseAddress);
        auto it = regions.find(addr);

        if (it == regions.end()) {
            // New region
            if (updateCount_ > 1 && r.riskLevel != MemoryRiskLevel::None) {
                MemoryEvent evt;
                evt.type = MemoryEventType::NewRegion;
                evt.pid = pid;
                evt.baseAddress = r.baseAddress;
                evt.regionSize = r.regionSize;
                evt.newProtect = r.currentProtect;
                evt.oldProtect = 0;
                evt.riskLevel = r.riskLevel;
                evt.description = "New suspicious memory region detected";
                evt.timestamp = now;
                events.push_back(evt);
            }
            regions[addr] = r;
        } else {
            auto& existing = it->second;

            // Check for protection change
            if (existing.currentProtect != r.currentProtect) {
                DWORD oldBase = existing.currentProtect & 0xFF;
                DWORD newBase = r.currentProtect & 0xFF;
                bool oldExec = (oldBase == PAGE_EXECUTE || oldBase == PAGE_EXECUTE_READ ||
                               oldBase == PAGE_EXECUTE_READWRITE || oldBase == PAGE_EXECUTE_WRITECOPY);
                bool newExec = (newBase == PAGE_EXECUTE || newBase == PAGE_EXECUTE_READ ||
                               newBase == PAGE_EXECUTE_READWRITE || newBase == PAGE_EXECUTE_WRITECOPY);

                if (!oldExec && newExec) {
                    // Protection escalated to executable — very suspicious
                    MemoryEvent evt;
                    evt.type = MemoryEventType::ProtectionChanged;
                    evt.pid = pid;
                    evt.baseAddress = r.baseAddress;
                    evt.regionSize = r.regionSize;
                    evt.oldProtect = existing.currentProtect;
                    evt.newProtect = r.currentProtect;
                    evt.riskLevel = MemoryRiskLevel::High;
                    evt.description = "Memory protection escalated to executable ("
                        + native::protectionToString(existing.currentProtect) + " -> "
                        + native::protectionToString(r.currentProtect) + ")";
                    evt.timestamp = now;
                    events.push_back(evt);
                }
            }

            // Check for content change (if deep scan)
            if (deepScan && existing.contentHash != 0 && r.contentHash != 0 &&
                existing.contentHash != r.contentHash) {
                r.contentChanged = true;

                MemoryEvent evt;
                evt.type = MemoryEventType::ContentChanged;
                evt.pid = pid;
                evt.baseAddress = r.baseAddress;
                evt.regionSize = r.regionSize;
                evt.oldProtect = existing.currentProtect;
                evt.newProtect = r.currentProtect;
                evt.riskLevel = MemoryRiskLevel::Medium;
                evt.description = "Executable region content modified";
                evt.timestamp = now;
                events.push_back(evt);
            }

            // Update existing
            existing.currentProtect = r.currentProtect;
            existing.contentHash = r.contentHash;
            existing.riskLevel = r.riskLevel;
            existing.riskScore = r.riskScore;
            existing.riskReasons = r.riskReasons;
            existing.lastUpdated = now;
            existing.contentChanged = r.contentChanged;
        }
    }

    // Detect freed regions (only track interesting ones)
    std::vector<ULONG_PTR> freed;
    for (const auto& [addr, info] : regions) {
        if (currentAddrs.find(addr) == currentAddrs.end()) {
            freed.push_back(addr);
        }
    }
    for (ULONG_PTR addr : freed) {
        regions.erase(addr);
    }

    // Store events
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
std::vector<MemoryRegionInfo> MemoryDatabase::getRegionsForProcess(DWORD pid) const {
    std::shared_lock lock(mutex_);
    std::vector<MemoryRegionInfo> result;
    auto it = processRegions_.find(pid);
    if (it != processRegions_.end()) {
        for (const auto& [addr, info] : it->second) {
            result.push_back(info);
        }
        std::sort(result.begin(), result.end(),
            [](const MemoryRegionInfo& a, const MemoryRegionInfo& b) {
                return a.baseAddress < b.baseAddress;
            });
    }
    return result;
}

std::vector<MemoryRegionInfo> MemoryDatabase::getSuspiciousRegions() const {
    std::shared_lock lock(mutex_);
    std::vector<MemoryRegionInfo> result;
    for (const auto& [pid, regions] : processRegions_) {
        for (const auto& [addr, info] : regions) {
            if (info.riskLevel != MemoryRiskLevel::None) {
                result.push_back(info);
            }
        }
    }
    std::sort(result.begin(), result.end(),
        [](const MemoryRegionInfo& a, const MemoryRegionInfo& b) {
            return a.riskScore > b.riskScore;
        });
    return result;
}

std::vector<MemoryRegionInfo> MemoryDatabase::getExecutablePrivateRegions() const {
    std::shared_lock lock(mutex_);
    std::vector<MemoryRegionInfo> result;
    for (const auto& [pid, regions] : processRegions_) {
        for (const auto& [addr, info] : regions) {
            if (info.classification == MemoryClassification::PrivateExec) {
                result.push_back(info);
            }
        }
    }
    return result;
}

ProcessMemorySummary MemoryDatabase::getProcessSummary(DWORD pid) const {
    std::shared_lock lock(mutex_);
    auto regions = getRegionsForProcess(pid);
    return computeMemorySummary(pid, regions);
}

// ============================================================================
// Statistics
// ============================================================================
size_t MemoryDatabase::trackedProcessCount() const {
    std::shared_lock lock(mutex_);
    return processRegions_.size();
}

size_t MemoryDatabase::totalRegionCount() const {
    std::shared_lock lock(mutex_);
    size_t total = 0;
    for (const auto& [pid, regions] : processRegions_) {
        total += regions.size();
    }
    return total;
}

size_t MemoryDatabase::suspiciousRegionCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [pid, regions] : processRegions_) {
        for (const auto& [addr, info] : regions) {
            if (info.riskLevel != MemoryRiskLevel::None) count++;
        }
    }
    return count;
}

const std::vector<MemoryEvent>& MemoryDatabase::recentEvents() const {
    return recentEvents_;
}

// ============================================================================
// Display
// ============================================================================
void MemoryDatabase::displayProcessMemory(DWORD pid) const {
    auto regions = getRegionsForProcess(pid);

    std::cout << "\n=== Memory Intelligence: PID " << pid << " ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;
    printf("  %-18s %-10s %-8s %-8s %-14s %-8s %s\n",
        "Address", "Size", "Prot", "Type", "Class", "Risk", "Info");
    std::cout << std::string(110, '-') << std::endl;

    int suspicious = 0;
    for (const auto& r : regions) {
        const char* info = "";
        if (r.hasPEHeader) info = "[MZ]";
        else if (r.hasShellcodePatterns) info = "[SHELLCODE]";
        else if (r.contentChanged) info = "[MODIFIED]";

        printf("  0x%016llX %-10s %-8s %-8s %-14s %-8s %s\n",
            (ULONGLONG)r.baseAddress,
            native::formatSize(r.regionSize).c_str(),
            native::protectionToString(r.currentProtect).c_str(),
            native::memoryTypeToString(r.type).c_str(),
            classificationToString(r.classification),
            memoryRiskToString(r.riskLevel),
            info);

        if (r.riskLevel != MemoryRiskLevel::None) suspicious++;
    }

    auto summary = computeMemorySummary(pid, regions);
    std::cout << std::string(110, '-') << std::endl;
    std::cout << "  Committed: " << native::formatSize(summary.totalCommitted)
              << "  Executable: " << native::formatSize(summary.totalExecutable)
              << "  Private: " << native::formatSize(summary.totalPrivate) << std::endl;
    std::cout << "  Regions: " << summary.regionCount
              << "  Suspicious: " << suspicious;
    if (summary.rwxRegionCount > 0)
        std::cout << "  RWX: " << summary.rwxRegionCount;
    if (summary.peHeaderCount > 0)
        std::cout << "  PE Headers: " << summary.peHeaderCount;
    std::cout << std::endl;
}

void MemoryDatabase::displaySuspicious() const {
    auto suspicious = getSuspiciousRegions();

    std::cout << "\n=== Suspicious Memory Regions ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    if (suspicious.empty()) {
        std::cout << "  [+] No suspicious memory regions detected." << std::endl;
        return;
    }

    std::cout << "  [!] " << suspicious.size() << " suspicious region(s):" << std::endl << std::endl;
    for (const auto& r : suspicious) {
        printf("  PID: %u\n", r.ownerPid);
        r.display();
        std::cout << std::endl;
    }
}

void MemoryDatabase::displayRecentEvents(int maxEvents) const {
    std::shared_lock lock(mutex_);

    std::cout << "\n=== Recent Memory Events ===" << std::endl;
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
            case MemoryEventType::NewRegion:         typeStr = "[+] NEW"; break;
            case MemoryEventType::RegionFreed:       typeStr = "[-] FREED"; break;
            case MemoryEventType::ProtectionChanged: typeStr = "[~] PROT_CHANGE"; break;
            case MemoryEventType::ContentChanged:    typeStr = "[~] CONTENT_MOD"; break;
        }
        printf("  %s PID %u @ 0x%016llX (%s) [%s] %s\n",
            typeStr, evt.pid, (ULONGLONG)evt.baseAddress,
            native::formatSize(evt.regionSize).c_str(),
            memoryRiskToString(evt.riskLevel),
            evt.description.c_str());
    }
}

} // namespace memory_intelligence
} // namespace zerophase
