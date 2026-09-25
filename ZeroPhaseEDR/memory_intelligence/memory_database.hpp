#pragma once
/*
 * ZeroPhase EDR - Memory Intelligence: Memory Database
 *
 * Thread-safe database tracking memory regions per process.
 * Detects new executable regions, protection changes, and
 * content modifications across scan cycles.
 */

#ifndef ZEROPHASE_MEMORY_DATABASE_HPP
#define ZEROPHASE_MEMORY_DATABASE_HPP

#include "entropy_analysis.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Memory change event
// ============================================================================
enum class MemoryEventType {
    NewRegion,           // New executable/suspicious region appeared
    RegionFreed,         // Region was freed
    ProtectionChanged,   // Protection was modified (e.g. RW -> RWX)
    ContentChanged,      // Content hash changed in existing region
};

struct MemoryEvent {
    MemoryEventType type;
    DWORD  pid;
    PVOID  baseAddress;
    SIZE_T regionSize;
    DWORD  oldProtect;
    DWORD  newProtect;
    MemoryRiskLevel riskLevel;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Memory Database
// ============================================================================
class MemoryDatabase {
public:
    MemoryDatabase() = default;

    // Scan a process and diff against known state
    std::vector<MemoryEvent> updateProcess(DWORD pid, bool deepScan = false);

    // Lookups
    std::vector<MemoryRegionInfo> getRegionsForProcess(DWORD pid) const;
    std::vector<MemoryRegionInfo> getSuspiciousRegions() const;
    std::vector<MemoryRegionInfo> getExecutablePrivateRegions() const;

    // Summaries
    ProcessMemorySummary getProcessSummary(DWORD pid) const;

    // Statistics
    size_t trackedProcessCount() const;
    size_t totalRegionCount() const;
    size_t suspiciousRegionCount() const;

    // Events
    const std::vector<MemoryEvent>& recentEvents() const;

    // Display
    void displayProcessMemory(DWORD pid) const;
    void displaySuspicious() const;
    void displayRecentEvents(int maxEvents = 50) const;

private:
    mutable std::shared_mutex mutex_;

    // Key: PID, Value: map of base address -> MemoryRegionInfo
    std::unordered_map<DWORD, std::unordered_map<ULONG_PTR, MemoryRegionInfo>> processRegions_;

    std::vector<MemoryEvent> recentEvents_;
    int updateCount_ = 0;
};

} // namespace memory_intelligence
} // namespace zerophase

#endif // ZEROPHASE_MEMORY_DATABASE_HPP
