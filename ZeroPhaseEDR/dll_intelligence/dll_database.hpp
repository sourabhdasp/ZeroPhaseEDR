#pragma once
/*
 * ZeroPhase EDR - DLL Intelligence: DLL Database
 *
 * Thread-safe database tracking loaded DLLs per process.
 * Detects new DLL loads, unloads, and suspicious modules.
 */

#ifndef ZEROPHASE_DLL_DATABASE_HPP
#define ZEROPHASE_DLL_DATABASE_HPP

#include "dll_info.hpp"

namespace zerophase {
namespace dll_intelligence {

// ============================================================================
// DLL lifecycle event
// ============================================================================
enum class DllEventType {
    Loaded,
    Unloaded,
};

struct DllEvent {
    DllEventType type;
    DWORD  pid;
    std::wstring ownerImageName;
    std::wstring moduleName;
    std::wstring fullPath;
    PVOID  baseAddress;
    DllRiskLevel riskLevel;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// DLL Database
// ============================================================================
class DllDatabase {
public:
    DllDatabase() = default;

    // Scan a process and diff
    std::vector<DllEvent> updateProcess(DWORD pid, bool verifySignatures = false);

    // Lookups
    std::vector<DllInfo> getDllsForProcess(DWORD pid) const;
    std::vector<DllInfo> getSuspiciousDlls() const;
    std::vector<DllInfo> getUnsignedDlls() const;

    // Summary
    ProcessDllSummary getProcessSummary(DWORD pid) const;

    // Statistics
    size_t trackedProcesses() const;
    size_t totalDlls() const;
    size_t suspiciousDlls() const;

    // Events
    const std::vector<DllEvent>& recentEvents() const;

    // Display
    void displayProcessDlls(DWORD pid) const;
    void displaySuspicious() const;
    void displayUnsigned() const;
    void displayRecentEvents(int maxEvents = 50) const;

private:
    mutable std::shared_mutex mutex_;
    // Key: PID, Value: map of base address -> DllInfo
    std::unordered_map<DWORD, std::unordered_map<ULONG_PTR, DllInfo>> processDlls_;
    std::vector<DllEvent> recentEvents_;
    int updateCount_ = 0;
};

} // namespace dll_intelligence
} // namespace zerophase

#endif // ZEROPHASE_DLL_DATABASE_HPP
