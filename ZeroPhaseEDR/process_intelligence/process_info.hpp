#pragma once
/*
 * ZeroPhase EDR - Process Intelligence: Process Info
 *
 * Rich process information structure that extends basic enumeration
 * with security context, risk scoring, and behavioral indicators.
 */

#ifndef ZEROPHASE_PROCESS_INFO_HPP
#define ZEROPHASE_PROCESS_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Risk level for process evaluation
// ============================================================================
enum class RiskLevel : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* riskLevelToString(RiskLevel level) {
    switch (level) {
        case RiskLevel::None:     return "NONE";
        case RiskLevel::Low:      return "LOW";
        case RiskLevel::Medium:   return "MEDIUM";
        case RiskLevel::High:     return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
        default:                  return "UNKNOWN";
    }
}

// ============================================================================
// Process creation source type
// ============================================================================
enum class ProcessSource : int {
    Unknown         = 0,
    SystemBoot      = 1,  // Created during boot (smss, csrss, etc.)
    ServiceManager  = 2,  // Started by services.exe
    Explorer        = 3,  // User launched via shell
    CommandLine     = 4,  // From cmd.exe or powershell.exe
    Scheduled       = 5,  // Scheduled task
    RemoteService   = 6,  // Remote service (WMI, PSRemoting, etc.)
    ParentSpawn     = 7,  // Child of another monitored process
};

// ============================================================================
// Rich process information
// ============================================================================
struct ProcessInfo {
    // Identity
    DWORD  pid              = 0;
    DWORD  parentPid        = 0;
    DWORD  sessionId        = 0;
    std::wstring imageName;
    std::wstring imagePathFull;
    std::wstring commandLine;

    // Timing
    LARGE_INTEGER createTime  = {};
    LARGE_INTEGER userTime    = {};
    LARGE_INTEGER kernelTime  = {};
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastUpdated;

    // Resource metrics
    DWORD  threadCount       = 0;
    DWORD  handleCount       = 0;
    LONG   basePriority      = 0;
    SIZE_T workingSetSize    = 0;
    SIZE_T privateBytes      = 0;
    SIZE_T virtualSize       = 0;
    ULONGLONG cycleTime      = 0;

    // Security context
    std::string integrityLevel;   // "System", "High", "Medium", "Low", "Untrusted"
    bool   isElevated        = false;
    bool   isProtected       = false;
    bool   isWow64           = false;         // 32-bit on 64-bit
    bool   beingDebugged     = false;

    // Lineage
    std::wstring parentImageName;
    std::wstring parentCommandLine;
    std::vector<DWORD> childPids;

    // Intelligence
    ProcessSource source     = ProcessSource::Unknown;
    RiskLevel     riskLevel  = RiskLevel::None;
    int           riskScore  = 0;  // 0-100
    std::vector<std::string> riskReasons;
    std::vector<std::string> tags;        // e.g., "browser", "system", "tool"

    // State tracking
    bool   isAlive           = true;
    bool   isNew             = false;       // Just appeared in this scan
    DWORD  exitCode          = 0;

    // Hash for change detection
    size_t lastStateHash     = 0;

    // Compute a state hash for change detection
    size_t computeStateHash() const {
        size_t h = 0;
        h ^= std::hash<DWORD>{}(threadCount) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<DWORD>{}(handleCount) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<SIZE_T>{}(workingSetSize) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<SIZE_T>{}(privateBytes) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<bool>{}(isAlive) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    // Display this process info
    void display() const {
        printf("  PID: %-8u  PPID: %-8u  %ls\n", pid, parentPid, imageName.c_str());
        if (!imagePathFull.empty())
            std::cout << "    Path:       " << native::wstringToString(imagePathFull) << std::endl;
        if (!commandLine.empty())
            std::cout << "    CmdLine:    " << native::wstringToString(commandLine) << std::endl;
        std::cout << "    Session:    " << sessionId
                  << "  Threads: " << threadCount
                  << "  Handles: " << handleCount << std::endl;
        std::cout << "    Integrity:  " << integrityLevel
                  << "  Elevated: " << (isElevated ? "YES" : "No")
                  << "  WoW64: " << (isWow64 ? "YES" : "No") << std::endl;
        std::cout << "    WorkSet:    " << native::formatSize(workingSetSize)
                  << "  Private: " << native::formatSize(privateBytes) << std::endl;
        if (riskLevel != RiskLevel::None) {
            std::cout << "    [!] Risk:   " << riskLevelToString(riskLevel)
                      << " (score: " << riskScore << ")" << std::endl;
            for (const auto& reason : riskReasons)
                std::cout << "        - " << reason << std::endl;
        }
        if (!tags.empty()) {
            std::cout << "    Tags:       ";
            for (size_t i = 0; i < tags.size(); i++) {
                if (i > 0) std::cout << ", ";
                std::cout << tags[i];
            }
            std::cout << std::endl;
        }
    }
};

// ============================================================================
// Free functions declared here, defined in process_info.cpp
// ============================================================================

// Build a ProcessInfo from a SYSTEM_PROCESS_INFORMATION_EX record + live queries
ProcessInfo buildProcessInfo(DWORD pid, const native::SYSTEM_PROCESS_INFORMATION_EX* sysProc);

// Snapshot all processes on the system
std::vector<ProcessInfo> snapshotAllProcesses();

} // namespace process_intelligence
} // namespace zerophase

#endif // ZEROPHASE_PROCESS_INFO_HPP
