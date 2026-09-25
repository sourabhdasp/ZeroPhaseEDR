#pragma once
/*
 * ZeroPhase EDR - Thread Intelligence: Thread Info
 *
 * Rich thread information structure that extends basic enumeration
 * with start address resolution, module mapping, suspicious indicators,
 * and behavioral analysis for injection detection.
 */

#ifndef ZEROPHASE_THREAD_INFO_HPP
#define ZEROPHASE_THREAD_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Thread risk assessment
// ============================================================================
enum class ThreadRiskLevel : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* threadRiskToString(ThreadRiskLevel level) {
    switch (level) {
        case ThreadRiskLevel::None:     return "NONE";
        case ThreadRiskLevel::Low:      return "LOW";
        case ThreadRiskLevel::Medium:   return "MEDIUM";
        case ThreadRiskLevel::High:     return "HIGH";
        case ThreadRiskLevel::Critical: return "CRITICAL";
        default:                        return "UNKNOWN";
    }
}

// ============================================================================
// Thread state names (from KTHREAD_STATE)
// ============================================================================
inline const char* threadStateToString(ULONG state) {
    static const char* names[] = {
        "Initialized", "Ready", "Running", "Standby",
        "Terminated", "Waiting", "Transition", "DeferredReady",
        "GateWaitObsolete"
    };
    return (state < 9) ? names[state] : "Unknown";
}

// ============================================================================
// Wait reason names
// ============================================================================
inline const char* waitReasonToString(ULONG reason) {
    static const char* names[] = {
        "Executive", "FreePage", "PageIn", "PoolAllocation",
        "DelayExecution", "Suspended", "UserRequest", "WrExecutive",
        "WrFreePage", "WrPageIn", "WrPoolAllocation", "WrDelayExecution",
        "WrSuspended", "WrUserRequest", "WrEventPair", "WrQueue",
        "WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut",
        "WrRendezvous", "WrKeyedEvent", "WrTerminated", "WrProcessInSwap",
        "WrCpuRateControl", "WrCalloutStack", "WrKernel", "WrResource",
        "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt",
        "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex",
        "WrRundown", "WrAlertByThreadId", "WrDeferredPreempt"
    };
    return (reason < 39) ? names[reason] : "Unknown";
}

// ============================================================================
// Module range for address resolution
// ============================================================================
struct ModuleRange {
    PVOID        baseAddress = nullptr;
    SIZE_T       size        = 0;
    std::wstring moduleName;
    std::wstring modulePath;
};

// ============================================================================
// Rich thread information
// ============================================================================
struct ThreadInfo {
    // Identity
    DWORD  threadId          = 0;
    DWORD  ownerPid          = 0;
    std::wstring ownerImageName;

    // Execution state
    ULONG  threadState       = 0;   // KTHREAD_STATE
    ULONG  waitReason        = 0;
    LONG   priority          = 0;
    LONG   basePriority      = 0;
    ULONG  contextSwitches   = 0;
    ULONG  waitTime          = 0;

    // Timing
    LARGE_INTEGER createTime  = {};
    LARGE_INTEGER kernelTime  = {};
    LARGE_INTEGER userTime    = {};
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastUpdated;

    // Start address analysis
    PVOID  kernelStartAddress = nullptr;  // From SYSTEM_THREAD_INFORMATION
    PVOID  win32StartAddress  = nullptr;  // From NtQueryInformationThread
    std::wstring startModule;             // Module containing start address
    bool   startAddressResolved = false;
    bool   startInLoadedModule  = false;

    // Memory context of start address
    DWORD  startMemoryProtect = 0;
    DWORD  startMemoryType    = 0;    // MEM_IMAGE, MEM_PRIVATE, etc.

    // Risk assessment
    ThreadRiskLevel riskLevel = ThreadRiskLevel::None;
    int    riskScore          = 0;    // 0-100
    std::vector<std::string> riskReasons;

    // State tracking
    bool   isAlive            = true;
    bool   isNew              = false;
    bool   isSuspended        = false;

    // Display
    void display() const {
        printf("  TID: %-8u  PID: %-8u  %ls\n", threadId, ownerPid, ownerImageName.c_str());
        printf("    Start:      0x%016llX", (ULONGLONG)win32StartAddress);
        if (startAddressResolved)
            printf("  -> %ls", startModule.c_str());
        else
            printf("  -> <unresolved>");
        printf("\n");
        printf("    State:      %-14s  Priority: %d/%d\n",
            threadStateToString(threadState), priority, basePriority);
        printf("    CtxSwitch:  %u  WaitTime: %u\n", contextSwitches, waitTime);

        if (startMemoryType != 0) {
            printf("    MemType:    %s  Protect: %s\n",
                native::memoryTypeToString(startMemoryType).c_str(),
                native::protectionToString(startMemoryProtect).c_str());
        }

        if (riskLevel != ThreadRiskLevel::None) {
            printf("    [!] Risk:   %s (score: %d)\n", threadRiskToString(riskLevel), riskScore);
            for (const auto& reason : riskReasons)
                printf("        - %s\n", reason.c_str());
        }
    }

    void displayCompact() const {
        printf("  %-8u %-8u 0x%016llX %-6d %-14s %-20ls %s%s\n",
            threadId, ownerPid,
            (ULONGLONG)win32StartAddress,
            priority,
            threadStateToString(threadState),
            startModule.empty() ? L"<unknown>" : startModule.c_str(),
            riskLevel != ThreadRiskLevel::None ? "[!" : "",
            riskLevel != ThreadRiskLevel::None ?
                (std::string(threadRiskToString(riskLevel)) + "]").c_str() : "");
    }
};

// ============================================================================
// Free functions — declared here, defined in thread_info.cpp
// ============================================================================

// Get the Win32 start address of a thread
PVOID getThreadWin32StartAddress(DWORD threadId);

// Get loaded modules for a process (for address resolution)
std::vector<ModuleRange> getProcessModuleRanges(DWORD pid);

// Resolve which module contains an address
std::wstring resolveAddressToModule(PVOID address, const std::vector<ModuleRange>& modules);

// Query the memory protection/type at a given address in a process
bool queryAddressMemoryInfo(DWORD pid, PVOID address, DWORD& outProtect, DWORD& outType);

// Build a ThreadInfo from system thread data + enrichment
ThreadInfo buildThreadInfo(
    DWORD threadId, DWORD ownerPid,
    const native::SYSTEM_THREAD_INFORMATION_EX* sysThread,
    const std::vector<ModuleRange>& ownerModules,
    const std::wstring& ownerImageName);

// Perform risk analysis on a thread
void analyzeThreadRisk(ThreadInfo& thread);

// Snapshot all threads for a specific process
std::vector<ThreadInfo> snapshotProcessThreads(DWORD pid);

// Snapshot all threads system-wide
std::vector<ThreadInfo> snapshotAllThreads();

} // namespace thread_intelligence
} // namespace zerophase

#endif // ZEROPHASE_THREAD_INFO_HPP
