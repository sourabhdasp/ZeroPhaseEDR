#pragma once
/*
 * ZeroPhase EDR - Injection Intelligence: Injection Info
 *
 * Detects code injection techniques from user-mode by correlating
 * multiple signals across process, thread, and memory telemetry:
 *
 * Techniques detected:
 * - Classic DLL Injection (CreateRemoteThread + LoadLibrary)
 * - Process Hollowing (CREATE_SUSPENDED + WriteProcessMemory + ResumeThread)
 * - APC Injection (QueueUserAPC)
 * - Thread Hijacking (SuspendThread + SetThreadContext)
 * - Reflective DLL Loading (PE in private memory)
 * - Module Stomping (legitimate DLL overwritten with malicious code)
 * - Phantom DLL Hollowing (DLL on disk != DLL in memory)
 */

#ifndef ZEROPHASE_INJECTION_INFO_HPP
#define ZEROPHASE_INJECTION_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace injection_intelligence {

// ============================================================================
// Injection technique type
// ============================================================================
enum class InjectionType : int {
    Unknown              = 0,
    RemoteThreadDll      = 1,   // CreateRemoteThread targeting LoadLibrary
    RemoteThreadShell    = 2,   // CreateRemoteThread with shellcode
    ProcessHollowing     = 3,   // Hollowed process image
    ReflectiveDllLoad    = 4,   // PE header in private memory
    ApcInjection         = 5,   // Thread with APC-queued start
    ThreadHijack         = 6,   // Existing thread redirected
    ModuleStomping       = 7,   // Legitimate DLL overwritten in memory
    AtomBombing          = 8,   // GlobalGetAtomName abuse
    EarlyBirdInjection   = 9,   // Injection before main thread runs
    PhantomDllHollow     = 10,  // On-disk DLL differs from in-memory
};

inline const char* injectionTypeToString(InjectionType type) {
    switch (type) {
        case InjectionType::RemoteThreadDll:    return "Remote Thread (DLL)";
        case InjectionType::RemoteThreadShell:  return "Remote Thread (Shellcode)";
        case InjectionType::ProcessHollowing:   return "Process Hollowing";
        case InjectionType::ReflectiveDllLoad:  return "Reflective DLL Load";
        case InjectionType::ApcInjection:       return "APC Injection";
        case InjectionType::ThreadHijack:       return "Thread Hijack";
        case InjectionType::ModuleStomping:     return "Module Stomping";
        case InjectionType::AtomBombing:        return "Atom Bombing";
        case InjectionType::EarlyBirdInjection: return "Early Bird Injection";
        case InjectionType::PhantomDllHollow:   return "Phantom DLL Hollowing";
        default:                                return "Unknown";
    }
}

// ============================================================================
// Injection risk level
// ============================================================================
enum class InjectionRisk : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* injectionRiskToString(InjectionRisk level) {
    switch (level) {
        case InjectionRisk::None:     return "NONE";
        case InjectionRisk::Low:      return "LOW";
        case InjectionRisk::Medium:   return "MEDIUM";
        case InjectionRisk::High:     return "HIGH";
        case InjectionRisk::Critical: return "CRITICAL";
        default:                      return "UNKNOWN";
    }
}

// ============================================================================
// Injection finding
// ============================================================================
struct InjectionFinding {
    // Target process
    DWORD  targetPid          = 0;
    std::wstring targetImageName;

    // Injection details
    InjectionType type        = InjectionType::Unknown;
    InjectionRisk riskLevel   = InjectionRisk::None;
    int    confidenceScore    = 0;   // 0-100, how confident we are

    // Evidence
    PVOID  suspiciousAddress  = nullptr;
    SIZE_T regionSize         = 0;
    DWORD  memoryProtect      = 0;
    DWORD  memoryType         = 0;
    DWORD  suspiciousThreadId = 0;

    // Description
    std::string description;
    std::vector<std::string> evidence;
    std::string mitreId;       // MITRE ATT&CK technique

    // Timing
    std::chrono::system_clock::time_point detectedAt;

    void display() const {
        printf("\n  [%s] %s in PID %u (%ls)\n",
            injectionRiskToString(riskLevel),
            injectionTypeToString(type),
            targetPid, targetImageName.c_str());
        printf("    MITRE:      %s\n", mitreId.c_str());
        printf("    Confidence: %d%%\n", confidenceScore);
        if (suspiciousAddress)
            printf("    Address:    0x%016llX  Size: %s  Prot: %s  Type: %s\n",
                (ULONGLONG)suspiciousAddress,
                native::formatSize(regionSize).c_str(),
                native::protectionToString(memoryProtect).c_str(),
                native::memoryTypeToString(memoryType).c_str());
        if (suspiciousThreadId)
            printf("    Thread:     TID %u\n", suspiciousThreadId);
        printf("    %s\n", description.c_str());
        if (!evidence.empty()) {
            printf("    Evidence:\n");
            for (const auto& e : evidence)
                printf("      - %s\n", e.c_str());
        }
    }
};

// ============================================================================
// Per-process injection scan result
// ============================================================================
struct ProcessInjectionResult {
    DWORD  pid                = 0;
    std::wstring imageName;
    std::vector<InjectionFinding> findings;
    InjectionRisk highestRisk = InjectionRisk::None;
    bool   scanned            = false;
    std::chrono::system_clock::time_point scanTime;
};

} // namespace injection_intelligence
} // namespace zerophase

#endif // ZEROPHASE_INJECTION_INFO_HPP
