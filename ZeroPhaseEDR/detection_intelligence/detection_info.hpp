#pragma once
/*
 * ZeroPhase EDR - Detection Intelligence
 *
 * Correlation engine that combines findings from all intelligence
 * modules into unified detection events with kill-chain mapping.
 */

#ifndef ZEROPHASE_DETECTION_INFO_HPP
#define ZEROPHASE_DETECTION_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace detection_intelligence {

enum class DetectionSeverity : int { Info=0, Low=1, Medium=2, High=3, Critical=4 };

inline const char* severityToString(DetectionSeverity s) {
    switch(s) {
        case DetectionSeverity::Info: return "INFO"; case DetectionSeverity::Low: return "LOW";
        case DetectionSeverity::Medium: return "MEDIUM"; case DetectionSeverity::High: return "HIGH";
        case DetectionSeverity::Critical: return "CRITICAL"; default: return "?";
    }
}

enum class DetectionSource : int {
    Process=1, Thread=2, Memory=3, Dll=4, CmdLine=5, Injection=6, Syscall=7, Kernel=8
};

inline const char* sourceToString(DetectionSource s) {
    switch(s) {
        case DetectionSource::Process: return "Process"; case DetectionSource::Thread: return "Thread";
        case DetectionSource::Memory: return "Memory"; case DetectionSource::Dll: return "DLL";
        case DetectionSource::CmdLine: return "CmdLine"; case DetectionSource::Injection: return "Injection";
        case DetectionSource::Syscall: return "Syscall"; case DetectionSource::Kernel: return "Kernel";
        default: return "?";
    }
}

// Unified detection event
struct DetectionEvent {
    DWORD  id              = 0;
    DetectionSeverity severity = DetectionSeverity::Info;
    DetectionSource source  = DetectionSource::Process;
    DWORD  pid             = 0;
    std::wstring imageName;
    std::string  title;
    std::string  description;
    std::string  mitreId;
    std::string  mitreTactic;
    std::vector<std::string> evidence;
    std::chrono::system_clock::time_point timestamp;
    bool   acknowledged    = false;

    void display() const {
        printf("  [%04u] [%s] [%s] PID %u (%ls)\n",
            id, severityToString(severity), sourceToString(source),
            pid, imageName.c_str());
        printf("    Title:  %s\n", title.c_str());
        if (!mitreId.empty()) printf("    MITRE:  %s (%s)\n", mitreId.c_str(), mitreTactic.c_str());
        printf("    %s\n", description.c_str());
        for (const auto& e : evidence) printf("    > %s\n", e.c_str());
    }
};

// Process risk profile (aggregated across all modules)
struct ProcessRiskProfile {
    DWORD  pid = 0;
    std::wstring imageName;
    int    totalFindings   = 0;
    int    criticalCount   = 0;
    int    highCount       = 0;
    int    mediumCount     = 0;
    int    overallScore    = 0;  // 0-100
    std::vector<std::string> sources; // Which modules flagged this process
};

} // namespace detection_intelligence
} // namespace zerophase

#endif
