#pragma once
/*
 * ZeroPhase EDR - Command Line Intelligence: Command Line Info
 *
 * Rich command line information with obfuscation detection,
 * base64 decoding, suspicious pattern matching, and MITRE ATT&CK
 * technique mapping for executed commands.
 */

#ifndef ZEROPHASE_COMMANDLINE_INFO_HPP
#define ZEROPHASE_COMMANDLINE_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace commandline_intelligence {

// ============================================================================
// Command line risk level
// ============================================================================
enum class CmdRiskLevel : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* cmdRiskToString(CmdRiskLevel level) {
    switch (level) {
        case CmdRiskLevel::None:     return "NONE";
        case CmdRiskLevel::Low:      return "LOW";
        case CmdRiskLevel::Medium:   return "MEDIUM";
        case CmdRiskLevel::High:     return "HIGH";
        case CmdRiskLevel::Critical: return "CRITICAL";
        default:                     return "UNKNOWN";
    }
}

// ============================================================================
// Command line category
// ============================================================================
enum class CmdCategory : int {
    Unknown         = 0,
    Normal          = 1,
    Reconnaissance  = 2,   // whoami, ipconfig, systeminfo, net user
    Execution       = 3,   // powershell, cmd, wscript, cscript, mshta
    Persistence     = 4,   // schtasks, reg add, sc create
    PrivilegeEsc    = 5,   // runas, token manipulation
    DefenseEvasion  = 6,   // encoded commands, obfuscation
    CredentialAccess= 7,   // mimikatz patterns, credential dump
    Discovery       = 8,   // net view, nltest, arp
    LateralMovement = 9,   // psexec, wmic /node, winrm
    Collection      = 10,  // compress, archive
    Exfiltration    = 11,  // curl, certutil -urlcache
    Impact          = 12,  // del, format, cipher /w
};

inline const char* cmdCategoryToString(CmdCategory cat) {
    switch (cat) {
        case CmdCategory::Normal:           return "Normal";
        case CmdCategory::Reconnaissance:   return "Recon";
        case CmdCategory::Execution:        return "Execution";
        case CmdCategory::Persistence:      return "Persistence";
        case CmdCategory::PrivilegeEsc:     return "PrivEsc";
        case CmdCategory::DefenseEvasion:   return "DefEvasion";
        case CmdCategory::CredentialAccess: return "CredAccess";
        case CmdCategory::Discovery:        return "Discovery";
        case CmdCategory::LateralMovement:  return "LatMov";
        case CmdCategory::Collection:       return "Collection";
        case CmdCategory::Exfiltration:     return "Exfiltration";
        case CmdCategory::Impact:           return "Impact";
        default:                            return "Unknown";
    }
}

// ============================================================================
// Detected technique with MITRE ATT&CK mapping
// ============================================================================
struct DetectedTechnique {
    std::string techniqueId;    // e.g., "T1059.001"
    std::string techniqueName;  // e.g., "PowerShell"
    CmdCategory category;
    CmdRiskLevel riskLevel;
    std::string description;
    std::string matchedPattern;
};

// ============================================================================
// Rich command line information
// ============================================================================
struct CommandLineInfo {
    // Identity
    DWORD  pid                = 0;
    DWORD  parentPid          = 0;
    std::wstring imageName;
    std::wstring commandLine;
    std::wstring parentImageName;

    // Analysis results
    size_t cmdLength          = 0;
    bool   hasEncodedContent  = false;   // Base64 or hex encoded
    bool   hasObfuscation     = false;   // String concat, caret insertion, etc.
    bool   hasDownloadCradle  = false;   // Download and execute pattern
    bool   hasLongArgument    = false;   // Unusually long single argument

    // Decoded content (if encoded)
    std::wstring decodedContent;

    // Detected techniques
    std::vector<DetectedTechnique> techniques;

    // Risk
    CmdRiskLevel riskLevel    = CmdRiskLevel::None;
    int    riskScore          = 0;
    std::vector<std::string> riskReasons;

    // Timestamps
    std::chrono::system_clock::time_point firstSeen;

    void display() const {
        printf("  PID: %-8u  PPID: %-8u  %ls\n", pid, parentPid, imageName.c_str());
        std::string cmd = native::wstringToString(commandLine);
        if (cmd.length() > 120) cmd = cmd.substr(0, 117) + "...";
        printf("    CmdLine: %s\n", cmd.c_str());
        printf("    Length:  %zu", cmdLength);
        if (hasEncodedContent) printf("  [ENCODED]");
        if (hasObfuscation) printf("  [OBFUSCATED]");
        if (hasDownloadCradle) printf("  [DOWNLOAD]");
        printf("\n");

        if (!decodedContent.empty()) {
            std::string decoded = native::wstringToString(decodedContent);
            if (decoded.length() > 120) decoded = decoded.substr(0, 117) + "...";
            printf("    Decoded: %s\n", decoded.c_str());
        }

        if (!techniques.empty()) {
            printf("    Techniques:\n");
            for (const auto& t : techniques)
                printf("      [%s] %s - %s (%s)\n",
                    t.techniqueId.c_str(), t.techniqueName.c_str(),
                    t.description.c_str(), cmdRiskToString(t.riskLevel));
        }

        if (riskLevel != CmdRiskLevel::None) {
            printf("    [!] Risk: %s (score: %d)\n", cmdRiskToString(riskLevel), riskScore);
            for (const auto& r : riskReasons)
                printf("        - %s\n", r.c_str());
        }
    }

    void displayCompact() const {
        std::string cmd = native::wstringToString(commandLine);
        if (cmd.length() > 60) cmd = cmd.substr(0, 57) + "...";
        printf("  %-8u %-20ls %-8s %s\n",
            pid, imageName.c_str(), cmdRiskToString(riskLevel), cmd.c_str());
    }
};

// ============================================================================
// Free functions
// ============================================================================

// Collect command line info for a process
CommandLineInfo collectCommandLineInfo(DWORD pid);

// Collect command lines for all processes
std::vector<CommandLineInfo> collectAllCommandLines();

} // namespace commandline_intelligence
} // namespace zerophase

#endif // ZEROPHASE_COMMANDLINE_INFO_HPP
