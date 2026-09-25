#pragma once
/*
 * ZeroPhase EDR - DLL Intelligence: DLL Info
 *
 * Rich DLL information with Authenticode signature verification,
 * sideloading detection, known-DLL analysis, and risk scoring.
 *
 * Detection capabilities:
 * - Unsigned DLLs loaded into signed processes
 * - DLL sideloading (DLL in unusual directory)
 * - Known-DLL hijacking (system DLL loaded from non-system path)
 * - Phantom DLL loading (DLL not on disk)
 * - DLL with mismatched PE timestamps
 */

#ifndef ZEROPHASE_DLL_INFO_HPP
#define ZEROPHASE_DLL_INFO_HPP

#include "../native.hpp"
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace zerophase {
namespace dll_intelligence {

// ============================================================================
// DLL risk level
// ============================================================================
enum class DllRiskLevel : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* dllRiskToString(DllRiskLevel level) {
    switch (level) {
        case DllRiskLevel::None:     return "NONE";
        case DllRiskLevel::Low:      return "LOW";
        case DllRiskLevel::Medium:   return "MEDIUM";
        case DllRiskLevel::High:     return "HIGH";
        case DllRiskLevel::Critical: return "CRITICAL";
        default:                     return "UNKNOWN";
    }
}

// ============================================================================
// Signature verification status
// ============================================================================
enum class SignatureStatus : int {
    Unknown       = 0,
    Valid         = 1,   // Authenticode signature valid
    Invalid       = 2,   // Signature present but invalid
    NotSigned     = 3,   // No signature
    CatalogSigned = 4,   // Signed via Windows catalog
    Expired       = 5,   // Signature expired
    Untrusted     = 6,   // Untrusted root CA
    Error         = 7,   // Could not verify
};

inline const char* signatureStatusToString(SignatureStatus s) {
    switch (s) {
        case SignatureStatus::Unknown:       return "Unknown";
        case SignatureStatus::Valid:         return "Signed";
        case SignatureStatus::Invalid:       return "INVALID";
        case SignatureStatus::NotSigned:     return "Unsigned";
        case SignatureStatus::CatalogSigned: return "Catalog";
        case SignatureStatus::Expired:       return "Expired";
        case SignatureStatus::Untrusted:     return "Untrusted";
        case SignatureStatus::Error:         return "Error";
        default:                             return "???";
    }
}

// ============================================================================
// DLL load location classification
// ============================================================================
enum class DllLocation : int {
    Unknown         = 0,
    System32        = 1,   // C:\Windows\System32
    SysWOW64        = 2,   // C:\Windows\SysWOW64
    WindowsDir      = 3,   // C:\Windows\*
    ProgramFiles    = 4,   // C:\Program Files\*
    AppDir          = 5,   // Same directory as the executable
    UserDir         = 6,   // User profile directory
    TempDir         = 7,   // %TEMP% or %TMP%
    DownloadsDir    = 8,   // Downloads folder
    Other           = 9,   // Unknown/other location
};

inline const char* dllLocationToString(DllLocation loc) {
    switch (loc) {
        case DllLocation::System32:     return "System32";
        case DllLocation::SysWOW64:     return "SysWOW64";
        case DllLocation::WindowsDir:   return "Windows";
        case DllLocation::ProgramFiles: return "ProgramFiles";
        case DllLocation::AppDir:       return "AppDir";
        case DllLocation::UserDir:      return "UserProfile";
        case DllLocation::TempDir:      return "TEMP";
        case DllLocation::DownloadsDir: return "Downloads";
        case DllLocation::Other:        return "Other";
        default:                        return "Unknown";
    }
}

// ============================================================================
// Rich DLL information
// ============================================================================
struct DllInfo {
    // Identity
    DWORD  ownerPid           = 0;
    std::wstring ownerImageName;
    PVOID  baseAddress        = nullptr;
    DWORD  sizeOfImage        = 0;
    std::wstring moduleName;      // Base name (e.g., "ntdll.dll")
    std::wstring fullPath;        // Full path on disk

    // PE information
    DWORD  peTimestamp        = 0;
    bool   is64Bit            = true;
    bool   isDotNet           = false;
    bool   existsOnDisk       = false;

    // Signature
    SignatureStatus signatureStatus = SignatureStatus::Unknown;
    std::wstring signerName;

    // Location
    DllLocation location      = DllLocation::Unknown;

    // Known-DLL analysis
    bool   isKnownDll         = false;  // In Windows KnownDLLs list
    bool   isSystemDll        = false;  // Loaded from System32/SysWOW64
    bool   isMicrosoftDll     = false;  // Signed by Microsoft

    // Sideloading indicators
    bool   sideloadSuspect    = false;  // DLL loaded from non-standard path
    bool   phantomDll         = false;  // DLL not found on disk

    // Risk
    DllRiskLevel riskLevel    = DllRiskLevel::None;
    int    riskScore          = 0;
    std::vector<std::string> riskReasons;

    // Timestamps
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastUpdated;

    // Display
    void display() const {
        printf("  0x%016llX %-10s %-30ls\n",
            (ULONGLONG)baseAddress,
            native::formatSize(sizeOfImage).c_str(),
            moduleName.c_str());
        if (!fullPath.empty())
            std::cout << "    Path:       " << native::wstringToString(fullPath) << std::endl;
        printf("    Location:   %-14s  Signature: %-10s",
            dllLocationToString(location),
            signatureStatusToString(signatureStatus));
        if (!signerName.empty())
            printf("  Signer: %ls", signerName.c_str());
        printf("\n");
        if (riskLevel != DllRiskLevel::None) {
            printf("    [!] Risk: %s (score: %d)\n", dllRiskToString(riskLevel), riskScore);
            for (const auto& r : riskReasons)
                printf("        - %s\n", r.c_str());
        }
    }

    void displayCompact() const {
        printf("  0x%016llX %-10s %-10s %-14s %-8s %ls",
            (ULONGLONG)baseAddress,
            native::formatSize(sizeOfImage).c_str(),
            signatureStatusToString(signatureStatus),
            dllLocationToString(location),
            dllRiskToString(riskLevel),
            moduleName.c_str());
        if (phantomDll) printf(" [PHANTOM]");
        if (sideloadSuspect) printf(" [SIDELOAD?]");
        printf("\n");
    }
};

// ============================================================================
// Per-process DLL summary
// ============================================================================
struct ProcessDllSummary {
    DWORD  pid                = 0;
    std::wstring imageName;
    DWORD  totalDlls          = 0;
    DWORD  signedCount        = 0;
    DWORD  unsignedCount      = 0;
    DWORD  catalogSignedCount = 0;
    DWORD  suspiciousCount    = 0;
    DWORD  phantomCount       = 0;
    DWORD  sideloadCount      = 0;
    DllRiskLevel highestRisk  = DllRiskLevel::None;
};

// ============================================================================
// Free functions — declared here, defined in dll_info.cpp
// ============================================================================

// Verify Authenticode signature of a file
SignatureStatus verifyFileSignature(const std::wstring& filePath, std::wstring& outSignerName);

// Classify where a DLL is loaded from
DllLocation classifyDllLocation(const std::wstring& dllPath, const std::wstring& processPath);

// Check if a DLL name is in the Windows KnownDLLs list
bool isKnownDll(const std::wstring& dllName);

// Enumerate all DLLs for a process with full enrichment
std::vector<DllInfo> enumerateProcessDlls(DWORD pid, bool verifySignatures = false);

// Compute DLL summary for a process
ProcessDllSummary computeDllSummary(const std::vector<DllInfo>& dlls, DWORD pid);

// Perform risk analysis on a DLL
void analyzeDllRisk(DllInfo& dll);

} // namespace dll_intelligence
} // namespace zerophase

#endif // ZEROPHASE_DLL_INFO_HPP
