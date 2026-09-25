#pragma once
/*
 * ZeroPhase EDR - Memory Intelligence: Memory Info
 *
 * Rich memory region information with classification, entropy scoring,
 * and suspicious pattern detection for shellcode/packed code identification.
 */

#ifndef ZEROPHASE_MEMORY_INFO_HPP
#define ZEROPHASE_MEMORY_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Memory risk level
// ============================================================================
enum class MemoryRiskLevel : int {
    None     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

inline const char* memoryRiskToString(MemoryRiskLevel level) {
    switch (level) {
        case MemoryRiskLevel::None:     return "NONE";
        case MemoryRiskLevel::Low:      return "LOW";
        case MemoryRiskLevel::Medium:   return "MEDIUM";
        case MemoryRiskLevel::High:     return "HIGH";
        case MemoryRiskLevel::Critical: return "CRITICAL";
        default:                        return "UNKNOWN";
    }
}

// ============================================================================
// Memory region classification
// ============================================================================
enum class MemoryClassification : int {
    Unknown         = 0,
    ImageCode       = 1,   // Code section of a PE image
    ImageData       = 2,   // Data section of a PE image
    Stack           = 3,   // Thread stack
    Heap            = 4,   // Process heap
    MappedFile      = 5,   // Memory-mapped file
    PrivateData     = 6,   // Private writable data
    PrivateExec     = 7,   // Private executable (SUSPICIOUS)
    SharedMemory    = 8,   // Shared section
    Guard           = 9,   // Guard page
    Free            = 10,  // Free/uncommitted
};

inline const char* classificationToString(MemoryClassification cls) {
    switch (cls) {
        case MemoryClassification::Unknown:      return "Unknown";
        case MemoryClassification::ImageCode:    return "Image Code";
        case MemoryClassification::ImageData:    return "Image Data";
        case MemoryClassification::Stack:        return "Stack";
        case MemoryClassification::Heap:         return "Heap";
        case MemoryClassification::MappedFile:   return "Mapped File";
        case MemoryClassification::PrivateData:  return "Private Data";
        case MemoryClassification::PrivateExec:  return "Private Exec";
        case MemoryClassification::SharedMemory: return "Shared";
        case MemoryClassification::Guard:        return "Guard";
        case MemoryClassification::Free:         return "Free";
        default:                                 return "???";
    }
}

// ============================================================================
// Rich memory region information
// ============================================================================
struct MemoryRegionInfo {
    // Identity
    DWORD  ownerPid           = 0;
    PVOID  baseAddress        = nullptr;
    PVOID  allocationBase     = nullptr;
    SIZE_T regionSize         = 0;

    // Protection
    DWORD  allocationProtect  = 0;
    DWORD  currentProtect     = 0;
    DWORD  state              = 0;    // MEM_COMMIT / MEM_RESERVE / MEM_FREE
    DWORD  type               = 0;    // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE

    // Classification
    MemoryClassification classification = MemoryClassification::Unknown;
    std::wstring mappedFileName;

    // Entropy analysis (0.0 = all zeros, 8.0 = perfectly random)
    double entropy            = 0.0;
    bool   entropyComputed    = false;

    // Content signatures
    bool   hasPEHeader        = false;   // MZ header detected
    bool   hasShellcodePatterns = false;  // Common shellcode byte patterns
    bool   hasNullFreeCode    = false;    // No null bytes in executable region (shellcode indicator)
    bool   hasStringPatterns  = false;    // Readable strings present

    // Risk assessment
    MemoryRiskLevel riskLevel = MemoryRiskLevel::None;
    int    riskScore          = 0;
    std::vector<std::string> riskReasons;

    // Change tracking
    size_t contentHash        = 0;       // Hash of first N bytes for change detection
    bool   contentChanged     = false;   // Changed since last scan
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastUpdated;

    // Display
    void display() const {
        printf("  0x%016llX  Size: %-10s  Prot: %-8s  Type: %-8s  Class: %s\n",
            (ULONGLONG)baseAddress,
            native::formatSize(regionSize).c_str(),
            native::protectionToString(currentProtect).c_str(),
            native::memoryTypeToString(type).c_str(),
            classificationToString(classification));

        if (!mappedFileName.empty()) {
            std::cout << "    File: " << native::wstringToString(mappedFileName) << std::endl;
        }
        if (entropyComputed) {
            printf("    Entropy: %.3f%s\n", entropy,
                entropy > 7.0 ? " [HIGH - possible packed/encrypted]" :
                entropy > 6.0 ? " [elevated]" : "");
        }
        if (hasPEHeader) printf("    [!] PE header (MZ) detected\n");
        if (hasShellcodePatterns) printf("    [!] Shellcode patterns detected\n");

        if (riskLevel != MemoryRiskLevel::None) {
            printf("    [!] Risk: %s (score: %d)\n", memoryRiskToString(riskLevel), riskScore);
            for (const auto& reason : riskReasons)
                printf("        - %s\n", reason.c_str());
        }
    }

    void displayCompact() const {
        printf("  0x%016llX %-10s %-8s %-8s %-14s",
            (ULONGLONG)baseAddress,
            native::formatSize(regionSize).c_str(),
            native::protectionToString(currentProtect).c_str(),
            native::memoryTypeToString(type).c_str(),
            classificationToString(classification));
        if (entropyComputed) printf(" E:%.1f", entropy);
        if (riskLevel != MemoryRiskLevel::None)
            printf(" [%s]", memoryRiskToString(riskLevel));
        printf("\n");
    }
};

// ============================================================================
// Process memory summary
// ============================================================================
struct ProcessMemorySummary {
    DWORD  pid                = 0;
    std::wstring imageName;

    SIZE_T totalCommitted     = 0;
    SIZE_T totalReserved      = 0;
    SIZE_T totalExecutable    = 0;
    SIZE_T totalWritable      = 0;
    SIZE_T totalRwx           = 0;
    SIZE_T totalImage         = 0;
    SIZE_T totalPrivate       = 0;
    SIZE_T totalMapped        = 0;

    DWORD  regionCount        = 0;
    DWORD  executableRegions  = 0;
    DWORD  rwxRegionCount     = 0;
    DWORD  suspiciousCount    = 0;
    DWORD  highEntropyCount   = 0;   // entropy > 7.0
    DWORD  peHeaderCount      = 0;   // Unbacked PE headers

    MemoryRiskLevel highestRisk = MemoryRiskLevel::None;
};

// ============================================================================
// Free functions — declared here, defined in memory_info.cpp
// ============================================================================

// Classify a memory region based on its attributes
MemoryClassification classifyRegion(const MEMORY_BASIC_INFORMATION& mbi,
                                     const std::wstring& mappedFile);

// Enumerate all memory regions for a process with enrichment
std::vector<MemoryRegionInfo> enumerateProcessMemory(DWORD pid, bool deepScan = false);

// Compute summary statistics
ProcessMemorySummary computeMemorySummary(DWORD pid,
    const std::vector<MemoryRegionInfo>& regions);

// Perform risk analysis on a memory region
void analyzeMemoryRisk(MemoryRegionInfo& region);

} // namespace memory_intelligence
} // namespace zerophase

#endif // ZEROPHASE_MEMORY_INFO_HPP
