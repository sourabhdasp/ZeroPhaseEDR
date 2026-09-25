#pragma once
/*
 * ZeroPhase EDR - Memory Intelligence: Entropy Analysis
 *
 * Shannon entropy calculation for memory regions.
 * High entropy (>7.0) indicates compressed, encrypted, or random data.
 * Combined with execution permissions, high entropy suggests:
 * - Packed malware (UPX, Themida, etc.)
 * - Encrypted shellcode
 * - Reflectively loaded encrypted payloads
 *
 * Entropy scale:
 *   0.0 = perfectly uniform (all same byte)
 *   8.0 = perfectly random (maximum for byte data)
 *   >7.0 = likely compressed/encrypted
 *   5.0-7.0 = typical code/data
 *   <4.0 = sparse data, lots of padding
 */

#ifndef ZEROPHASE_ENTROPY_ANALYSIS_HPP
#define ZEROPHASE_ENTROPY_ANALYSIS_HPP

#include "memory_info.hpp"
#include <cmath>

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Entropy calculation
// ============================================================================

// Calculate Shannon entropy for a byte buffer (returns 0.0 - 8.0)
double calculateEntropy(const BYTE* data, SIZE_T length);

// Calculate entropy for a memory region in a remote process
double calculateRegionEntropy(DWORD pid, PVOID baseAddress, SIZE_T regionSize,
                               SIZE_T maxSampleSize = 65536);

// ============================================================================
// Entropy scan result for a single region
// ============================================================================
struct EntropyResult {
    PVOID  baseAddress    = nullptr;
    SIZE_T regionSize     = 0;
    SIZE_T sampleSize     = 0;   // Actual bytes analyzed
    double entropy        = 0.0;
    DWORD  protect        = 0;
    DWORD  type           = 0;
    MemoryClassification classification = MemoryClassification::Unknown;

    // Byte distribution stats
    int    uniqueBytes    = 0;   // How many distinct byte values appear
    BYTE   mostCommonByte = 0;
    double mostCommonPct  = 0.0; // Percentage of most common byte

    // Flags
    bool   isHighEntropy  = false;  // > 7.0
    bool   isLowEntropy   = false;  // < 2.0
    bool   isExecutable   = false;
    bool   isSuspicious   = false;
    std::string suspiciousReason;
};

// ============================================================================
// Entropy Scanner
// ============================================================================
class EntropyScanner {
public:
    // Scan all memory regions of a process for entropy
    std::vector<EntropyResult> scanProcess(DWORD pid, bool executableOnly = true);

    // Scan a specific region
    EntropyResult scanRegion(DWORD pid, PVOID baseAddress, SIZE_T regionSize,
                              DWORD protect, DWORD type, MemoryClassification cls);

    // Display entropy scan results
    static void displayResults(const std::vector<EntropyResult>& results);

    // Display a histogram of entropy distribution
    static void displayEntropyHistogram(const std::vector<EntropyResult>& results);

    // Get only suspicious results (high entropy + executable)
    static std::vector<EntropyResult> filterSuspicious(
        const std::vector<EntropyResult>& results);
};

} // namespace memory_intelligence
} // namespace zerophase

#endif // ZEROPHASE_ENTROPY_ANALYSIS_HPP
