/*
 * ZeroPhase EDR - Memory Intelligence: Entropy Analysis Implementation
 *
 * Shannon entropy calculation and scanning for detecting packed,
 * encrypted, or obfuscated code in memory.
 */

#include "entropy_analysis.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Calculate Shannon entropy for a byte buffer
// ============================================================================
double calculateEntropy(const BYTE* data, SIZE_T length) {
    if (!data || length == 0) return 0.0;

    // Count byte frequencies
    ULONGLONG freq[256] = {};
    for (SIZE_T i = 0; i < length; i++) {
        freq[data[i]]++;
    }

    // Calculate entropy: H = -Σ p(x) * log2(p(x))
    double entropy = 0.0;
    double len = static_cast<double>(length);
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

// ============================================================================
// Calculate entropy for a memory region in a remote process
// ============================================================================
double calculateRegionEntropy(DWORD pid, PVOID baseAddress, SIZE_T regionSize,
                               SIZE_T maxSampleSize) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return 0.0;

    SIZE_T toRead = (regionSize < maxSampleSize) ? regionSize : maxSampleSize;
    std::vector<BYTE> buffer(toRead);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, baseAddress, buffer.data(), toRead, &bytesRead)
        || bytesRead == 0) {
        CloseHandle(hProcess);
        return 0.0;
    }

    CloseHandle(hProcess);
    return calculateEntropy(buffer.data(), bytesRead);
}

// ============================================================================
// Scan a specific region
// ============================================================================
EntropyResult EntropyScanner::scanRegion(DWORD pid, PVOID baseAddress, SIZE_T regionSize,
                                          DWORD protect, DWORD type, MemoryClassification cls) {
    EntropyResult result;
    result.baseAddress = baseAddress;
    result.regionSize = regionSize;
    result.protect = protect;
    result.type = type;
    result.classification = cls;

    DWORD baseProt = protect & 0xFF;
    result.isExecutable = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                           baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

    // Read the region (sample up to 64KB)
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return result;

    SIZE_T toRead = (regionSize < 65536) ? regionSize : 65536;
    std::vector<BYTE> buffer(toRead);
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hProcess, baseAddress, buffer.data(), toRead, &bytesRead)
        && bytesRead > 0) {
        result.sampleSize = bytesRead;
        result.entropy = calculateEntropy(buffer.data(), bytesRead);
        result.isHighEntropy = (result.entropy > 7.0);
        result.isLowEntropy = (result.entropy < 2.0);

        // Byte distribution analysis
        ULONGLONG freq[256] = {};
        for (SIZE_T i = 0; i < bytesRead; i++) {
            freq[buffer[i]]++;
        }

        // Count unique bytes
        result.uniqueBytes = 0;
        ULONGLONG maxFreq = 0;
        BYTE maxByte = 0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > 0) result.uniqueBytes++;
            if (freq[i] > maxFreq) {
                maxFreq = freq[i];
                maxByte = static_cast<BYTE>(i);
            }
        }
        result.mostCommonByte = maxByte;
        result.mostCommonPct = (bytesRead > 0) ?
            (static_cast<double>(maxFreq) / bytesRead * 100.0) : 0.0;

        // Determine if suspicious
        if (result.isHighEntropy && result.isExecutable && type == MEM_PRIVATE) {
            result.isSuspicious = true;
            result.suspiciousReason = "High entropy executable private memory (possible packed/encrypted code)";
        }
        else if (result.isHighEntropy && baseProt == PAGE_EXECUTE_READWRITE) {
            result.isSuspicious = true;
            result.suspiciousReason = "High entropy RWX memory (possible encrypted shellcode)";
        }
    }

    CloseHandle(hProcess);
    return result;
}

// ============================================================================
// Scan all memory regions of a process
// ============================================================================
std::vector<EntropyResult> EntropyScanner::scanProcess(DWORD pid, bool executableOnly) {
    std::vector<EntropyResult> results;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return results;

    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            DWORD baseProt = mbi.Protect & 0xFF;
            bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                          baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

            // In executableOnly mode, skip non-executable regions
            if (!executableOnly || isExec) {
                // Also skip very small regions and guard pages
                if (mbi.RegionSize >= 64 && !(mbi.Protect & PAGE_GUARD)) {
                    std::wstring mappedFile;
                    wchar_t fileName[MAX_PATH] = {};
                    if (GetMappedFileNameW(hProcess, mbi.BaseAddress, fileName, MAX_PATH)) {
                        mappedFile = fileName;
                    }

                    auto cls = classifyRegion(mbi, mappedFile);

                    // Close and reopen in scanRegion (it needs its own handle)
                    auto result = scanRegion(pid, mbi.BaseAddress, mbi.RegionSize,
                                              mbi.Protect, mbi.Type, cls);
                    results.push_back(std::move(result));
                }
            }
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);
    return results;
}

// ============================================================================
// Display entropy scan results
// ============================================================================
void EntropyScanner::displayResults(const std::vector<EntropyResult>& results) {
    std::cout << "\n=== Entropy Scan Results ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;
    printf("  %-18s %-10s %-8s %-8s %-14s %-8s %-5s %s\n",
        "Address", "Size", "Prot", "Type", "Class", "Entropy", "Uniq", "Status");
    std::cout << std::string(110, '-') << std::endl;

    int suspicious = 0;
    for (const auto& r : results) {
        printf("  0x%016llX %-10s %-8s %-8s %-14s %-8.3f %-5d %s\n",
            (ULONGLONG)r.baseAddress,
            native::formatSize(r.regionSize).c_str(),
            native::protectionToString(r.protect).c_str(),
            native::memoryTypeToString(r.type).c_str(),
            classificationToString(r.classification),
            r.entropy,
            r.uniqueBytes,
            r.isSuspicious ? "[!] SUSPICIOUS" :
            r.isHighEntropy ? "[*] High" : "");

        if (r.isSuspicious) {
            printf("       ^^ %s\n", r.suspiciousReason.c_str());
            suspicious++;
        }
    }

    std::cout << std::string(110, '-') << std::endl;
    std::cout << "  Total regions scanned: " << results.size() << std::endl;
    if (suspicious > 0)
        std::cout << "  [!] Suspicious regions: " << suspicious << std::endl;
}

// ============================================================================
// Display entropy histogram
// ============================================================================
void EntropyScanner::displayEntropyHistogram(const std::vector<EntropyResult>& results) {
    std::cout << "\n=== Entropy Distribution ===" << std::endl;

    // Buckets: 0-1, 1-2, 2-3, 3-4, 4-5, 5-6, 6-7, 7-8
    int buckets[8] = {};
    SIZE_T bucketSizes[8] = {};

    for (const auto& r : results) {
        int bucket = static_cast<int>(r.entropy);
        if (bucket >= 8) bucket = 7;
        if (bucket < 0) bucket = 0;
        buckets[bucket]++;
        bucketSizes[bucket] += r.regionSize;
    }

    int maxCount = *std::max_element(buckets, buckets + 8);
    if (maxCount == 0) maxCount = 1;

    for (int i = 0; i < 8; i++) {
        printf("  %d.0-%d.0 |", i, i + 1);
        int barLen = (buckets[i] * 40) / maxCount;
        for (int j = 0; j < barLen; j++) std::cout << "█";
        printf(" %d (%s)%s\n", buckets[i],
            native::formatSize(bucketSizes[i]).c_str(),
            (i == 7 && buckets[i] > 0) ? " [!]" : "");
    }
}

// ============================================================================
// Filter to suspicious only
// ============================================================================
std::vector<EntropyResult> EntropyScanner::filterSuspicious(
    const std::vector<EntropyResult>& results) {
    std::vector<EntropyResult> filtered;
    for (const auto& r : results) {
        if (r.isSuspicious) filtered.push_back(r);
    }
    return filtered;
}

} // namespace memory_intelligence
} // namespace zerophase
