/*
 * ZeroPhase EDR - Memory Intelligence: Memory Info Implementation
 *
 * Enumerates process memory with classification, mapped file resolution,
 * and risk analysis for each region.
 */

#include "memory_info.hpp"

namespace zerophase {
namespace memory_intelligence {

// ============================================================================
// Classify a memory region
// ============================================================================
MemoryClassification classifyRegion(const MEMORY_BASIC_INFORMATION& mbi,
                                     const std::wstring& mappedFile)
{
    if (mbi.State == MEM_FREE) return MemoryClassification::Free;
    if (mbi.State != MEM_COMMIT) return MemoryClassification::Unknown;
    if (mbi.Protect & PAGE_GUARD) return MemoryClassification::Guard;

    DWORD baseProt = mbi.Protect & 0xFF;
    bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                   baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

    if (mbi.Type == MEM_IMAGE) {
        return isExec ? MemoryClassification::ImageCode : MemoryClassification::ImageData;
    }
    if (mbi.Type == MEM_MAPPED) {
        return MemoryClassification::MappedFile;
    }
    // MEM_PRIVATE
    if (isExec) return MemoryClassification::PrivateExec;
    return MemoryClassification::PrivateData;
}

// ============================================================================
// Enumerate all memory regions for a process
// ============================================================================
std::vector<MemoryRegionInfo> enumerateProcessMemory(DWORD pid, bool deepScan) {
    std::vector<MemoryRegionInfo> regions;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return regions;

    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;
    auto now = std::chrono::system_clock::now();

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegionInfo region;
            region.ownerPid        = pid;
            region.baseAddress     = mbi.BaseAddress;
            region.allocationBase  = mbi.AllocationBase;
            region.regionSize      = mbi.RegionSize;
            region.allocationProtect = mbi.AllocationProtect;
            region.currentProtect  = mbi.Protect;
            region.state           = mbi.State;
            region.type            = mbi.Type;
            region.firstSeen       = now;
            region.lastUpdated     = now;

            // Get mapped file name
            wchar_t fileName[MAX_PATH] = {};
            if (GetMappedFileNameW(hProcess, mbi.BaseAddress, fileName, MAX_PATH)) {
                region.mappedFileName = fileName;
            }

            // Classify
            region.classification = classifyRegion(mbi, region.mappedFileName);

            // Deep scan: read content for PE header check and content hashing
            if (deepScan) {
                DWORD baseProt = mbi.Protect & 0xFF;
                bool isExecOrRw = (baseProt == PAGE_EXECUTE_READWRITE ||
                                   baseProt == PAGE_EXECUTE_READ ||
                                   baseProt == PAGE_EXECUTE ||
                                   baseProt == PAGE_EXECUTE_WRITECOPY);
                bool isPrivateExec = (region.classification == MemoryClassification::PrivateExec);

                // Only deep-scan interesting regions to avoid perf hit
                if (isPrivateExec || (isExecOrRw && mbi.Type == MEM_PRIVATE)) {
                    SIZE_T toRead = (mbi.RegionSize < 4096) ? mbi.RegionSize : 4096;
                    std::vector<BYTE> buf(toRead);
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(), toRead, &bytesRead)
                        && bytesRead > 0) {
                        // Check for MZ (PE) header
                        if (bytesRead >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
                            region.hasPEHeader = true;
                        }

                        // Content hash (first bytes)
                        size_t h = 0;
                        for (SIZE_T i = 0; i < bytesRead && i < 256; i++) {
                            h ^= std::hash<BYTE>{}(buf[i]) + 0x9e3779b9 + (h << 6) + (h >> 2);
                        }
                        region.contentHash = h;

                        // Check for null-free executable code (common in shellcode)
                        if (bytesRead >= 64) {
                            bool hasNull = false;
                            for (SIZE_T i = 0; i < bytesRead && i < 256; i++) {
                                if (buf[i] == 0x00) { hasNull = true; break; }
                            }
                            region.hasNullFreeCode = !hasNull;
                        }

                        // Check for common shellcode patterns
                        // - NOP sled (0x90 repeated)
                        // - INT3 sled (0xCC repeated)
                        // - call/jmp patterns at start
                        if (bytesRead >= 4) {
                            int nopCount = 0;
                            for (SIZE_T i = 0; i < bytesRead && i < 64; i++) {
                                if (buf[i] == 0x90) nopCount++;
                            }
                            if (nopCount > 16) region.hasShellcodePatterns = true;

                            // Pattern: E8 XX XX XX XX (call rel32) at start
                            if (buf[0] == 0xE8 || buf[0] == 0xE9) {
                                region.hasShellcodePatterns = true;
                            }
                            // Pattern: FC (cld) followed by code (common Metasploit pattern)
                            if (buf[0] == 0xFC && buf[1] == 0x48) {
                                region.hasShellcodePatterns = true;
                            }
                        }
                    }
                }
            }

            // Risk analysis
            analyzeMemoryRisk(region);
            regions.push_back(std::move(region));
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break; // Overflow protection
    }

    CloseHandle(hProcess);
    return regions;
}

// ============================================================================
// Compute memory summary for a process
// ============================================================================
ProcessMemorySummary computeMemorySummary(DWORD pid,
    const std::vector<MemoryRegionInfo>& regions)
{
    ProcessMemorySummary summary;
    summary.pid = pid;
    summary.regionCount = static_cast<DWORD>(regions.size());

    for (const auto& r : regions) {
        summary.totalCommitted += r.regionSize;

        DWORD baseProt = r.currentProtect & 0xFF;
        bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                       baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);
        bool isWrite = (baseProt == PAGE_READWRITE || baseProt == PAGE_WRITECOPY ||
                        baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

        if (isExec) {
            summary.totalExecutable += r.regionSize;
            summary.executableRegions++;
        }
        if (isWrite) summary.totalWritable += r.regionSize;
        if (baseProt == PAGE_EXECUTE_READWRITE) {
            summary.totalRwx += r.regionSize;
            summary.rwxRegionCount++;
        }

        switch (r.type) {
            case MEM_IMAGE:   summary.totalImage += r.regionSize; break;
            case MEM_MAPPED:  summary.totalMapped += r.regionSize; break;
            case MEM_PRIVATE: summary.totalPrivate += r.regionSize; break;
        }

        if (r.riskLevel != MemoryRiskLevel::None) summary.suspiciousCount++;
        if (r.entropyComputed && r.entropy > 7.0) summary.highEntropyCount++;
        if (r.hasPEHeader && r.type == MEM_PRIVATE) summary.peHeaderCount++;

        if (static_cast<int>(r.riskLevel) > static_cast<int>(summary.highestRisk))
            summary.highestRisk = r.riskLevel;
    }

    return summary;
}

// ============================================================================
// Risk analysis for a memory region
// ============================================================================
void analyzeMemoryRisk(MemoryRegionInfo& region) {
    region.riskScore = 0;
    region.riskReasons.clear();
    region.riskLevel = MemoryRiskLevel::None;

    DWORD baseProt = region.currentProtect & 0xFF;

    // 1. RWX memory (Read-Write-Execute) - very strong indicator
    if (baseProt == PAGE_EXECUTE_READWRITE) {
        region.riskScore += 40;
        region.riskReasons.push_back("RWX (Read-Write-Execute) memory");
    }

    // 2. Private executable memory not backed by a file
    if (region.classification == MemoryClassification::PrivateExec) {
        region.riskScore += 30;
        region.riskReasons.push_back("Executable private memory (no backing image)");
    }

    // 3. PE header in private memory (reflective DLL loading)
    if (region.hasPEHeader && region.type == MEM_PRIVATE) {
        region.riskScore += 35;
        region.riskReasons.push_back("PE header (MZ) found in private memory (possible reflective load)");
    }

    // 4. Shellcode patterns detected
    if (region.hasShellcodePatterns) {
        region.riskScore += 25;
        region.riskReasons.push_back("Common shellcode byte patterns detected");
    }

    // 5. Null-free code region (shellcode indicator)
    if (region.hasNullFreeCode && region.classification == MemoryClassification::PrivateExec) {
        region.riskScore += 15;
        region.riskReasons.push_back("Null-free code detected (common in shellcode)");
    }

    // 6. High entropy in executable region (packed/encrypted code)
    if (region.entropyComputed && region.entropy > 7.0 &&
        region.classification == MemoryClassification::PrivateExec) {
        region.riskScore += 30;
        region.riskReasons.push_back("High entropy executable memory (possible packed/encrypted code)");
    }

    // 7. Protection changed from original allocation (stomp)
    if (region.allocationProtect != region.currentProtect) {
        DWORD origBase = region.allocationProtect & 0xFF;
        bool origExec = (origBase == PAGE_EXECUTE || origBase == PAGE_EXECUTE_READ ||
                         origBase == PAGE_EXECUTE_READWRITE || origBase == PAGE_EXECUTE_WRITECOPY);
        bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                       baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

        // Originally non-exec, now exec = possible code injection via VirtualProtect
        if (!origExec && isExec) {
            region.riskScore += 25;
            region.riskReasons.push_back("Protection escalated to executable (possible VirtualProtect abuse)");
        }
    }

    // Calculate risk level
    if (region.riskScore >= 70)
        region.riskLevel = MemoryRiskLevel::Critical;
    else if (region.riskScore >= 50)
        region.riskLevel = MemoryRiskLevel::High;
    else if (region.riskScore >= 30)
        region.riskLevel = MemoryRiskLevel::Medium;
    else if (region.riskScore >= 10)
        region.riskLevel = MemoryRiskLevel::Low;
}

} // namespace memory_intelligence
} // namespace zerophase
