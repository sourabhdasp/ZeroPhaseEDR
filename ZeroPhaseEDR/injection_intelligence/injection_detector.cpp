/*
 * ZeroPhase EDR - Injection Intelligence: Injection Detector Implementation
 *
 * Correlates memory, thread, and module signals to detect injection.
 */

#include "injection_detector.hpp"
#include <cmath>

namespace zerophase {
namespace injection_intelligence {

// ============================================================================
// Helpers
// ============================================================================
bool InjectionDetector::readRemoteBytes(HANDLE hProcess, PVOID address, BYTE* buffer, SIZE_T size) {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(hProcess, address, buffer, size, &bytesRead) && bytesRead == size;
}

bool InjectionDetector::isPEHeader(const BYTE* data, SIZE_T size) {
    if (size < 64) return false;
    // MZ signature
    if (data[0] != 'M' || data[1] != 'Z') return false;
    // Check e_lfanew points to valid PE\0\0
    LONG e_lfanew = *reinterpret_cast<const LONG*>(data + 0x3C);
    if (e_lfanew < 0 || (SIZE_T)e_lfanew + 4 > size) return false;
    if (data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E' &&
        data[e_lfanew + 2] == 0 && data[e_lfanew + 3] == 0) {
        return true;
    }
    return false;
}

double InjectionDetector::quickEntropy(HANDLE hProcess, PVOID address, SIZE_T maxRead) {
    std::vector<BYTE> buf(maxRead);
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, address, buf.data(), maxRead, &bytesRead) || bytesRead == 0)
        return 0.0;

    ULONGLONG freq[256] = {};
    for (SIZE_T i = 0; i < bytesRead; i++) freq[buf[i]]++;

    double entropy = 0.0;
    double len = (double)bytesRead;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// ============================================================================
// Full injection scan for a process
// ============================================================================
ProcessInjectionResult InjectionDetector::scanProcess(DWORD pid) {
    ProcessInjectionResult result;
    result.pid = pid;
    result.scanTime = std::chrono::system_clock::now();

    // Get image name
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t path[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
            std::wstring full(path, sz);
            auto pos = full.find_last_of(L'\\');
            result.imageName = (pos != std::wstring::npos) ? full.substr(pos + 1) : full;
        }
        CloseHandle(hProc);
    }

    // Open with full access for scanning
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        result.scanned = false;
        return result;
    }

    result.scanned = true;

    // Run all detectors
    detectRemoteThreads(pid, hProcess, result);
    detectPrivateExecutable(pid, hProcess, result);
    detectReflectiveDll(pid, hProcess, result);
    detectModuleStomping(pid, hProcess, result);
    detectProcessHollowing(pid, hProcess, result);

    CloseHandle(hProcess);

    // Compute highest risk
    for (const auto& f : result.findings) {
        if (static_cast<int>(f.riskLevel) > static_cast<int>(result.highestRisk))
            result.highestRisk = f.riskLevel;
    }

    return result;
}

// ============================================================================
// Detect remote threads (threads whose start address is outside all modules)
// ============================================================================
void InjectionDetector::detectRemoteThreads(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result) {
    auto& api = native::NativeApi::instance();
    if (!api.NtQueryInformationThread) return;

    // Get module ranges
    HMODULE hMods[2048];
    DWORD cbNeeded;
    struct ModRange { PBYTE base; SIZE_T size; std::wstring name; };
    std::vector<ModRange> modules;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO mi;
            wchar_t name[MAX_PATH] = {};
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH);
                modules.push_back({(PBYTE)mi.lpBaseOfDll, mi.SizeOfImage, name});
            }
        }
    }

    // Enumerate threads
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            PVOID startAddr = nullptr;
            ULONG retLen = 0;
            api.NtQueryInformationThread(hThread, native::ThreadQuerySetWin32StartAddress,
                &startAddr, sizeof(startAddr), &retLen);
            CloseHandle(hThread);

            if (!startAddr) continue;

            // Check if start address is in any module
            bool inModule = false;
            for (const auto& m : modules) {
                if ((PBYTE)startAddr >= m.base && (PBYTE)startAddr < m.base + m.size) {
                    inModule = true;
                    break;
                }
            }

            if (!inModule) {
                // Check the memory at the start address
                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQueryEx(hProcess, startAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                    InjectionFinding finding;
                    finding.targetPid = pid;
                    finding.targetImageName = result.imageName;
                    finding.suspiciousAddress = startAddr;
                    finding.regionSize = mbi.RegionSize;
                    finding.memoryProtect = mbi.Protect;
                    finding.memoryType = mbi.Type;
                    finding.suspiciousThreadId = te.th32ThreadID;
                    finding.detectedAt = std::chrono::system_clock::now();

                    if (mbi.Type == MEM_PRIVATE) {
                        finding.type = InjectionType::RemoteThreadShell;
                        finding.riskLevel = InjectionRisk::Critical;
                        finding.confidenceScore = 85;
                        finding.mitreId = "T1055.003";
                        finding.description = "Thread start address in private memory outside all modules";
                        finding.evidence.push_back("TID " + std::to_string(te.th32ThreadID) +
                            " starts at 0x" + std::to_string((ULONGLONG)startAddr));
                        finding.evidence.push_back("Memory type: PRIVATE, Protect: " +
                            native::protectionToString(mbi.Protect));
                    } else {
                        finding.type = InjectionType::RemoteThreadDll;
                        finding.riskLevel = InjectionRisk::High;
                        finding.confidenceScore = 60;
                        finding.mitreId = "T1055.001";
                        finding.description = "Thread start address outside loaded module boundaries";
                        finding.evidence.push_back("TID " + std::to_string(te.th32ThreadID));
                    }

                    result.findings.push_back(std::move(finding));
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

// ============================================================================
// Detect private executable memory (potential shellcode regions)
// ============================================================================
void InjectionDetector::detectPrivateExecutable(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result) {
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            DWORD baseProt = mbi.Protect & 0xFF;

            // RWX private memory — strongest injection signal
            if (baseProt == PAGE_EXECUTE_READWRITE) {
                InjectionFinding finding;
                finding.targetPid = pid;
                finding.targetImageName = result.imageName;
                finding.suspiciousAddress = mbi.BaseAddress;
                finding.regionSize = mbi.RegionSize;
                finding.memoryProtect = mbi.Protect;
                finding.memoryType = mbi.Type;
                finding.detectedAt = std::chrono::system_clock::now();
                finding.type = InjectionType::RemoteThreadShell;
                finding.riskLevel = InjectionRisk::High;
                finding.confidenceScore = 70;
                finding.mitreId = "T1055";
                finding.description = "RWX private memory region (potential shellcode)";
                finding.evidence.push_back("Address: 0x" + std::to_string((ULONGLONG)mbi.BaseAddress));
                finding.evidence.push_back("Size: " + native::formatSize(mbi.RegionSize));

                // Check entropy
                double ent = quickEntropy(hProcess, mbi.BaseAddress);
                if (ent > 6.5) {
                    finding.confidenceScore += 15;
                    finding.evidence.push_back("High entropy: " + std::to_string(ent));
                }

                result.findings.push_back(std::move(finding));
            }
            // Executable private (R-X) — less suspicious but still notable
            else if (baseProt == PAGE_EXECUTE_READ && mbi.RegionSize >= 4096) {
                // Check for protection escalation (originally non-exec)
                DWORD origBase = mbi.AllocationProtect & 0xFF;
                bool origExec = (origBase == PAGE_EXECUTE || origBase == PAGE_EXECUTE_READ ||
                                origBase == PAGE_EXECUTE_READWRITE || origBase == PAGE_EXECUTE_WRITECOPY);

                if (!origExec) {
                    InjectionFinding finding;
                    finding.targetPid = pid;
                    finding.targetImageName = result.imageName;
                    finding.suspiciousAddress = mbi.BaseAddress;
                    finding.regionSize = mbi.RegionSize;
                    finding.memoryProtect = mbi.Protect;
                    finding.memoryType = mbi.Type;
                    finding.detectedAt = std::chrono::system_clock::now();
                    finding.type = InjectionType::RemoteThreadShell;
                    finding.riskLevel = InjectionRisk::Medium;
                    finding.confidenceScore = 50;
                    finding.mitreId = "T1055";
                    finding.description = "Private memory with escalated execute permission";
                    finding.evidence.push_back("Original protect: " + native::protectionToString(mbi.AllocationProtect));
                    finding.evidence.push_back("Current protect: " + native::protectionToString(mbi.Protect));
                    result.findings.push_back(std::move(finding));
                }
            }
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break;
    }
}

// ============================================================================
// Detect reflective DLL loading (PE header in private memory)
// ============================================================================
void InjectionDetector::detectReflectiveDll(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result) {
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && mbi.RegionSize >= 4096) {
            DWORD baseProt = mbi.Protect & 0xFF;
            bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                          baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);
            bool isRW = (baseProt == PAGE_READWRITE);

            if (isExec || isRW) {
                // Read first 1024 bytes to check for PE header
                BYTE header[1024] = {};
                if (readRemoteBytes(hProcess, mbi.BaseAddress, header, sizeof(header))) {
                    if (isPEHeader(header, sizeof(header))) {
                        InjectionFinding finding;
                        finding.targetPid = pid;
                        finding.targetImageName = result.imageName;
                        finding.suspiciousAddress = mbi.BaseAddress;
                        finding.regionSize = mbi.RegionSize;
                        finding.memoryProtect = mbi.Protect;
                        finding.memoryType = mbi.Type;
                        finding.detectedAt = std::chrono::system_clock::now();
                        finding.type = InjectionType::ReflectiveDllLoad;
                        finding.riskLevel = InjectionRisk::Critical;
                        finding.confidenceScore = 90;
                        finding.mitreId = "T1620";
                        finding.description = "PE header (MZ/PE) found in private memory — reflective DLL loading";
                        finding.evidence.push_back("Valid MZ+PE signature at 0x" +
                            std::to_string((ULONGLONG)mbi.BaseAddress));
                        finding.evidence.push_back("Region size: " + native::formatSize(mbi.RegionSize));
                        finding.evidence.push_back("Protection: " + native::protectionToString(mbi.Protect));
                        result.findings.push_back(std::move(finding));
                    }
                }
            }
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break;
    }
}

// ============================================================================
// Detect module stomping (image section with modified executable content)
// ============================================================================
void InjectionDetector::detectModuleStomping(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result) {
    // Module stomping: an IMAGE region whose .text section has been overwritten
    // We detect this by checking if executable IMAGE regions have unusually high entropy
    // or if the first bytes don't match expected PE section patterns

    HMODULE hMods[2048];
    DWORD cbNeeded;
    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
        return;

    for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
        MODULEINFO mi;
        wchar_t modName[MAX_PATH] = {};
        if (!GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) continue;
        GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);

        // Skip the main executable (first module) — it's expected to have code
        if (i == 0) continue;

        // Read the PE header to find .text section
        BYTE header[4096] = {};
        if (!readRemoteBytes(hProcess, mi.lpBaseOfDll, header, sizeof(header))) continue;
        if (!isPEHeader(header, sizeof(header))) continue;

        LONG e_lfanew = *reinterpret_cast<LONG*>(header + 0x3C);
        if (e_lfanew < 0 || (SIZE_T)e_lfanew + 0x18 > sizeof(header)) continue;

        // Get number of sections
        WORD numSections = *reinterpret_cast<WORD*>(header + e_lfanew + 6);
        WORD optHeaderSize = *reinterpret_cast<WORD*>(header + e_lfanew + 20);

        SIZE_T sectionStart = e_lfanew + 24 + optHeaderSize;
        if (sectionStart + numSections * 40 > sizeof(header)) continue;

        // Find .text section and check its entropy
        for (WORD s = 0; s < numSections; s++) {
            BYTE* sec = header + sectionStart + s * 40;
            char secName[9] = {};
            memcpy(secName, sec, 8);

            DWORD virtAddr = *reinterpret_cast<DWORD*>(sec + 12);
            DWORD rawSize = *reinterpret_cast<DWORD*>(sec + 16);
            DWORD chars = *reinterpret_cast<DWORD*>(sec + 36);

            // Check .text or executable sections
            bool isExecSection = (chars & IMAGE_SCN_MEM_EXECUTE) ||
                                 (strcmp(secName, ".text") == 0);
            if (!isExecSection || rawSize < 4096) continue;

            // Compute entropy of the section
            PVOID secAddr = reinterpret_cast<PBYTE>(mi.lpBaseOfDll) + virtAddr;
            double ent = quickEntropy(hProcess, secAddr, 8192);

            // Normal compiled code: entropy 5.5–6.5
            // Encrypted/packed code: entropy > 7.0
            if (ent > 7.2) {
                InjectionFinding finding;
                finding.targetPid = pid;
                finding.targetImageName = result.imageName;
                finding.suspiciousAddress = secAddr;
                finding.regionSize = rawSize;
                finding.memoryProtect = PAGE_EXECUTE_READ;
                finding.memoryType = MEM_IMAGE;
                finding.detectedAt = std::chrono::system_clock::now();
                finding.type = InjectionType::ModuleStomping;
                finding.riskLevel = InjectionRisk::Critical;
                finding.confidenceScore = 75;
                finding.mitreId = "T1055.001";
                finding.description = std::string("Module stomping: .text section of ") +
                    native::wstringToString(modName) + " has abnormally high entropy";
                finding.evidence.push_back(std::string("Module: ") + native::wstringToString(modName));
                finding.evidence.push_back("Section: " + std::string(secName));
                finding.evidence.push_back("Entropy: " + std::to_string(ent) + " (expected <7.0)");
                result.findings.push_back(std::move(finding));
            }
        }
    }
}

// ============================================================================
// Detect process hollowing (main image sections unmapped/replaced)
// ============================================================================
void InjectionDetector::detectProcessHollowing(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result) {
    // Process hollowing: the main image is created suspended, its sections are unmapped,
    // and new code is written. We detect this by checking if the main module's entry point
    // is in private memory instead of image memory.

    auto& api = native::NativeApi::instance();
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = api.NtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (status != STATUS_SUCCESS || !pbi.PebBaseAddress) return;

    // Read PEB to get ImageBaseAddress
    PEB pebLocal = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead))
        return;

    PVOID imageBase = pebLocal.Reserved3[1]; // ImageBaseAddress
    if (!imageBase) return;

    // Check the memory type at the image base
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQueryEx(hProcess, imageBase, &mbi, sizeof(mbi)) != sizeof(mbi)) return;

    // If the image base is private memory instead of image memory, it's hollowed
    if (mbi.Type == MEM_PRIVATE) {
        InjectionFinding finding;
        finding.targetPid = pid;
        finding.targetImageName = result.imageName;
        finding.suspiciousAddress = imageBase;
        finding.regionSize = mbi.RegionSize;
        finding.memoryProtect = mbi.Protect;
        finding.memoryType = mbi.Type;
        finding.detectedAt = std::chrono::system_clock::now();
        finding.type = InjectionType::ProcessHollowing;
        finding.riskLevel = InjectionRisk::Critical;
        finding.confidenceScore = 95;
        finding.mitreId = "T1055.012";
        finding.description = "Process image base is in PRIVATE memory (process hollowing)";
        finding.evidence.push_back("PEB ImageBase: 0x" + std::to_string((ULONGLONG)imageBase));
        finding.evidence.push_back("Memory type: PRIVATE (expected: IMAGE)");
        result.findings.push_back(std::move(finding));
    }
}

// ============================================================================
// Display
// ============================================================================
void InjectionDetector::displayResult(const ProcessInjectionResult& result) {
    std::cout << "\n=== Injection Scan: PID " << result.pid
              << " (" << native::wstringToString(result.imageName) << ") ===" << std::endl;
    std::cout << std::string(90, '-') << std::endl;

    if (!result.scanned) {
        std::cout << "  [!] Could not scan process (access denied)" << std::endl;
        return;
    }

    if (result.findings.empty()) {
        std::cout << "  [+] No injection indicators detected." << std::endl;
        return;
    }

    std::cout << "  [!] " << result.findings.size() << " finding(s)  Highest risk: "
              << injectionRiskToString(result.highestRisk) << std::endl;

    for (const auto& f : result.findings) {
        f.display();
    }
}

void InjectionDetector::displayFindings(const std::vector<InjectionFinding>& findings) {
    if (findings.empty()) {
        std::cout << "  [+] No injection findings." << std::endl;
        return;
    }
    for (const auto& f : findings) {
        f.display();
    }
}

} // namespace injection_intelligence
} // namespace zerophase
