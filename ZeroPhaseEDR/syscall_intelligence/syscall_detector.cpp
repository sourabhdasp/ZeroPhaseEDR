/*
 * ZeroPhase EDR - Syscall Intelligence: Detector Implementation
 *
 * Parses ntdll PE export table, reads syscall stubs, checks integrity,
 * and scans for direct syscall usage outside ntdll.
 */

#include "syscall_detector.hpp"

namespace zerophase {
namespace syscall_intelligence {

SyscallDetector::SyscallDetector() {}

// ============================================================================
// Get ntdll base address for a process
// ============================================================================
PVOID SyscallDetector::getNtdllBase(DWORD pid) {
    HANDLE hProcess = (pid == 0 || pid == GetCurrentProcessId())
        ? GetCurrentProcess()
        : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return nullptr;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    PVOID ntdllBase = nullptr;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            wchar_t name[MAX_PATH] = {};
            GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH);
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower == L"ntdll.dll") {
                ntdllBase = hMods[i];
                break;
            }
        }
    }

    if (hProcess != GetCurrentProcess()) CloseHandle(hProcess);
    return ntdllBase;
}

// ============================================================================
// Parse ntdll PE export table to find all Nt* functions
// ============================================================================
std::vector<SyscallDetector::ExportEntry> SyscallDetector::parseNtdllExports(
    HANDLE hProcess, PVOID ntdllBase)
{
    std::vector<ExportEntry> exports;
    if (!ntdllBase) return exports;

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, ntdllBase, &dosHeader, sizeof(dosHeader), &bytesRead))
        return exports;
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return exports;

    // Read NT headers
    IMAGE_NT_HEADERS64 ntHeaders = {};
    PVOID ntHeaderAddr = reinterpret_cast<PBYTE>(ntdllBase) + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead))
        return exports;
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return exports;

    // Get export directory
    auto& exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) return exports;

    IMAGE_EXPORT_DIRECTORY expDir = {};
    PVOID expDirAddr = reinterpret_cast<PBYTE>(ntdllBase) + exportDir.VirtualAddress;
    if (!ReadProcessMemory(hProcess, expDirAddr, &expDir, sizeof(expDir), &bytesRead))
        return exports;

    // Read function RVAs, name RVAs, and ordinals
    std::vector<DWORD> funcRVAs(expDir.NumberOfFunctions);
    std::vector<DWORD> nameRVAs(expDir.NumberOfNames);
    std::vector<WORD> ordinals(expDir.NumberOfNames);

    ReadProcessMemory(hProcess,
        reinterpret_cast<PBYTE>(ntdllBase) + expDir.AddressOfFunctions,
        funcRVAs.data(), funcRVAs.size() * sizeof(DWORD), &bytesRead);
    ReadProcessMemory(hProcess,
        reinterpret_cast<PBYTE>(ntdllBase) + expDir.AddressOfNames,
        nameRVAs.data(), nameRVAs.size() * sizeof(DWORD), &bytesRead);
    ReadProcessMemory(hProcess,
        reinterpret_cast<PBYTE>(ntdllBase) + expDir.AddressOfNameOrdinals,
        ordinals.data(), ordinals.size() * sizeof(WORD), &bytesRead);

    // Enumerate named exports, keep only Nt* and Zw* functions
    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        char name[256] = {};
        ReadProcessMemory(hProcess,
            reinterpret_cast<PBYTE>(ntdllBase) + nameRVAs[i],
            name, sizeof(name) - 1, &bytesRead);

        // Filter to Nt* and Zw* functions (syscall wrappers)
        if ((name[0] == 'N' && name[1] == 't') ||
            (name[0] == 'Z' && name[1] == 'w')) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            ExportEntry entry;
            entry.name = name;
            entry.rva = funcRVA;
            entry.address = reinterpret_cast<PBYTE>(ntdllBase) + funcRVA;
            exports.push_back(std::move(entry));
        }
    }

    return exports;
}

// ============================================================================
// Verify a single syscall stub
// Expected x64 pattern:
//   4C 8B D1          mov r10, rcx
//   B8 XX XX 00 00    mov eax, <syscall_num>
// ============================================================================
StubStatus SyscallDetector::verifyStub(HANDLE hProcess, PVOID stubAddress,
    BYTE* rawBytes, DWORD& outSyscallNum, PVOID& outHookTarget)
{
    outSyscallNum = 0;
    outHookTarget = nullptr;

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, stubAddress, rawBytes, 16, &bytesRead) || bytesRead < 16)
        return StubStatus::Unknown;

    // Check for standard syscall stub: 4C 8B D1 B8 XX XX 00 00
    if (rawBytes[0] == 0x4C && rawBytes[1] == 0x8B && rawBytes[2] == 0xD1 &&
        rawBytes[3] == 0xB8) {
        // Extract syscall number (little-endian DWORD at offset 4)
        outSyscallNum = *reinterpret_cast<DWORD*>(rawBytes + 4);
        return StubStatus::Clean;
    }

    // Check for common hook patterns:
    // JMP rel32:  E9 XX XX XX XX
    if (rawBytes[0] == 0xE9) {
        INT32 offset = *reinterpret_cast<INT32*>(rawBytes + 1);
        outHookTarget = reinterpret_cast<PBYTE>(stubAddress) + 5 + offset;
        return StubStatus::Hooked;
    }

    // JMP [rip+disp32]:  FF 25 XX XX XX XX
    if (rawBytes[0] == 0xFF && rawBytes[1] == 0x25) {
        INT32 disp = *reinterpret_cast<INT32*>(rawBytes + 2);
        PVOID ptrAddr = reinterpret_cast<PBYTE>(stubAddress) + 6 + disp;
        PVOID target = nullptr;
        if (ReadProcessMemory(hProcess, ptrAddr, &target, sizeof(target), &bytesRead))
            outHookTarget = target;
        return StubStatus::Hooked;
    }

    // MOV RAX, imm64; JMP RAX:  48 B8 XX XX XX XX XX XX XX XX FF E0
    if (rawBytes[0] == 0x48 && rawBytes[1] == 0xB8 && rawBytes[10] == 0xFF && rawBytes[11] == 0xE0) {
        outHookTarget = *reinterpret_cast<PVOID*>(rawBytes + 2);
        return StubStatus::Hooked;
    }

    // PUSH addr; RET:  68 XX XX XX XX C3 (32-bit-like, unusual on x64)
    if (rawBytes[0] == 0x68 && rawBytes[5] == 0xC3) {
        return StubStatus::Hooked;
    }

    // If first 3 bytes aren't the expected mov r10,rcx but aren't a known hook
    // it could be a partial patch
    if (rawBytes[0] != 0x4C || rawBytes[1] != 0x8B || rawBytes[2] != 0xD1) {
        // Still try to extract syscall number if B8 is at offset 3
        if (rawBytes[3] == 0xB8) {
            outSyscallNum = *reinterpret_cast<DWORD*>(rawBytes + 4);
        }
        return StubStatus::Patched;
    }

    return StubStatus::Unknown;
}

// ============================================================================
// Resolve which module an address belongs to
// ============================================================================
std::string SyscallDetector::resolveModule(HANDLE hProcess, PVOID address) {
    if (!address) return "";

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO mi;
            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                if (address >= mi.lpBaseOfDll &&
                    address < reinterpret_cast<PBYTE>(mi.lpBaseOfDll) + mi.SizeOfImage) {
                    wchar_t name[MAX_PATH] = {};
                    GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH);
                    return native::wstringToString(name);
                }
            }
        }
    }
    return "<unbacked>";
}

// ============================================================================
// Build syscall table from ntdll exports
// ============================================================================
std::vector<SyscallEntry> SyscallDetector::buildSyscallTable(DWORD pid) {
    std::vector<SyscallEntry> table;

    bool isSelf = (pid == 0 || pid == GetCurrentProcessId());
    HANDLE hProcess = isSelf ? GetCurrentProcess() :
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return table;

    PVOID ntdllBase = getNtdllBase(pid);
    if (!ntdllBase) {
        if (!isSelf) CloseHandle(hProcess);
        return table;
    }

    auto exports = parseNtdllExports(hProcess, ntdllBase);

    for (const auto& exp : exports) {
        // Only process Nt* functions (Zw* are duplicates pointing to same code)
        if (exp.name[0] != 'N' || exp.name[1] != 't') continue;

        SyscallEntry entry;
        entry.functionName = exp.name;
        entry.address = exp.address;
        entry.rva = reinterpret_cast<PVOID>((ULONG_PTR)exp.rva);

        DWORD sysNum = 0;
        PVOID hookTarget = nullptr;
        entry.status = verifyStub(hProcess, exp.address, entry.rawBytes, sysNum, hookTarget);
        entry.syscallNumber = sysNum;
        entry.hookTarget = hookTarget;

        if (entry.status == StubStatus::Hooked && hookTarget) {
            entry.hookModule = resolveModule(hProcess, hookTarget);
            entry.hookDescription = "Hooked -> " + entry.hookModule;
        }

        table.push_back(std::move(entry));
    }

    if (!isSelf) CloseHandle(hProcess);

    // Sort by syscall number
    std::sort(table.begin(), table.end(),
        [](const SyscallEntry& a, const SyscallEntry& b) {
            return a.syscallNumber < b.syscallNumber;
        });

    return table;
}

// ============================================================================
// Scan for direct syscall instructions outside ntdll
// ============================================================================
std::vector<DirectSyscallFinding> SyscallDetector::scanDirectSyscalls(DWORD pid) {
    std::vector<DirectSyscallFinding> findings;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return findings;

    // Get ntdll range
    PVOID ntdllBase = nullptr;
    SIZE_T ntdllSize = 0;
    {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                wchar_t name[MAX_PATH] = {};
                MODULEINFO mi;
                GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH);
                std::wstring lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                if (lower == L"ntdll.dll" && GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    ntdllBase = mi.lpBaseOfDll;
                    ntdllSize = mi.SizeOfImage;
                    break;
                }
            }
        }
    }

    // Get process image name
    std::wstring imageName;
    {
        wchar_t path[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &sz)) {
            std::wstring full(path, sz);
            auto pos = full.find_last_of(L'\\');
            imageName = (pos != std::wstring::npos) ? full.substr(pos + 1) : full;
        }
    }

    // Scan all executable committed regions for syscall/sysenter instructions
    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD)) {
            DWORD baseProt = mbi.Protect & 0xFF;
            bool isExec = (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
                          baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY);

            if (isExec && mbi.RegionSize >= 2) {
                // Check if this region is inside ntdll
                bool isNtdll = (ntdllBase &&
                    mbi.BaseAddress >= ntdllBase &&
                    mbi.BaseAddress < reinterpret_cast<PBYTE>(ntdllBase) + ntdllSize);

                // Read the region (cap at 64KB to avoid huge reads)
                SIZE_T readSize = (mbi.RegionSize < 65536) ? mbi.RegionSize : 65536;
                std::vector<BYTE> buf(readSize);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(hProcess, mbi.BaseAddress, buf.data(), readSize, &bytesRead)
                    && bytesRead >= 2) {
                    int syscallCount = 0;
                    int sysenterCount = 0;

                    for (SIZE_T i = 0; i < bytesRead - 1; i++) {
                        // 0F 05 = syscall
                        if (buf[i] == 0x0F && buf[i + 1] == 0x05) syscallCount++;
                        // 0F 34 = sysenter
                        if (buf[i] == 0x0F && buf[i + 1] == 0x34) sysenterCount++;
                    }

                    // Report syscall/sysenter instructions found OUTSIDE ntdll
                    if (!isNtdll && (syscallCount > 0 || sysenterCount > 0)) {
                        DirectSyscallFinding finding;
                        finding.pid = pid;
                        finding.imageName = imageName;
                        finding.address = mbi.BaseAddress;
                        finding.regionSize = mbi.RegionSize;
                        finding.memoryType = mbi.Type;
                        finding.memoryProtect = mbi.Protect;
                        finding.syscallCount = syscallCount;
                        finding.sysenterCount = sysenterCount;
                        finding.inNtdll = false;

                        // Try to identify which module
                        wchar_t mappedName[MAX_PATH] = {};
                        if (GetMappedFileNameW(hProcess, mbi.BaseAddress, mappedName, MAX_PATH)) {
                            std::wstring full = mappedName;
                            auto pos = full.find_last_of(L'\\');
                            finding.moduleName = (pos != std::wstring::npos) ? full.substr(pos + 1) : full;
                        }

                        if (mbi.Type == MEM_PRIVATE) {
                            finding.description = "Direct syscall in PRIVATE memory (evasion technique)";
                        } else {
                            finding.description = "Syscall instruction outside ntdll in " +
                                native::wstringToString(finding.moduleName);
                        }

                        findings.push_back(std::move(finding));
                    }
                }
            }
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);
    return findings;
}

// ============================================================================
// Verify ntdll integrity: compare in-memory vs on-disk
// ============================================================================
int SyscallDetector::verifyNtdllIntegrity(DWORD pid) {
    bool isSelf = (pid == 0 || pid == GetCurrentProcessId());
    HANDLE hProcess = isSelf ? GetCurrentProcess() :
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return -1;

    PVOID ntdllBase = getNtdllBase(pid);
    if (!ntdllBase) {
        if (!isSelf) CloseHandle(hProcess);
        return -1;
    }

    // Read on-disk ntdll
    std::wstring ntdllPath = L"C:\\Windows\\System32\\ntdll.dll";
    HANDLE hFile = CreateFileW(ntdllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (!isSelf) CloseHandle(hProcess);
        return -1;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    std::vector<BYTE> diskData(fileSize);
    DWORD bytesRead = 0;
    ReadFile(hFile, diskData.data(), fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);

    if (bytesRead < sizeof(IMAGE_DOS_HEADER)) {
        if (!isSelf) CloseHandle(hProcess);
        return -1;
    }

    // Parse on-disk PE to find .text section
    auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(diskData.data());
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        if (!isSelf) CloseHandle(hProcess);
        return -1;
    }
    auto* ntHdr = reinterpret_cast<IMAGE_NT_HEADERS64*>(diskData.data() + dosHdr->e_lfanew);

    WORD numSections = ntHdr->FileHeader.NumberOfSections;
    auto* sections = IMAGE_FIRST_SECTION(ntHdr);

    int patchCount = 0;

    for (WORD i = 0; i < numSections; i++) {
        // Only check executable sections
        if (!(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        DWORD virtAddr = sections[i].VirtualAddress;
        DWORD rawAddr = sections[i].PointerToRawData;
        DWORD rawSize = sections[i].SizeOfRawData;

        if (rawAddr + rawSize > bytesRead) continue;

        // Read the in-memory version
        SIZE_T memReadSize = rawSize;
        if (memReadSize > 1024 * 1024) memReadSize = 1024 * 1024; // Cap at 1MB

        std::vector<BYTE> memData(memReadSize);
        SIZE_T memBytesRead = 0;
        PVOID memAddr = reinterpret_cast<PBYTE>(ntdllBase) + virtAddr;

        if (ReadProcessMemory(hProcess, memAddr, memData.data(), memReadSize, &memBytesRead)
            && memBytesRead > 0) {
            // Compare byte by byte
            SIZE_T compareSize = (memBytesRead < rawSize) ? memBytesRead : rawSize;
            for (SIZE_T j = 0; j < compareSize; j++) {
                if (memData[j] != diskData[rawAddr + j]) {
                    patchCount++;
                }
            }
        }
    }

    if (!isSelf) CloseHandle(hProcess);
    return patchCount;
}

// ============================================================================
// Full process scan
// ============================================================================
SyscallScanResult SyscallDetector::scanProcess(DWORD pid) {
    SyscallScanResult result;
    result.pid = pid;

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

    // Build syscall table
    result.syscallTable = buildSyscallTable(pid);
    result.totalFunctions = static_cast<int>(result.syscallTable.size());
    for (const auto& e : result.syscallTable) {
        switch (e.status) {
            case StubStatus::Clean:   result.cleanCount++; break;
            case StubStatus::Hooked:  result.hookedCount++; break;
            case StubStatus::Patched: result.patchedCount++; break;
            default: break;
        }
    }

    // Scan for direct syscalls
    result.directSyscalls = scanDirectSyscalls(pid);

    // Verify ntdll integrity
    result.ntdllPatchCount = verifyNtdllIntegrity(pid);
    result.ntdllIntact = (result.ntdllPatchCount == 0);

    result.scanned = true;
    return result;
}

// ============================================================================
// Display
// ============================================================================
void SyscallDetector::displaySyscallTable(const std::vector<SyscallEntry>& table, bool hookedOnly) {
    std::cout << "\n=== Syscall Table ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    printf("  %-4s  %-6s  %-8s  %-40s %s\n", "SSN", "Hex", "Status", "Function", "Hook Target");
    std::cout << std::string(80, '-') << std::endl;

    int displayed = 0;
    for (const auto& e : table) {
        if (hookedOnly && e.status == StubStatus::Clean) continue;
        e.displayCompact();
        displayed++;
    }
    std::cout << "\n  Total: " << displayed << " / " << table.size() << " functions" << std::endl;
}

void SyscallDetector::displayScanResult(const SyscallScanResult& result) {
    std::cout << "\n=== Syscall Scan: PID " << result.pid
              << " (" << native::wstringToString(result.imageName) << ") ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    if (!result.scanned) {
        std::cout << "  [!] Could not scan (access denied)" << std::endl;
        return;
    }

    // Stub integrity
    printf("  Syscall stubs: %d total  Clean: %d  Hooked: %d  Patched: %d\n",
        result.totalFunctions, result.cleanCount, result.hookedCount, result.patchedCount);

    if (result.hookedCount > 0) {
        std::cout << "\n  [!] HOOKED functions:" << std::endl;
        for (const auto& e : result.syscallTable) {
            if (e.status == StubStatus::Hooked)
                e.displayCompact();
        }
    }

    // ntdll integrity
    if (result.ntdllPatchCount >= 0) {
        printf("\n  ntdll integrity: %s (%d modified bytes)\n",
            result.ntdllIntact ? "INTACT" : "MODIFIED",
            result.ntdllPatchCount);
    }

    // Direct syscalls
    if (!result.directSyscalls.empty()) {
        std::cout << "\n  [!] Direct syscall instructions found outside ntdll:" << std::endl;
        for (const auto& ds : result.directSyscalls) {
            printf("    0x%016llX  syscall:%d sysenter:%d  %s  %s  %s\n",
                (ULONGLONG)ds.address,
                ds.syscallCount, ds.sysenterCount,
                native::protectionToString(ds.memoryProtect).c_str(),
                native::memoryTypeToString(ds.memoryType).c_str(),
                ds.description.c_str());
        }
    } else {
        std::cout << "\n  [+] No direct syscall usage detected outside ntdll." << std::endl;
    }
}

void SyscallDetector::displayDirectSyscalls(const std::vector<DirectSyscallFinding>& findings) {
    if (findings.empty()) {
        std::cout << "  [+] No direct syscall findings." << std::endl;
        return;
    }
    for (const auto& f : findings) {
        printf("  PID %u: 0x%016llX  syscall:%d sysenter:%d  %ls  %s\n",
            f.pid, (ULONGLONG)f.address, f.syscallCount, f.sysenterCount,
            f.moduleName.c_str(), f.description.c_str());
    }
}

} // namespace syscall_intelligence
} // namespace zerophase
