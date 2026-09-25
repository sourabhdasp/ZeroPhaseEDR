/*
 * ZeroPhase EDR - Entry Point
 *
 * Main console application with menu-driven interface for
 * endpoint telemetry collection and threat detection.
 *
 * Phase 1: Process Intelligence (user-mode)
 */

#include "native.hpp"
#include "process_intelligence/process_info.hpp"
#include "process_intelligence/process_database.hpp"
#include "process_intelligence/lineage_detector.hpp"
#include "process_intelligence/session_tracker.hpp"
#include "thread_intelligence/thread_info.hpp"
#include "thread_intelligence/thread_database.hpp"
#include "thread_intelligence/thread_monitor.hpp"
#include "thread_intelligence/stack_walker.hpp"
#include "memory_intelligence/memory_info.hpp"
#include "memory_intelligence/memory_database.hpp"
#include "memory_intelligence/memory_monitor.hpp"
#include "memory_intelligence/entropy_analysis.hpp"
#include "dll_intelligence/dll_info.hpp"
#include "dll_intelligence/dll_database.hpp"
#include "dll_intelligence/dll_monitor.hpp"
#include "commandline_intelligence/commandline_info.hpp"
#include "commandline_intelligence/commandline_analyzer.hpp"
#include "commandline_intelligence/commandline_database.hpp"
#include "commandline_intelligence/commandline_monitor.hpp"
#include "injection_intelligence/injection_info.hpp"
#include "injection_intelligence/injection_detector.hpp"
#include "injection_intelligence/injection_database.hpp"
#include "injection_intelligence/injection_monitor.hpp"
#include "syscall_intelligence/syscall_info.hpp"
#include "syscall_intelligence/syscall_detector.hpp"
#include "syscall_intelligence/syscall_database.hpp"
#include "syscall_intelligence/syscall_monitor.hpp"
#include "kernel_intelligence/kernel_info.hpp"
#include "kernel_intelligence/kernel_database.hpp"
#include "detection_intelligence/detection_info.hpp"
#include "detection_intelligence/detection_engine.hpp"
#include "forensics_intelligence/forensics_info.hpp"
#include "production_intelligence/production_info.hpp"

// Global Process Intelligence components
static zerophase::process_intelligence::ProcessDatabase g_processDb;
static zerophase::process_intelligence::LineageDetector g_lineageDetector;
static zerophase::process_intelligence::SessionTracker g_sessionTracker;

// Global Thread Intelligence components
static zerophase::thread_intelligence::ThreadDatabase g_threadDb;
static zerophase::thread_intelligence::ThreadMonitor g_threadMonitor(g_threadDb);
static zerophase::thread_intelligence::StackWalker g_stackWalker;

// Global Memory Intelligence components
static zerophase::memory_intelligence::MemoryDatabase g_memoryDb;
static zerophase::memory_intelligence::MemoryMonitor g_memoryMonitor(g_memoryDb);
static zerophase::memory_intelligence::EntropyScanner g_entropyScanner;

// Global DLL Intelligence components
static zerophase::dll_intelligence::DllDatabase g_dllDb;
static zerophase::dll_intelligence::DllMonitor g_dllMonitor(g_dllDb);

// Global Command Line Intelligence components
static zerophase::commandline_intelligence::CommandLineDatabase g_cmdDb;
static zerophase::commandline_intelligence::CommandLineMonitor g_cmdMonitor(g_cmdDb);

// Global Injection Intelligence components
static zerophase::injection_intelligence::InjectionDatabase g_injectionDb;
static zerophase::injection_intelligence::InjectionMonitor g_injectionMonitor(g_injectionDb);

// Global Syscall Intelligence components
static zerophase::syscall_intelligence::SyscallDatabase g_syscallDb;
static zerophase::syscall_intelligence::SyscallMonitor g_syscallMonitor(g_syscallDb);

// Global Kernel Intelligence
static zerophase::kernel_intelligence::KernelDatabase g_kernelDb;

// Global Detection Intelligence
static zerophase::detection_intelligence::DetectionEngine g_detectionEngine;

// Global Forensics Intelligence
static zerophase::forensics_intelligence::ForensicsEngine g_forensicsEngine;

// Global Production Intelligence
static zerophase::production_intelligence::ProductionMonitor g_productionMonitor;

// ============================================================================
// Banner
// ============================================================================
void printBanner() {
    std::cout << R"(
  ╔══════════════════════════════════════════════════════════════╗
  ║                                                              ║
  ║     ███████╗███████╗██████╗  ██████╗ ██████╗ ██╗  ██╗       ║
  ║     ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║  ██║       ║
  ║       ███╔╝ █████╗  ██████╔╝██║   ██║██████╔╝███████║       ║
  ║      ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██╔═══╝ ██╔══██║       ║
  ║     ███████╗███████╗██║  ██║╚██████╔╝██║     ██║  ██║       ║
  ║     ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝       ║
  ║                                                              ║
  ║           E D R  -  Endpoint Detection & Response            ║
  ║                    [ User-Mode Agent ]                       ║
  ║                                                              ║
  ╚══════════════════════════════════════════════════════════════╝
)" << std::endl;
}

// ============================================================================
// Initialization
// ============================================================================
bool initializeEDR() {
    std::cout << "[*] Initializing ZeroPhase EDR..." << std::endl;

    // Enable SeDebugPrivilege for full process access
    if (native::enablePrivilege(SE_DEBUG_NAME)) {
        std::cout << "[+] SeDebugPrivilege enabled" << std::endl;
    } else {
        std::cout << "[-] SeDebugPrivilege not available (run as Administrator for full access)" << std::endl;
    }

    // Initialize Native API
    auto& api = native::NativeApi::instance();
    if (api.isInitialized()) {
        std::cout << "[+] Native API (ntdll) resolved successfully" << std::endl;
        std::cout << "    NtQuerySystemInformation  = " << (api.NtQuerySystemInformation ? "OK" : "FAIL") << std::endl;
        std::cout << "    NtQueryInformationProcess = " << (api.NtQueryInformationProcess ? "OK" : "FAIL") << std::endl;
        std::cout << "    NtQueryInformationThread  = " << (api.NtQueryInformationThread ? "OK" : "FAIL") << std::endl;
        std::cout << "    NtQueryVirtualMemory      = " << (api.NtQueryVirtualMemory ? "OK" : "FAIL") << std::endl;
        std::cout << "    NtReadVirtualMemory       = " << (api.NtReadVirtualMemory ? "OK" : "FAIL") << std::endl;
    } else {
        std::cout << "[!] CRITICAL: Failed to resolve Native API functions" << std::endl;
        return false;
    }

    std::cout << "[+] ZeroPhase EDR initialized at " << native::getCurrentTimestamp() << std::endl;
    std::cout << "[+] PID: " << GetCurrentProcessId() << std::endl;
    return true;
}

// ============================================================================
// Main Menu
// ============================================================================
void printMenu() {
    std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
    std::cout << "  │           ZeroPhase EDR - Main Menu          │" << std::endl;
    std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
    std::cout << "  │  [1] Process List                           │" << std::endl;
    std::cout << "  │  [2] Process Detail (by PID)                │" << std::endl;
    std::cout << "  │  [3] Module List (by PID)                   │" << std::endl;
    std::cout << "  │  [4] Memory Map (by PID)                    │" << std::endl;
    std::cout << "  │  [5] Thread List (by PID)                   │" << std::endl;
    std::cout << "  │  [6] PEB Info (by PID)                      │" << std::endl;
    std::cout << "  │  [7] Kernel Modules                         │" << std::endl;
    std::cout << "  │  [8] System Overview                        │" << std::endl;
    std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
    std::cout << "  │  [10] Process Intelligence (Phase 1)        │" << std::endl;
    std::cout << "  │  [11] Thread Intelligence  (Phase 2)        │" << std::endl;
    std::cout << "  │  [12] Memory Intelligence  (Phase 3)        │" << std::endl;
    std::cout << "  │  [13] DLL Intelligence     (Phase 4)        │" << std::endl;
    std::cout << "  │  [14] CmdLine Intelligence (Phase 5)        │" << std::endl;
    std::cout << "  │  [15] Injection Intelligence(Phase 6)       │" << std::endl;
    std::cout << "  │  [16] Syscall Intelligence  (Phase 7)       │" << std::endl;
    std::cout << "  │  [17] Kernel Intelligence   (Phase 8)       │" << std::endl;
    std::cout << "  │  [18] Detection Engine      (Phase 9)       │" << std::endl;
    std::cout << "  │  [19] Forensics             (Phase 10)      │" << std::endl;
    std::cout << "  │  [20] Production/Health     (Phase 11)      │" << std::endl;
    std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
    std::cout << "  │  [0] Exit                                   │" << std::endl;
    std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
    std::cout << "  Select> ";
}

// ============================================================================
// Helper: Ask for a PID from the user
// ============================================================================
DWORD askForPid() {
    std::cout << "  Enter PID: ";
    DWORD pid = 0;
    if (!(std::cin >> pid)) {
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        return 0;
    }
    return pid;
}

// ============================================================================
// Process List - Enumerate all processes via Native API
// ============================================================================
void processList() {
    std::cout << "\n=== Process List (NtQuerySystemInformation) ===" << std::endl;
    std::cout << std::string(120, '-') << std::endl;
    printf("  %-8s %-8s %-6s %-6s %-4s %-10s %-10s %s\n",
        "PID", "PPID", "Thds", "Hndls", "Sess", "WorkSet", "Private", "Image");
    std::cout << std::string(120, '-') << std::endl;

    auto& api = native::NativeApi::instance();
    ULONG bufferSize = 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 64 * 1024 * 1024);

    if (status != STATUS_SUCCESS) {
        std::cout << "  [!] NtQuerySystemInformation failed: 0x"
                  << std::hex << status << std::dec << std::endl;
        return;
    }

    int count = 0;
    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        std::string name = native::wstringToString(native::unicodeToWstring(proc->ImageName));
        if (name.empty()) name = "[System Process]";

        printf("  %-8u %-8u %-6u %-6u %-4u %-10s %-10s %s\n",
            HandleToUlong(proc->UniqueProcessId),
            HandleToUlong(proc->InheritedFromUniqueProcessId),
            proc->NumberOfThreads,
            proc->HandleCount,
            proc->SessionId,
            native::formatSize(proc->WorkingSetSize).c_str(),
            native::formatSize(proc->PrivatePageCount).c_str(),
            name.c_str());
        count++;

        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }
    std::cout << std::string(120, '-') << std::endl;
    std::cout << "  Total: " << count << " processes" << std::endl;
}

// ============================================================================
// Process Detail - Show rich information for a single process
// ============================================================================
std::wstring getProcessImagePath(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return L"";
    wchar_t path[MAX_PATH * 2] = {};
    DWORD size = MAX_PATH * 2;
    std::wstring result;
    if (QueryFullProcessImageNameW(hProcess, 0, path, &size))
        result.assign(path, size);
    CloseHandle(hProcess);
    return result;
}

std::wstring getProcessCommandLine(DWORD pid) {
    auto& api = native::NativeApi::instance();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return L"";

    ULONG bufSize = 4096;
    std::vector<BYTE> buf(bufSize);
    NTSTATUS status = api.NtQueryInformationProcess(hProcess,
        native::ProcessCommandLineInformation, buf.data(), bufSize, &bufSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
        buf.resize(bufSize);
        status = api.NtQueryInformationProcess(hProcess,
            native::ProcessCommandLineInformation, buf.data(), bufSize, &bufSize);
    }
    std::wstring cmdline;
    if (status == STATUS_SUCCESS) {
        auto* ustr = reinterpret_cast<UNICODE_STRING*>(buf.data());
        cmdline = native::unicodeToWstring(*ustr);
    }
    CloseHandle(hProcess);
    return cmdline;
}

std::string getProcessIntegrityLevel(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return "Unknown";
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return "Unknown";
    }
    DWORD size = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &size);
    if (size == 0) { CloseHandle(hToken); CloseHandle(hProcess); return "Unknown"; }
    std::vector<BYTE> buffer(size);
    auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
    std::string level = "Unknown";
    if (GetTokenInformation(hToken, TokenIntegrityLevel, til, size, &size)) {
        DWORD sid = *GetSidSubAuthority(til->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
        if (sid < SECURITY_MANDATORY_LOW_RID)          level = "Untrusted";
        else if (sid < SECURITY_MANDATORY_MEDIUM_RID)   level = "Low";
        else if (sid < SECURITY_MANDATORY_HIGH_RID)     level = "Medium";
        else if (sid < SECURITY_MANDATORY_SYSTEM_RID)   level = "High";
        else                                            level = "System";
    }
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return level;
}

bool isProcessElevated(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return false;
    }
    TOKEN_ELEVATION elev;
    DWORD size = sizeof(elev);
    bool elevated = false;
    if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &size))
        elevated = elev.TokenIsElevated != 0;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return elevated;
}

void processDetail(DWORD pid) {
    std::cout << "\n=== Process Detail: PID " << pid << " ===" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    auto& api = native::NativeApi::instance();
    ULONG bufferSize = 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 64 * 1024 * 1024);

    if (status != STATUS_SUCCESS) {
        std::cout << "  [!] Failed to query system information" << std::endl;
        return;
    }

    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    bool found = false;
    while (true) {
        if (HandleToUlong(proc->UniqueProcessId) == pid) {
            found = true;
            std::string name = native::wstringToString(native::unicodeToWstring(proc->ImageName));
            std::wstring fullPath = getProcessImagePath(pid);
            std::wstring cmdLine = getProcessCommandLine(pid);
            std::string integrity = getProcessIntegrityLevel(pid);
            bool elevated = isProcessElevated(pid);

            std::cout << "  Image Name:    " << (name.empty() ? "[System Process]" : name) << std::endl;
            std::cout << "  Full Path:     " << native::wstringToString(fullPath) << std::endl;
            std::cout << "  Command Line:  " << native::wstringToString(cmdLine) << std::endl;
            std::cout << "  PID:           " << pid << std::endl;
            std::cout << "  Parent PID:    " << HandleToUlong(proc->InheritedFromUniqueProcessId) << std::endl;
            std::cout << "  Session ID:    " << proc->SessionId << std::endl;
            std::cout << "  Threads:       " << proc->NumberOfThreads << std::endl;
            std::cout << "  Handles:       " << proc->HandleCount << std::endl;
            std::cout << "  Priority:      " << proc->BasePriority << std::endl;
            std::cout << "  Working Set:   " << native::formatSize(proc->WorkingSetSize) << std::endl;
            std::cout << "  Private Bytes: " << native::formatSize(proc->PrivatePageCount) << std::endl;
            std::cout << "  Virtual Size:  " << native::formatSize(proc->VirtualSize) << std::endl;
            std::cout << "  Integrity:     " << integrity << std::endl;
            std::cout << "  Elevated:      " << (elevated ? "YES" : "No") << std::endl;
            if (proc->CreateTime.QuadPart != 0)
                std::cout << "  Created:       " << native::formatTimestamp(proc->CreateTime) << std::endl;
            break;
        }
        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }
    if (!found) std::cout << "  Process not found." << std::endl;
}

// ============================================================================
// Module List - Enumerate loaded modules for a process
// ============================================================================
void moduleList(DWORD pid) {
    std::cout << "\n=== Loaded Modules: PID " << pid << " ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        // Fallback to PSAPI
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            std::cout << "  [!] Cannot access process (access denied or invalid PID)" << std::endl;
            return;
        }

        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            printf("  %-18s %-10s %-30s %s\n", "Base Address", "Size", "Module", "Path");
            std::cout << "  " << std::string(108, '-') << std::endl;

            DWORD count = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                wchar_t modName[MAX_PATH] = {}, modPath[MAX_PATH] = {};
                MODULEINFO mi = {};
                GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);
                GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH);
                GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi));
                printf("  0x%016llX %-10s %-30ls %ls\n",
                    (ULONGLONG)mi.lpBaseOfDll,
                    native::formatSize(mi.SizeOfImage).c_str(),
                    modName, modPath);
            }
            std::cout << "\n  Total: " << count << " modules" << std::endl;
        } else {
            std::cout << "  [!] EnumProcessModulesEx failed" << std::endl;
        }
        CloseHandle(hProcess);
        return;
    }

    printf("  %-18s %-10s %-30s %s\n", "Base Address", "Size", "Module", "Path");
    std::cout << "  " << std::string(108, '-') << std::endl;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);
    int count = 0;

    if (Module32FirstW(snap, &me)) {
        do {
            printf("  0x%016llX %-10s %-30ls %ls\n",
                (ULONGLONG)me.modBaseAddr,
                native::formatSize(me.modBaseSize).c_str(),
                me.szModule, me.szExePath);
            count++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    std::cout << "\n  Total: " << count << " modules" << std::endl;
}

// ============================================================================
// Memory Map - Enumerate virtual memory regions with suspicious detection
// ============================================================================
void memoryMap(DWORD pid) {
    std::cout << "\n=== Memory Map: PID " << pid << " ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cout << "  [!] Cannot access process (access denied or invalid PID)" << std::endl;
        return;
    }

    MEMORY_BASIC_INFORMATION mbi = {};
    PVOID address = nullptr;
    int totalRegions = 0, commitRegions = 0, suspiciousCount = 0;
    SIZE_T totalCommitted = 0, totalRwx = 0, totalExec = 0;

    struct SuspiciousRegion {
        PVOID  addr;
        SIZE_T size;
        DWORD  protect;
        DWORD  type;
        std::string reason;
    };
    std::vector<SuspiciousRegion> suspicious;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        totalRegions++;

        if (mbi.State == MEM_COMMIT) {
            commitRegions++;
            totalCommitted += mbi.RegionSize;
            DWORD base = mbi.Protect & 0xFF;

            bool isExec = (base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
                          base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY);
            if (isExec) totalExec += mbi.RegionSize;

            // Check for RWX
            if (base == PAGE_EXECUTE_READWRITE) {
                totalRwx += mbi.RegionSize;
                suspicious.push_back({mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type,
                    "RWX (Read-Write-Execute) memory"});
            }
            // Executable private memory with no backing file
            else if (isExec && mbi.Type == MEM_PRIVATE) {
                wchar_t fileName[MAX_PATH] = {};
                if (!GetMappedFileNameW(hProcess, mbi.BaseAddress, fileName, MAX_PATH)) {
                    suspicious.push_back({mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type,
                        "Executable private memory (no backing file)"});
                }
            }
        }

        address = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        if (address < mbi.BaseAddress) break;
    }

    CloseHandle(hProcess);

    // Summary
    std::cout << "  Memory Summary:" << std::endl;
    std::cout << "    Committed:     " << native::formatSize(totalCommitted)
              << " (" << commitRegions << " regions)" << std::endl;
    std::cout << "    Executable:    " << native::formatSize(totalExec) << std::endl;
    if (totalRwx > 0) {
        std::cout << "    [!] RWX:       " << native::formatSize(totalRwx)
                  << " *** SUSPICIOUS ***" << std::endl;
    }
    std::cout << "    Total regions: " << totalRegions << std::endl;

    // Suspicious regions
    if (!suspicious.empty()) {
        std::cout << "\n  [!] Suspicious Regions (" << suspicious.size() << "):" << std::endl;
        printf("    %-18s %-10s %-8s %-8s %s\n", "Address", "Size", "Prot", "Type", "Reason");
        std::cout << "    " << std::string(80, '-') << std::endl;
        for (const auto& s : suspicious) {
            printf("    0x%016llX %-10s %-8s %-8s %s\n",
                (ULONGLONG)s.addr,
                native::formatSize(s.size).c_str(),
                native::protectionToString(s.protect).c_str(),
                native::memoryTypeToString(s.type).c_str(),
                s.reason.c_str());
        }
    } else {
        std::cout << "\n  [+] No suspicious memory regions detected." << std::endl;
    }
}

// ============================================================================
// Thread List - Enumerate threads for a process with start address resolution
// ============================================================================
void threadList(DWORD pid) {
    std::cout << "\n=== Threads: PID " << pid << " ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::cout << "  [!] Failed to create thread snapshot" << std::endl;
        return;
    }

    auto& api = native::NativeApi::instance();

    // Get process modules for start address resolution
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    struct ModRange { PBYTE base; SIZE_T size; std::wstring name; };
    std::vector<ModRange> modRanges;
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                MODULEINFO mi;
                wchar_t name[MAX_PATH] = {};
                if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                    GetModuleBaseNameW(hProcess, hMods[i], name, MAX_PATH);
                    modRanges.push_back({(PBYTE)mi.lpBaseOfDll, mi.SizeOfImage, name});
                }
            }
        }
        CloseHandle(hProcess);
    }

    printf("  %-8s %-18s %-6s %-30s %s\n", "TID", "Start Address", "Prio", "Module", "Status");
    std::cout << "  " << std::string(98, '-') << std::endl;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    int count = 0, suspiciousCount = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;

            // Get Win32 start address
            PVOID startAddr = nullptr;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread && api.NtQueryInformationThread) {
                ULONG retLen = 0;
                api.NtQueryInformationThread(hThread,
                    native::ThreadQuerySetWin32StartAddress,
                    &startAddr, sizeof(startAddr), &retLen);
                CloseHandle(hThread);
            }

            // Resolve module
            std::wstring modName = L"<unknown>";
            bool suspicious = false;
            if (startAddr) {
                for (const auto& m : modRanges) {
                    if ((PBYTE)startAddr >= m.base && (PBYTE)startAddr < m.base + m.size) {
                        modName = m.name;
                        break;
                    }
                }
                if (modName == L"<unknown>") {
                    suspicious = true;
                    suspiciousCount++;
                    modName = L"[!] NOT IN ANY MODULE";
                }
            }

            printf("  %-8u 0x%016llX %-6d %-30ls %s\n",
                te.th32ThreadID,
                (ULONGLONG)startAddr,
                te.tpBasePri,
                modName.c_str(),
                suspicious ? "[SUSPICIOUS]" : "");
            count++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    std::cout << "\n  Total: " << count << " threads" << std::endl;
    if (suspiciousCount > 0) {
        std::cout << "  [!] " << suspiciousCount
                  << " thread(s) with start address outside loaded modules!" << std::endl;
    }
}

// ============================================================================
// PEB Info - Read Process Environment Block
// ============================================================================
void pebInfo(DWORD pid) {
    std::cout << "\n=== PEB Information: PID " << pid << " ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    auto& api = native::NativeApi::instance();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::cout << "  [!] Cannot access process" << std::endl;
        return;
    }

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = api.NtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

    if (status != STATUS_SUCCESS || !pbi.PebBaseAddress) {
        std::cout << "  [!] Failed to query PEB address" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    std::cout << "  PEB Base Address: 0x" << std::hex << (ULONG_PTR)pbi.PebBaseAddress
              << std::dec << std::endl;

    // Read PEB
    PEB pebLocal = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead)) {
        std::cout << "  [!] Failed to read PEB" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    std::cout << "  Image Base:      0x" << std::hex << (ULONG_PTR)pebLocal.Reserved3[1]
              << std::dec << std::endl;
    std::cout << "  Being Debugged:  " << (pebLocal.BeingDebugged ? "YES [!]" : "No") << std::endl;

    // Read process parameters for command line and image path
    if (pebLocal.ProcessParameters) {
        native::RTL_USER_PROCESS_PARAMETERS_EX params = {};
        if (ReadProcessMemory(hProcess, pebLocal.ProcessParameters, &params, sizeof(params), &bytesRead)) {
            // Read image path
            if (params.ImagePathName.Buffer && params.ImagePathName.Length > 0) {
                std::vector<wchar_t> imgBuf(params.ImagePathName.Length / sizeof(wchar_t) + 1, 0);
                if (ReadProcessMemory(hProcess, params.ImagePathName.Buffer, imgBuf.data(),
                    params.ImagePathName.Length, &bytesRead)) {
                    std::cout << "  Image Path:      " << native::wstringToString(imgBuf.data()) << std::endl;
                }
            }
            // Read command line
            if (params.CommandLine.Buffer && params.CommandLine.Length > 0) {
                std::vector<wchar_t> cmdBuf(params.CommandLine.Length / sizeof(wchar_t) + 1, 0);
                if (ReadProcessMemory(hProcess, params.CommandLine.Buffer, cmdBuf.data(),
                    params.CommandLine.Length, &bytesRead)) {
                    std::cout << "  Command Line:    " << native::wstringToString(cmdBuf.data()) << std::endl;
                }
            }
        }
    }

    // Read PEB Loader Data - walk loaded modules
    if (pebLocal.Ldr) {
        native::PEB_LDR_DATA_EX ldrData = {};
        if (ReadProcessMemory(hProcess, pebLocal.Ldr, &ldrData, sizeof(ldrData), &bytesRead)) {
            std::cout << "\n  --- Loaded Modules (from PEB LDR) ---" << std::endl;
            printf("    %-4s %-18s %-10s %s\n", "#", "Base", "Size", "Module");
            std::cout << "    " << std::string(76, '-') << std::endl;

            LIST_ENTRY* listHead = &(reinterpret_cast<native::PEB_LDR_DATA_EX*>(pebLocal.Ldr))->InLoadOrderModuleList;
            LIST_ENTRY* current = ldrData.InLoadOrderModuleList.Flink;
            int idx = 0, maxMods = 512;

            while (current != listHead && idx < maxMods) {
                native::LDR_DATA_TABLE_ENTRY_EX entry = {};
                PVOID entryAddr = CONTAINING_RECORD(current, native::LDR_DATA_TABLE_ENTRY_EX, InLoadOrderLinks);
                if (!ReadProcessMemory(hProcess, entryAddr, &entry, sizeof(entry), &bytesRead))
                    break;

                // Read module name
                std::wstring modName;
                if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
                    std::vector<wchar_t> nameBuf(entry.BaseDllName.Length / sizeof(wchar_t) + 1, 0);
                    if (ReadProcessMemory(hProcess, entry.BaseDllName.Buffer, nameBuf.data(),
                        entry.BaseDllName.Length, &bytesRead)) {
                        modName = nameBuf.data();
                    }
                }

                if (!modName.empty()) {
                    printf("    [%2d] 0x%016llX 0x%08X %ls\n",
                        idx, (ULONGLONG)entry.DllBase, entry.SizeOfImage, modName.c_str());
                    idx++;
                }

                current = entry.InLoadOrderLinks.Flink;
            }
            std::cout << "    Total: " << idx << " modules" << std::endl;
        }
    }

    CloseHandle(hProcess);
}

// ============================================================================
// Kernel Modules - List loaded kernel drivers
// ============================================================================
void kernelModules() {
    std::cout << "\n=== Kernel Modules ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    auto& api = native::NativeApi::instance();
    ULONG bufferSize = 256 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemModuleInformation_Ex,
            buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 32 * 1024 * 1024);

    if (status != STATUS_SUCCESS) {
        std::cout << "  [!] Failed to query kernel modules (0x"
                  << std::hex << status << std::dec << ")" << std::endl;
        std::cout << "  [*] This requires Administrator privileges" << std::endl;
        return;
    }

    auto* modules = reinterpret_cast<native::RTL_PROCESS_MODULES*>(buffer.data());
    printf("  %-18s %-10s %-5s %s\n", "Base Address", "Size", "Loads", "Driver");
    std::cout << "  " << std::string(98, '-') << std::endl;

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        auto& mod = modules->Modules[i];
        const char* fileName = reinterpret_cast<const char*>(
            mod.FullPathName + mod.OffsetToFileName);
        printf("  0x%016llX %-10s %-5u %s\n",
            (ULONGLONG)mod.ImageBase,
            native::formatSize(mod.ImageSize).c_str(),
            mod.LoadCount,
            fileName);
    }
    std::cout << "\n  Total: " << modules->NumberOfModules << " kernel modules" << std::endl;
}

// ============================================================================
// Quick system overview (test that NtQuerySystemInformation works)
// ============================================================================
void systemOverview() {
    std::cout << "\n=== System Overview ===" << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    auto& api = native::NativeApi::instance();

    // Count processes via NtQuerySystemInformation
    ULONG bufferSize = 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(),
            bufferSize,
            &bufferSize
        );
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 64 * 1024 * 1024);

    if (status == STATUS_SUCCESS) {
        int processCount = 0;
        int totalThreads = 0;
        SIZE_T totalWorkingSet = 0;

        auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
        while (true) {
            processCount++;
            totalThreads += proc->NumberOfThreads;
            totalWorkingSet += proc->WorkingSetSize;

            if (proc->NextEntryOffset == 0) break;
            proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
                reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
        }

        std::cout << "  Timestamp:       " << native::getCurrentTimestamp() << std::endl;
        std::cout << "  Total Processes: " << processCount << std::endl;
        std::cout << "  Total Threads:   " << totalThreads << std::endl;
        std::cout << "  Total WorkSet:   " << native::formatSize(totalWorkingSet) << std::endl;

        MEMORYSTATUSEX memStatus = {};
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            std::cout << "  Physical Memory: " << native::formatSize(memStatus.ullTotalPhys) << std::endl;
            std::cout << "  Available:       " << native::formatSize(memStatus.ullAvailPhys) << std::endl;
            std::cout << "  Memory Load:     " << memStatus.dwMemoryLoad << "%" << std::endl;
        }

        SYSTEM_INFO sysInfo = {};
        GetSystemInfo(&sysInfo);
        std::cout << "  Processors:      " << sysInfo.dwNumberOfProcessors << std::endl;
        std::cout << "  Page Size:       " << sysInfo.dwPageSize << " bytes" << std::endl;
    } else {
        std::cout << "  [!] NtQuerySystemInformation failed: 0x"
                  << std::hex << status << std::dec << std::endl;
    }
}

// ============================================================================
// Process Intelligence Submenu (Phase 1)
// ============================================================================
void processIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Process Intelligence (Phase 1)           │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan & Update Database                 │" << std::endl;
        std::cout << "  │  [2] View Database                          │" << std::endl;
        std::cout << "  │  [3] Process Tree                           │" << std::endl;
        std::cout << "  │  [4] Lineage Analysis (anomaly detection)   │" << std::endl;
        std::cout << "  │  [5] Session Tracker                        │" << std::endl;
        std::cout << "  │  [6] Processes by Session                   │" << std::endl;
        std::cout << "  │  [7] Search by Name                         │" << std::endl;
        std::cout << "  │  [8] New Processes (since last scan)        │" << std::endl;
        std::cout << "  │  [9] Terminated Processes                   │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  PI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "\n  [*] Scanning system processes..." << std::endl;
                auto events = g_processDb.update();
                std::cout << "  [+] Database updated. Active: " << g_processDb.activeCount()
                          << "  Total observed: " << g_processDb.totalObserved() << std::endl;
                if (!events.empty()) {
                    std::cout << "  [*] Events this scan:" << std::endl;
                    for (const auto& evt : events) {
                        if (evt.type == zerophase::process_intelligence::ProcessEventType::Created)
                            std::cout << "    [+] CREATED: PID " << evt.pid << " "
                                      << native::wstringToString(evt.imageName) << std::endl;
                        else if (evt.type == zerophase::process_intelligence::ProcessEventType::Terminated)
                            std::cout << "    [-] TERMINATED: PID " << evt.pid << " "
                                      << native::wstringToString(evt.imageName) << std::endl;
                    }
                }
                break;
            }

            case 2:
                if (g_processDb.activeCount() == 0) {
                    std::cout << "  [*] Database empty. Running initial scan..." << std::endl;
                    g_processDb.update();
                }
                g_processDb.displayDatabase();
                break;

            case 3: {
                if (g_processDb.activeCount() == 0) g_processDb.update();
                std::cout << "  Enter root PID (0 for full tree): ";
                DWORD rootPid = 0;
                std::cin >> rootPid;
                g_lineageDetector.displayProcessTree(g_processDb, rootPid);
                break;
            }

            case 4: {
                if (g_processDb.activeCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_processDb.update();
                }
                std::cout << "  [*] Analyzing process lineage..." << std::endl;
                auto alerts = g_lineageDetector.analyzeAll(g_processDb);
                zerophase::process_intelligence::LineageDetector::displayAlerts(alerts);
                break;
            }

            case 5:
                g_sessionTracker.displaySessions();
                break;

            case 6:
                if (g_processDb.activeCount() == 0) g_processDb.update();
                g_sessionTracker.displayBySession(g_processDb);
                break;

            case 7: {
                std::cout << "  Enter process name to search: ";
                std::string searchTerm;
                std::cin >> searchTerm;
                auto results = g_processDb.getByName(native::stringToWstring(searchTerm));
                if (results.empty()) {
                    std::cout << "  No matches found." << std::endl;
                } else {
                    std::cout << "  Found " << results.size() << " match(es):" << std::endl;
                    for (const auto& p : results) {
                        p.display();
                        std::cout << std::endl;
                    }
                }
                break;
            }

            case 8:
                g_processDb.displayNew();
                break;

            case 9:
                g_processDb.displayTerminated();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Thread Intelligence Submenu (Phase 2)
// ============================================================================
void threadIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Thread Intelligence (Phase 2)            │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan All Threads                       │" << std::endl;
        std::cout << "  │  [2] Scan Process Threads (by PID)          │" << std::endl;
        std::cout << "  │  [3] View Suspicious Threads                │" << std::endl;
        std::cout << "  │  [4] Process Thread Summaries               │" << std::endl;
        std::cout << "  │  [5] Thread Detail (by TID)                 │" << std::endl;
        std::cout << "  │  [6] Stack Walk (by TID)                    │" << std::endl;
        std::cout << "  │  [7] Start Background Monitor               │" << std::endl;
        std::cout << "  │  [8] Stop Background Monitor                │" << std::endl;
        std::cout << "  │  [9] Recent Thread Events                   │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;

        if (g_threadMonitor.isRunning()) {
            std::cout << "  [*] Monitor: ACTIVE (scans: " << g_threadMonitor.scanCount()
                      << " alerts: " << g_threadMonitor.alertCount() << ")" << std::endl;
        }
        std::cout << "  TI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "\n  [*] Scanning all threads system-wide..." << std::endl;
                auto events = g_threadDb.updateAll();
                std::cout << "  [+] Database updated. Active threads: " << g_threadDb.activeCount()
                          << "  Suspicious: " << g_threadDb.suspiciousCount()
                          << "  Total observed: " << g_threadDb.totalObserved() << std::endl;
                if (!events.empty()) {
                    int created = 0, terminated = 0;
                    for (const auto& e : events) {
                        if (e.type == zerophase::thread_intelligence::ThreadEventType::Created) created++;
                        else if (e.type == zerophase::thread_intelligence::ThreadEventType::Terminated) terminated++;
                    }
                    std::cout << "  [*] Events: " << created << " created, "
                              << terminated << " terminated" << std::endl;
                }
                break;
            }

            case 2: {
                std::cout << "  Enter PID: ";
                DWORD pid = 0;
                std::cin >> pid;
                if (pid == 0) break;

                std::cout << "\n  [*] Scanning threads for PID " << pid << "..." << std::endl;
                auto events = g_threadDb.updateForProcess(pid);
                g_threadDb.displayThreadsForProcess(pid);
                break;
            }

            case 3:
                if (g_threadDb.activeCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_threadDb.updateAll();
                }
                g_threadDb.displaySuspiciousThreads();
                break;

            case 4:
                if (g_threadDb.activeCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_threadDb.updateAll();
                }
                g_threadDb.displayProcessSummaries();
                break;

            case 5: {
                std::cout << "  Enter TID: ";
                DWORD tid = 0;
                std::cin >> tid;
                if (tid == 0) break;

                auto threadOpt = g_threadDb.getByThreadId(tid);
                if (threadOpt) {
                    std::cout << "\n=== Thread Detail ===" << std::endl;
                    std::cout << std::string(60, '-') << std::endl;
                    threadOpt->display();
                } else {
                    std::cout << "  Thread not found in database. Try scanning first." << std::endl;
                }
                break;
            }

            case 6: {
                std::cout << "  Enter TID: ";
                DWORD tid = 0;
                std::cin >> tid;
                if (tid == 0) break;

                // Need the owner PID
                DWORD ownerPid = 0;
                auto threadOpt = g_threadDb.getByThreadId(tid);
                if (threadOpt) {
                    ownerPid = threadOpt->ownerPid;
                } else {
                    std::cout << "  Enter owner PID: ";
                    std::cin >> ownerPid;
                }
                if (ownerPid == 0) break;

                std::cout << "\n  [*] Walking stack for TID " << tid << "..." << std::endl;
                auto result = g_stackWalker.walkThread(tid, ownerPid);
                zerophase::thread_intelligence::StackWalker::displayStackWalk(result);
                break;
            }

            case 7: {
                if (g_threadMonitor.isRunning()) {
                    std::cout << "  [*] Monitor is already running." << std::endl;
                    break;
                }
                std::cout << "  Enter scan interval (ms, default 5000): ";
                int interval = 5000;
                std::string input;
                std::cin >> input;
                try { interval = std::stoi(input); } catch (...) { interval = 5000; }
                if (interval < 1000) interval = 1000;

                g_threadMonitor.setAlertCallback([](const zerophase::thread_intelligence::ThreadAlert& alert) {
                    printf("  [ALERT] [%s] TID %u in PID %u (%ls): %s\n",
                        zerophase::thread_intelligence::threadRiskToString(alert.riskLevel),
                        alert.threadId, alert.ownerPid,
                        alert.ownerImageName.c_str(),
                        alert.description.c_str());
                });

                if (g_threadMonitor.start(interval)) {
                    std::cout << "  [+] Thread monitor started (interval: "
                              << interval << "ms)" << std::endl;
                } else {
                    std::cout << "  [!] Failed to start monitor" << std::endl;
                }
                break;
            }

            case 8:
                if (!g_threadMonitor.isRunning()) {
                    std::cout << "  [*] Monitor is not running." << std::endl;
                } else {
                    g_threadMonitor.stop();
                    std::cout << "  [+] Thread monitor stopped. Scans: "
                              << g_threadMonitor.scanCount()
                              << " Alerts: " << g_threadMonitor.alertCount() << std::endl;
                }
                break;

            case 9:
                g_threadDb.displayRecentEvents();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Memory Intelligence Submenu (Phase 3)
// ============================================================================
void memoryIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Memory Intelligence (Phase 3)            │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan Process Memory (by PID)           │" << std::endl;
        std::cout << "  │  [2] Deep Scan (PE/shellcode detection)     │" << std::endl;
        std::cout << "  │  [3] Entropy Scan (by PID)                  │" << std::endl;
        std::cout << "  │  [4] Entropy Histogram (by PID)             │" << std::endl;
        std::cout << "  │  [5] View Suspicious Regions                │" << std::endl;
        std::cout << "  │  [6] Recent Memory Events                   │" << std::endl;
        std::cout << "  │  [7] Full Entropy Scan (all regions)        │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  MI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        DWORD pid = 0;

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Scanning memory for PID " << pid << "..." << std::endl;
                g_memoryDb.updateProcess(pid, false);
                g_memoryDb.displayProcessMemory(pid);
                break;
            }

            case 2: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Deep scanning memory for PID " << pid
                          << " (PE header + shellcode detection)..." << std::endl;
                auto events = g_memoryDb.updateProcess(pid, true);
                g_memoryDb.displayProcessMemory(pid);
                if (!events.empty()) {
                    std::cout << "\n  [*] " << events.size() << " event(s) detected:" << std::endl;
                    for (const auto& evt : events) {
                        printf("    [%s] %s\n",
                            zerophase::memory_intelligence::memoryRiskToString(evt.riskLevel),
                            evt.description.c_str());
                    }
                }
                break;
            }

            case 3: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Entropy scanning executable regions for PID " << pid << "..." << std::endl;
                auto results = g_entropyScanner.scanProcess(pid, true); // executable only
                zerophase::memory_intelligence::EntropyScanner::displayResults(results);
                break;
            }

            case 4: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Computing entropy histogram for PID " << pid << "..." << std::endl;
                auto results = g_entropyScanner.scanProcess(pid, true);
                zerophase::memory_intelligence::EntropyScanner::displayEntropyHistogram(results);
                break;
            }

            case 5:
                g_memoryDb.displaySuspicious();
                break;

            case 6:
                g_memoryDb.displayRecentEvents();
                break;

            case 7: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Full entropy scan (ALL regions) for PID " << pid << "..." << std::endl;
                auto results = g_entropyScanner.scanProcess(pid, false); // all regions
                zerophase::memory_intelligence::EntropyScanner::displayResults(results);
                zerophase::memory_intelligence::EntropyScanner::displayEntropyHistogram(results);
                break;
            }

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// DLL Intelligence Submenu (Phase 4)
// ============================================================================
void dllIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     DLL Intelligence (Phase 4)               │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan Process DLLs (by PID)             │" << std::endl;
        std::cout << "  │  [2] Scan + Verify Signatures (by PID)      │" << std::endl;
        std::cout << "  │  [3] View Suspicious DLLs                   │" << std::endl;
        std::cout << "  │  [4] View Unsigned DLLs                     │" << std::endl;
        std::cout << "  │  [5] DLL Detail (by PID)                    │" << std::endl;
        std::cout << "  │  [6] Recent DLL Events                      │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  DI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        DWORD pid = 0;

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Scanning DLLs for PID " << pid << "..." << std::endl;
                g_dllDb.updateProcess(pid, false);
                g_dllDb.displayProcessDlls(pid);
                break;
            }

            case 2: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Scanning DLLs with signature verification for PID "
                          << pid << "..." << std::endl;
                std::cout << "  [*] This may take a moment..." << std::endl;
                g_dllDb.updateProcess(pid, true);
                g_dllDb.displayProcessDlls(pid);
                break;
            }

            case 3:
                g_dllDb.displaySuspicious();
                break;

            case 4:
                g_dllDb.displayUnsigned();
                break;

            case 5: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                auto dlls = g_dllDb.getDllsForProcess(pid);
                if (dlls.empty()) {
                    std::cout << "  [*] No DLLs in database for this PID. Scanning..." << std::endl;
                    g_dllDb.updateProcess(pid, false);
                    dlls = g_dllDb.getDllsForProcess(pid);
                }
                std::cout << "\n=== DLL Details: PID " << pid << " ===" << std::endl;
                for (const auto& d : dlls) {
                    d.display();
                    std::cout << std::endl;
                }
                break;
            }

            case 6:
                g_dllDb.displayRecentEvents();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Command Line Intelligence Submenu (Phase 5)
// ============================================================================
void cmdlineIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Command Line Intelligence (Phase 5)      │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan All Command Lines                 │" << std::endl;
        std::cout << "  │  [2] View Suspicious Only                   │" << std::endl;
        std::cout << "  │  [3] Summary & Technique Stats              │" << std::endl;
        std::cout << "  │  [4] Analyze Single PID                     │" << std::endl;
        std::cout << "  │  [5] Search Command Lines                   │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  CI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "\n  [*] Scanning all process command lines..." << std::endl;
                g_cmdDb.update();
                std::cout << "  [+] Scanned " << g_cmdDb.totalCount() << " processes, "
                          << g_cmdDb.suspiciousCount() << " suspicious" << std::endl;
                g_cmdDb.displayAll(false);
                break;
            }

            case 2: {
                if (g_cmdDb.totalCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_cmdDb.update();
                }
                g_cmdDb.displayAll(true);
                break;
            }

            case 3: {
                if (g_cmdDb.totalCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_cmdDb.update();
                }
                g_cmdDb.displaySummary();
                break;
            }

            case 4: {
                std::cout << "  Enter PID: ";
                DWORD pid = 0;
                std::cin >> pid;
                if (pid == 0) break;

                auto info = zerophase::commandline_intelligence::collectCommandLineInfo(pid);
                zerophase::commandline_intelligence::CommandLineAnalyzer analyzer;
                analyzer.analyze(info);

                std::cout << "\n=== Command Line Analysis: PID " << pid << " ===" << std::endl;
                std::cout << std::string(80, '-') << std::endl;
                info.display();
                break;
            }

            case 5: {
                std::cout << "  Enter search term: ";
                std::string term;
                std::cin >> term;
                if (term.empty()) break;

                if (g_cmdDb.totalCount() == 0) {
                    std::cout << "  [*] Running initial scan..." << std::endl;
                    g_cmdDb.update();
                }

                std::wstring wterm = native::stringToWstring(term);
                std::wstring lowerTerm = wterm;
                std::transform(lowerTerm.begin(), lowerTerm.end(), lowerTerm.begin(), ::towlower);

                auto all = g_cmdDb.getAll();
                int found = 0;
                for (const auto& cmd : all) {
                    std::wstring lowerCmd = cmd.commandLine;
                    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);
                    if (lowerCmd.find(lowerTerm) != std::wstring::npos) {
                        cmd.display();
                        std::cout << std::endl;
                        found++;
                    }
                }
                std::cout << "  Found " << found << " match(es)" << std::endl;
                break;
            }

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Injection Intelligence Submenu (Phase 6)
// ============================================================================
void injectionIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Injection Intelligence (Phase 6)         │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Scan Single Process (by PID)           │" << std::endl;
        std::cout << "  │  [2] Scan All User Processes                │" << std::endl;
        std::cout << "  │  [3] View All Findings                      │" << std::endl;
        std::cout << "  │  [4] Scan Summary                           │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  II> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "  Enter PID: ";
                DWORD pid = 0;
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Scanning PID " << pid << " for injection indicators..." << std::endl;
                auto result = g_injectionDb.scanProcess(pid);
                zerophase::injection_intelligence::InjectionDetector::displayResult(result);
                break;
            }

            case 2: {
                std::cout << "\n  [*] Scanning all accessible user processes..." << std::endl;
                std::cout << "  [*] This may take a moment..." << std::endl;
                auto results = g_injectionDb.scanUserProcesses();
                int total = 0, withFindings = 0;
                for (const auto& r : results) {
                    total++;
                    if (!r.findings.empty()) withFindings++;
                }
                std::cout << "  [+] Scanned " << total << " processes, "
                          << withFindings << " with findings" << std::endl;

                // Show processes with findings
                for (const auto& r : results) {
                    if (!r.findings.empty()) {
                        zerophase::injection_intelligence::InjectionDetector::displayResult(r);
                    }
                }
                if (withFindings == 0) {
                    std::cout << "  [+] No injection indicators detected." << std::endl;
                }
                break;
            }

            case 3:
                g_injectionDb.displayAllFindings();
                break;

            case 4:
                g_injectionDb.displaySummary();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Syscall Intelligence Submenu (Phase 7)
// ============================================================================
void syscallIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Syscall Intelligence (Phase 7)           │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Build Syscall Table (current process)  │" << std::endl;
        std::cout << "  │  [2] Scan Process (stub integrity)          │" << std::endl;
        std::cout << "  │  [3] Show Hooked Functions Only             │" << std::endl;
        std::cout << "  │  [4] Scan Direct Syscalls (by PID)          │" << std::endl;
        std::cout << "  │  [5] Verify ntdll Integrity (by PID)        │" << std::endl;
        std::cout << "  │  [6] Full Scan (all checks)                 │" << std::endl;
        std::cout << "  │  [7] Scan Summary                           │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back to Main Menu                      │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  SI> ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            continue;
        }

        DWORD pid = 0;

        switch (choice) {
            case 0:
                return;

            case 1: {
                std::cout << "\n  [*] Building syscall table from current process ntdll..." << std::endl;
                auto table = g_syscallDb.getSyscallTable(0);
                zerophase::syscall_intelligence::SyscallDetector::displaySyscallTable(table, false);
                break;
            }

            case 2: {
                std::cout << "  Enter PID (0 = self): ";
                std::cin >> pid;
                std::cout << "\n  [*] Scanning syscall stubs for PID " << pid << "..." << std::endl;
                auto result = g_syscallDb.scanProcess(pid == 0 ? GetCurrentProcessId() : pid);
                zerophase::syscall_intelligence::SyscallDetector::displayScanResult(result);
                break;
            }

            case 3: {
                std::cout << "  Enter PID (0 = self): ";
                std::cin >> pid;
                auto table = g_syscallDb.getSyscallTable(pid == 0 ? GetCurrentProcessId() : pid);
                zerophase::syscall_intelligence::SyscallDetector::displaySyscallTable(table, true);
                break;
            }

            case 4: {
                std::cout << "  Enter PID: ";
                std::cin >> pid;
                if (pid == 0) break;
                std::cout << "\n  [*] Scanning for direct syscall instructions in PID " << pid << "..." << std::endl;
                zerophase::syscall_intelligence::SyscallDetector det;
                auto findings = det.scanDirectSyscalls(pid);
                if (findings.empty()) {
                    std::cout << "  [+] No direct syscall usage detected outside ntdll." << std::endl;
                } else {
                    std::cout << "  [!] " << findings.size() << " region(s) with syscall instructions:" << std::endl;
                    zerophase::syscall_intelligence::SyscallDetector::displayDirectSyscalls(findings);
                }
                break;
            }

            case 5: {
                std::cout << "  Enter PID (0 = self): ";
                std::cin >> pid;
                std::cout << "\n  [*] Comparing in-memory ntdll with on-disk version..." << std::endl;
                zerophase::syscall_intelligence::SyscallDetector det;
                int patches = det.verifyNtdllIntegrity(pid == 0 ? GetCurrentProcessId() : pid);
                if (patches < 0) {
                    std::cout << "  [!] Failed to verify ntdll integrity" << std::endl;
                } else if (patches == 0) {
                    std::cout << "  [+] ntdll is INTACT — no modifications detected" << std::endl;
                } else {
                    std::cout << "  [!] ntdll is MODIFIED — " << patches << " byte(s) differ from disk" << std::endl;
                }
                break;
            }

            case 6: {
                std::cout << "  Enter PID (0 = self): ";
                std::cin >> pid;
                std::cout << "\n  [*] Full syscall scan for PID " << (pid == 0 ? GetCurrentProcessId() : pid) << "..." << std::endl;
                auto result = g_syscallDb.scanProcess(pid == 0 ? GetCurrentProcessId() : pid);
                zerophase::syscall_intelligence::SyscallDetector::displayScanResult(result);
                break;
            }

            case 7:
                g_syscallDb.displaySummary();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }
}

// ============================================================================
// Kernel Intelligence Submenu (Phase 8)
// ============================================================================
void kernelIntelligenceMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Kernel Intelligence (Phase 8)            │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Enumerate Kernel Drivers               │" << std::endl;
        std::cout << "  │  [2] All Services                           │" << std::endl;
        std::cout << "  │  [3] Kernel Driver Services Only            │" << std::endl;
        std::cout << "  │  [4] Suspicious Services                    │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back                                   │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  KI> ";
        int c = -1; if (!(std::cin >> c)) { std::cin.clear(); std::cin.ignore(10000,'\n'); continue; }
        switch (c) {
            case 0: return;
            case 1: g_kernelDb.update(); g_kernelDb.displayDrivers(); break;
            case 2: g_kernelDb.update(); g_kernelDb.displayServices(false); break;
            case 3: g_kernelDb.update(); g_kernelDb.displayServices(true); break;
            case 4: g_kernelDb.update(); g_kernelDb.displaySuspicious(); break;
            default: std::cout << "  [!] Invalid" << std::endl;
        }
    }
}

// ============================================================================
// Detection Engine Submenu (Phase 9) - Correlates all modules
// ============================================================================
void detectionEngineMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Detection Engine (Phase 9)               │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] Run Full System Scan (all modules)     │" << std::endl;
        std::cout << "  │  [2] View Detection Dashboard               │" << std::endl;
        std::cout << "  │  [3] View All Events                        │" << std::endl;
        std::cout << "  │  [4] View HIGH+ Events Only                 │" << std::endl;
        std::cout << "  │  [5] Process Risk Profiles                  │" << std::endl;
        std::cout << "  │  [6] Events for PID                         │" << std::endl;
        std::cout << "  │  [7] Clear All Events                       │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back                                   │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  DE> ";
        int c = -1; if (!(std::cin >> c)) { std::cin.clear(); std::cin.ignore(10000,'\n'); continue; }
        switch (c) {
            case 0: return;
            case 1: {
                std::cout << "\n  [*] Running full system scan across all modules..." << std::endl;
                g_detectionEngine.clearAll();
                auto t0 = std::chrono::steady_clock::now();

                // Phase 1: Process Intelligence
                std::cout << "  [*] Phase 1: Process scan..." << std::endl;
                auto pEvts = g_processDb.update();
                auto lineageAlerts = g_lineageDetector.analyzeAll(g_processDb);
                for (const auto& a : lineageAlerts) {
                    g_detectionEngine.addEvent(
                        static_cast<zerophase::detection_intelligence::DetectionSeverity>(static_cast<int>(a.riskLevel)),
                        zerophase::detection_intelligence::DetectionSource::Process,
                        a.childPid, a.childName, "Lineage anomaly", a.description, "", "Defense Evasion");
                }
                g_productionMonitor.recordScan("Process", 0, (int)lineageAlerts.size());

                // Phase 5: Command line
                std::cout << "  [*] Phase 5: Command line scan..." << std::endl;
                g_cmdDb.update();
                auto suspCmd = g_cmdDb.getSuspicious();
                for (const auto& cmd : suspCmd) {
                    g_detectionEngine.addEvent(
                        static_cast<zerophase::detection_intelligence::DetectionSeverity>(static_cast<int>(cmd.riskLevel)),
                        zerophase::detection_intelligence::DetectionSource::CmdLine,
                        cmd.pid, cmd.imageName,
                        cmd.techniques.empty() ? "Suspicious command" : cmd.techniques[0].techniqueName,
                        native::wstringToString(cmd.commandLine).substr(0, 200),
                        cmd.techniques.empty() ? "" : cmd.techniques[0].techniqueId, "Execution");
                }
                g_productionMonitor.recordScan("CmdLine", 0, (int)suspCmd.size());

                // Phase 7: Syscall (self)
                std::cout << "  [*] Phase 7: Syscall integrity (self)..." << std::endl;
                auto sysResult = g_syscallDb.scanProcess(GetCurrentProcessId());
                if (sysResult.hookedCount > 0) {
                    g_detectionEngine.addEvent(
                        zerophase::detection_intelligence::DetectionSeverity::Medium,
                        zerophase::detection_intelligence::DetectionSource::Syscall,
                        GetCurrentProcessId(), L"ZeroPhaseEDR.exe",
                        "Syscall hooks detected",
                        std::to_string(sysResult.hookedCount) + " hooked Nt functions",
                        "T1562", "Defense Evasion");
                }
                g_productionMonitor.recordScan("Syscall", 0, sysResult.hookedCount);

                auto t1 = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double, std::milli>(t1-t0).count();
                g_forensicsEngine.addEntry("DetectionEngine", "FullScan", 0, L"",
                    "Full scan completed in " + std::to_string((int)elapsed) + "ms");

                std::cout << "  [+] Full scan completed in " << (int)elapsed << "ms" << std::endl;
                g_detectionEngine.displayDashboard();
                break;
            }
            case 2: g_detectionEngine.displayDashboard(); break;
            case 3: g_detectionEngine.displayAllEvents(zerophase::detection_intelligence::DetectionSeverity::Info); break;
            case 4: g_detectionEngine.displayAllEvents(zerophase::detection_intelligence::DetectionSeverity::High); break;
            case 5: g_detectionEngine.displayRiskProfiles(); break;
            case 6: {
                std::cout << "  Enter PID: "; DWORD pid = 0; std::cin >> pid;
                if (pid == 0) break;
                auto evts = g_detectionEngine.getEventsForPid(pid);
                if (evts.empty()) std::cout << "  No events for PID " << pid << std::endl;
                else for (const auto& e : evts) { e.display(); std::cout << std::endl; }
                break;
            }
            case 7: g_detectionEngine.clearAll(); std::cout << "  [+] All events cleared." << std::endl; break;
            default: std::cout << "  [!] Invalid" << std::endl;
        }
    }
}

// ============================================================================
// Forensics Submenu (Phase 10)
// ============================================================================
void forensicsMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Forensics Intelligence (Phase 10)        │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] View Timeline                          │" << std::endl;
        std::cout << "  │  [2] Export Timeline to CSV                  │" << std::endl;
        std::cout << "  │  [3] Take System Snapshot                    │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back                                   │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  FI> ";
        int c = -1; if (!(std::cin >> c)) { std::cin.clear(); std::cin.ignore(10000,'\n'); continue; }
        switch (c) {
            case 0: return;
            case 1: g_forensicsEngine.displayTimeline(); break;
            case 2: {
                std::string path = "C:\\Users\\c3ihub\\Desktop\\EDR\\zerophase_timeline.csv";
                if (g_forensicsEngine.exportToFile(path))
                    std::cout << "  [+] Exported to " << path << std::endl;
                else std::cout << "  [!] Export failed" << std::endl;
                break;
            }
            case 3: {
                std::string path = "C:\\Users\\c3ihub\\Desktop\\EDR\\zerophase_snapshot.txt";
                g_forensicsEngine.takeSnapshot(path);
                std::cout << "  [+] Snapshot saved to " << path << std::endl;
                break;
            }
            default: std::cout << "  [!] Invalid" << std::endl;
        }
    }
}

// ============================================================================
// Production/Health Submenu (Phase 11)
// ============================================================================
void productionMenu() {
    while (true) {
        std::cout << "\n  ┌─────────────────────────────────────────────┐" << std::endl;
        std::cout << "  │     Production Intelligence (Phase 11)       │" << std::endl;
        std::cout << "  ├─────────────────────────────────────────────┤" << std::endl;
        std::cout << "  │  [1] EDR Health Check                       │" << std::endl;
        std::cout << "  │  [2] Scan Metrics                           │" << std::endl;
        std::cout << "  │  ─────────────────────────────────────────  │" << std::endl;
        std::cout << "  │  [0] Back                                   │" << std::endl;
        std::cout << "  └─────────────────────────────────────────────┘" << std::endl;
        std::cout << "  PM> ";
        int c = -1; if (!(std::cin >> c)) { std::cin.clear(); std::cin.ignore(10000,'\n'); continue; }
        switch (c) {
            case 0: return;
            case 1: g_productionMonitor.displayHealth(); break;
            case 2: g_productionMonitor.displayMetrics(); break;
            default: std::cout << "  [!] Invalid" << std::endl;
        }
    }
}

// ============================================================================
// Entry Point
// ============================================================================
int main() {
    // Set console to UTF-8
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    printBanner();

    if (!initializeEDR()) {
        std::cout << "[!] Initialization failed. Exiting." << std::endl;
        return 1;
    }

    // Main loop
    int choice = -1;
    while (true) {
        printMenu();

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << "  [!] Invalid input" << std::endl;
            continue;
        }

        DWORD pid = 0;

        switch (choice) {
            case 0:
                std::cout << "\n[*] ZeroPhase EDR shutting down..." << std::endl;
                if (g_threadMonitor.isRunning()) {
                    g_threadMonitor.stop();
                    std::cout << "[*] Thread monitor stopped." << std::endl;
                }
                return 0;

            case 8:
                systemOverview();
                break;

            case 1:
                processList();
                break;

            case 2:
                pid = askForPid();
                if (pid > 0) processDetail(pid);
                else std::cout << "  [!] Invalid PID" << std::endl;
                break;

            case 3:
                pid = askForPid();
                if (pid > 0) moduleList(pid);
                else std::cout << "  [!] Invalid PID" << std::endl;
                break;

            case 4:
                pid = askForPid();
                if (pid > 0) memoryMap(pid);
                else std::cout << "  [!] Invalid PID" << std::endl;
                break;

            case 5:
                pid = askForPid();
                if (pid > 0) threadList(pid);
                else std::cout << "  [!] Invalid PID" << std::endl;
                break;

            case 6:
                pid = askForPid();
                if (pid > 0) pebInfo(pid);
                else std::cout << "  [!] Invalid PID" << std::endl;
                break;

            case 7:
                kernelModules();
                break;

            case 10:
                processIntelligenceMenu();
                break;

            case 11:
                threadIntelligenceMenu();
                break;

            case 12:
                memoryIntelligenceMenu();
                break;

            case 13:
                dllIntelligenceMenu();
                break;

            case 14:
                cmdlineIntelligenceMenu();
                break;

            case 15:
                injectionIntelligenceMenu();
                break;

            case 16:
                syscallIntelligenceMenu();
                break;

            case 17:
                kernelIntelligenceMenu();
                break;

            case 18:
                detectionEngineMenu();
                break;

            case 19:
                forensicsMenu();
                break;

            case 20:
                productionMenu();
                break;

            default:
                std::cout << "  [!] Invalid choice" << std::endl;
                break;
        }
    }

    return 0;
}
