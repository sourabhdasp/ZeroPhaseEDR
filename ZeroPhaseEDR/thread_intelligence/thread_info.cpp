/*
 * ZeroPhase EDR - Thread Intelligence: Thread Info Implementation
 *
 * Populates ThreadInfo structures with enriched data including
 * start address resolution, module mapping, memory analysis,
 * and risk scoring for injection detection.
 */

#include "thread_info.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Get the Win32 start address of a thread via NtQueryInformationThread
// ============================================================================
PVOID getThreadWin32StartAddress(DWORD threadId) {
    auto& api = native::NativeApi::instance();
    if (!api.NtQueryInformationThread) return nullptr;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) {
        // Try with limited access
        hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        if (!hThread) return nullptr;
    }

    PVOID startAddr = nullptr;
    ULONG retLen = 0;
    NTSTATUS status = api.NtQueryInformationThread(
        hThread,
        native::ThreadQuerySetWin32StartAddress,
        &startAddr, sizeof(startAddr), &retLen);

    CloseHandle(hThread);
    return (status == STATUS_SUCCESS) ? startAddr : nullptr;
}

// ============================================================================
// Get loaded modules for a process (for address resolution)
// ============================================================================
std::vector<ModuleRange> getProcessModuleRanges(DWORD pid) {
    std::vector<ModuleRange> modules;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return modules;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
            MODULEINFO mi;
            wchar_t modName[MAX_PATH] = {};
            wchar_t modPath[MAX_PATH] = {};

            if (GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi))) {
                GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);
                GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH);

                ModuleRange range;
                range.baseAddress = mi.lpBaseOfDll;
                range.size = mi.SizeOfImage;
                range.moduleName = modName;
                range.modulePath = modPath;
                modules.push_back(std::move(range));
            }
        }
    }

    CloseHandle(hProcess);
    return modules;
}

// ============================================================================
// Resolve which module contains an address
// ============================================================================
std::wstring resolveAddressToModule(PVOID address, const std::vector<ModuleRange>& modules) {
    if (!address) return L"";

    for (const auto& mod : modules) {
        PBYTE base = reinterpret_cast<PBYTE>(mod.baseAddress);
        if (address >= base && address < base + mod.size) {
            return mod.moduleName;
        }
    }
    return L"";
}

// ============================================================================
// Query memory protection/type at a given address
// ============================================================================
bool queryAddressMemoryInfo(DWORD pid, PVOID address, DWORD& outProtect, DWORD& outType) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    bool result = false;
    if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        outProtect = mbi.Protect;
        outType = mbi.Type;
        result = true;
    }

    CloseHandle(hProcess);
    return result;
}

// ============================================================================
// Build a ThreadInfo from system thread data + enrichment
// ============================================================================
ThreadInfo buildThreadInfo(
    DWORD threadId, DWORD ownerPid,
    const native::SYSTEM_THREAD_INFORMATION_EX* sysThread,
    const std::vector<ModuleRange>& ownerModules,
    const std::wstring& ownerImageName)
{
    ThreadInfo info;
    info.threadId       = threadId;
    info.ownerPid       = ownerPid;
    info.ownerImageName = ownerImageName;
    info.firstSeen      = std::chrono::system_clock::now();
    info.lastUpdated    = info.firstSeen;

    // From SYSTEM_THREAD_INFORMATION
    if (sysThread) {
        info.kernelStartAddress = sysThread->StartAddress;
        info.threadState        = sysThread->ThreadState;
        info.waitReason         = sysThread->WaitReason;
        info.priority           = sysThread->Priority;
        info.basePriority       = sysThread->BasePriority;
        info.contextSwitches    = sysThread->ContextSwitches;
        info.waitTime           = sysThread->WaitTime;
        info.createTime         = sysThread->CreateTime;
        info.kernelTime         = sysThread->KernelTime;
        info.userTime           = sysThread->UserTime;
    }

    // Get Win32 start address
    info.win32StartAddress = getThreadWin32StartAddress(threadId);

    // Resolve start address to module
    PVOID addrToResolve = info.win32StartAddress ? info.win32StartAddress : info.kernelStartAddress;
    if (addrToResolve && !ownerModules.empty()) {
        info.startModule = resolveAddressToModule(addrToResolve, ownerModules);
        info.startAddressResolved = true;
        info.startInLoadedModule = !info.startModule.empty();
    }

    // Query memory info at start address
    if (addrToResolve) {
        queryAddressMemoryInfo(ownerPid, addrToResolve,
            info.startMemoryProtect, info.startMemoryType);
    }

    // Check suspended state
    info.isSuspended = (info.threadState == 5 && // Waiting
                        (info.waitReason == 5 || info.waitReason == 6)); // Suspended/UserRequest

    // Risk analysis
    analyzeThreadRisk(info);

    return info;
}

// ============================================================================
// Risk analysis for a single thread
// ============================================================================
void analyzeThreadRisk(ThreadInfo& thread) {
    thread.riskScore = 0;
    thread.riskReasons.clear();
    thread.riskLevel = ThreadRiskLevel::None;

    // Skip PID 0 and 4 (System)
    if (thread.ownerPid <= 4) return;

    // 1. Thread start address not in any loaded module (HIGH)
    //    This is one of the strongest indicators of code injection
    if (thread.startAddressResolved && !thread.startInLoadedModule &&
        thread.win32StartAddress != nullptr) {
        thread.riskScore += 40;
        thread.riskReasons.push_back(
            "Start address not in any loaded module (possible injection)");
    }

    // 2. Thread starts in private executable memory (not backed by a file)
    if (thread.startMemoryType == MEM_PRIVATE) {
        DWORD baseProt = thread.startMemoryProtect & 0xFF;
        if (baseProt == PAGE_EXECUTE || baseProt == PAGE_EXECUTE_READ ||
            baseProt == PAGE_EXECUTE_READWRITE || baseProt == PAGE_EXECUTE_WRITECOPY) {
            thread.riskScore += 30;
            thread.riskReasons.push_back(
                "Start address in executable private memory (no backing file)");
        }
        // RWX is extra suspicious
        if (baseProt == PAGE_EXECUTE_READWRITE) {
            thread.riskScore += 20;
            thread.riskReasons.push_back(
                "Start address in RWX memory (Read-Write-Execute)");
        }
    }

    // 3. Thread created in a suspended state (common for process hollowing)
    if (thread.isSuspended && thread.contextSwitches == 0) {
        thread.riskScore += 15;
        thread.riskReasons.push_back(
            "Thread created suspended with zero context switches");
    }

    // 4. Thread in a system process starting from unusual location
    std::wstring lowerOwner = thread.ownerImageName;
    std::transform(lowerOwner.begin(), lowerOwner.end(), lowerOwner.begin(), ::towlower);

    bool isSystemProcess = (lowerOwner == L"svchost.exe" || lowerOwner == L"lsass.exe" ||
                           lowerOwner == L"csrss.exe" || lowerOwner == L"services.exe" ||
                           lowerOwner == L"wininit.exe" || lowerOwner == L"winlogon.exe");

    if (isSystemProcess && thread.startAddressResolved && !thread.startInLoadedModule) {
        thread.riskScore += 25;
        thread.riskReasons.push_back(
            "Injected thread in system-critical process");
    }

    // Calculate final risk level
    if (thread.riskScore >= 70)
        thread.riskLevel = ThreadRiskLevel::Critical;
    else if (thread.riskScore >= 50)
        thread.riskLevel = ThreadRiskLevel::High;
    else if (thread.riskScore >= 30)
        thread.riskLevel = ThreadRiskLevel::Medium;
    else if (thread.riskScore >= 10)
        thread.riskLevel = ThreadRiskLevel::Low;
    else
        thread.riskLevel = ThreadRiskLevel::None;
}

// ============================================================================
// Snapshot all threads for a specific process
// ============================================================================
std::vector<ThreadInfo> snapshotProcessThreads(DWORD pid) {
    std::vector<ThreadInfo> results;
    auto& api = native::NativeApi::instance();
    if (!api.isInitialized()) return results;

    // Get process image name
    std::wstring imageName;
    {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            wchar_t path[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
                std::wstring fullPath(path, size);
                auto pos = fullPath.find_last_of(L'\\');
                imageName = (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
            }
            CloseHandle(hProcess);
        }
    }

    // Get module ranges for this process
    auto modules = getProcessModuleRanges(pid);

    // Enumerate threads via NtQuerySystemInformation to get rich data
    ULONG bufferSize = 2 * 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 64 * 1024 * 1024);

    if (status != STATUS_SUCCESS) return results;

    // Find our process in the list
    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        if (HandleToUlong(proc->UniqueProcessId) == pid) {
            if (imageName.empty())
                imageName = native::unicodeToWstring(proc->ImageName);

            // Enumerate threads for this process
            for (ULONG i = 0; i < proc->NumberOfThreads; i++) {
                auto& sysThread = proc->Threads[i];
                DWORD tid = HandleToUlong(sysThread.ClientId.UniqueThread);

                auto threadInfo = buildThreadInfo(tid, pid, &sysThread, modules, imageName);
                results.push_back(std::move(threadInfo));
            }
            break;
        }

        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }

    return results;
}

// ============================================================================
// Snapshot all threads system-wide
// ============================================================================
std::vector<ThreadInfo> snapshotAllThreads() {
    std::vector<ThreadInfo> results;
    auto& api = native::NativeApi::instance();
    if (!api.isInitialized()) return results;

    ULONG bufferSize = 4 * 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;

    do {
        buffer.resize(bufferSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufferSize < 128 * 1024 * 1024);

    if (status != STATUS_SUCCESS) return results;

    // Cache module ranges per process to avoid re-querying
    std::unordered_map<DWORD, std::vector<ModuleRange>> moduleCache;

    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        DWORD pid = HandleToUlong(proc->UniqueProcessId);
        std::wstring imageName = native::unicodeToWstring(proc->ImageName);

        // Lazy-load module ranges
        auto& modules = moduleCache[pid];
        if (modules.empty() && pid > 4) {
            modules = getProcessModuleRanges(pid);
        }

        for (ULONG i = 0; i < proc->NumberOfThreads; i++) {
            auto& sysThread = proc->Threads[i];
            DWORD tid = HandleToUlong(sysThread.ClientId.UniqueThread);

            auto threadInfo = buildThreadInfo(tid, pid, &sysThread, modules, imageName);
            results.push_back(std::move(threadInfo));
        }

        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }

    return results;
}

} // namespace thread_intelligence
} // namespace zerophase
