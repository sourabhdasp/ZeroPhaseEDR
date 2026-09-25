/*
 * ZeroPhase EDR - Process Intelligence: Process Info Implementation
 *
 * Populates ProcessInfo structures from live system data using
 * both Win32 and Native API calls.
 */

#include "process_info.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Populate a ProcessInfo from NtQuerySystemInformation data + additional queries
// ============================================================================
ProcessInfo buildProcessInfo(DWORD pid, const native::SYSTEM_PROCESS_INFORMATION_EX* sysProc) {
    ProcessInfo info;
    info.pid            = pid;
    info.parentPid      = HandleToUlong(sysProc->InheritedFromUniqueProcessId);
    info.sessionId      = sysProc->SessionId;
    info.threadCount    = sysProc->NumberOfThreads;
    info.handleCount    = sysProc->HandleCount;
    info.basePriority   = sysProc->BasePriority;
    info.workingSetSize = sysProc->WorkingSetSize;
    info.privateBytes   = sysProc->PrivatePageCount;
    info.virtualSize    = sysProc->VirtualSize;
    info.cycleTime      = sysProc->CycleTime;
    info.createTime     = sysProc->CreateTime;
    info.userTime       = sysProc->UserTime;
    info.kernelTime     = sysProc->KernelTime;
    info.imageName      = native::unicodeToWstring(sysProc->ImageName);
    info.firstSeen      = std::chrono::system_clock::now();
    info.lastUpdated    = info.firstSeen;

    // Try to get additional info from the process handle
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        // Full image path
        wchar_t path[MAX_PATH * 2] = {};
        DWORD pathSize = MAX_PATH * 2;
        if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize))
            info.imagePathFull.assign(path, pathSize);

        // Command line via NtQueryInformationProcess
        auto& api = native::NativeApi::instance();
        if (api.NtQueryInformationProcess) {
            ULONG bufSize = 4096;
            std::vector<BYTE> buf(bufSize);
            NTSTATUS st = api.NtQueryInformationProcess(hProcess,
                native::ProcessCommandLineInformation, buf.data(), bufSize, &bufSize);
            if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) {
                buf.resize(bufSize);
                st = api.NtQueryInformationProcess(hProcess,
                    native::ProcessCommandLineInformation, buf.data(), bufSize, &bufSize);
            }
            if (st == STATUS_SUCCESS) {
                auto* ustr = reinterpret_cast<UNICODE_STRING*>(buf.data());
                info.commandLine = native::unicodeToWstring(*ustr);
            }
        }

        // Token info: integrity & elevation
        HANDLE hToken;
        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            // Integrity level
            DWORD needed = 0;
            GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &needed);
            if (needed > 0) {
                std::vector<BYTE> tilBuf(needed);
                auto* til = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(tilBuf.data());
                if (GetTokenInformation(hToken, TokenIntegrityLevel, til, needed, &needed)) {
                    DWORD sid = *GetSidSubAuthority(til->Label.Sid,
                        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(til->Label.Sid) - 1));
                    if (sid < SECURITY_MANDATORY_LOW_RID)          info.integrityLevel = "Untrusted";
                    else if (sid < SECURITY_MANDATORY_MEDIUM_RID)   info.integrityLevel = "Low";
                    else if (sid < SECURITY_MANDATORY_HIGH_RID)     info.integrityLevel = "Medium";
                    else if (sid < SECURITY_MANDATORY_SYSTEM_RID)   info.integrityLevel = "High";
                    else                                            info.integrityLevel = "System";
                }
            }

            // Elevation
            TOKEN_ELEVATION elev;
            DWORD elevSize = sizeof(elev);
            if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &elevSize))
                info.isElevated = (elev.TokenIsElevated != 0);

            CloseHandle(hToken);
        }

        // WoW64 check
        BOOL wow64 = FALSE;
        if (IsWow64Process(hProcess, &wow64))
            info.isWow64 = (wow64 != FALSE);

        CloseHandle(hProcess);
    }

    if (info.integrityLevel.empty())
        info.integrityLevel = "Unknown";

    return info;
}

// ============================================================================
// Snapshot all processes on the system into ProcessInfo structures
// ============================================================================
std::vector<ProcessInfo> snapshotAllProcesses() {
    std::vector<ProcessInfo> results;
    auto& api = native::NativeApi::instance();
    if (!api.isInitialized()) return results;

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

    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        DWORD pid = HandleToUlong(proc->UniqueProcessId);
        results.push_back(buildProcessInfo(pid, proc));

        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }

    return results;
}

} // namespace process_intelligence
} // namespace zerophase
