/*
 * ZeroPhase EDR - Command Line Intelligence: Command Line Info Implementation
 */

#include "commandline_info.hpp"

namespace zerophase {
namespace commandline_intelligence {

// ============================================================================
// Collect command line info for a single process
// ============================================================================
CommandLineInfo collectCommandLineInfo(DWORD pid) {
    CommandLineInfo info;
    info.pid = pid;
    info.firstSeen = std::chrono::system_clock::now();

    auto& api = native::NativeApi::instance();

    // Get image name and parent PID via NtQuerySystemInformation
    ULONG bufSize = 2 * 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    do {
        buffer.resize(bufSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufSize, &bufSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufSize < 64 * 1024 * 1024);

    if (status == STATUS_SUCCESS) {
        auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
        while (true) {
            if (HandleToUlong(proc->UniqueProcessId) == pid) {
                info.imageName = native::unicodeToWstring(proc->ImageName);
                info.parentPid = HandleToUlong(proc->InheritedFromUniqueProcessId);
                break;
            }
            if (proc->NextEntryOffset == 0) break;
            proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
                reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
        }
        // Get parent image name
        if (info.parentPid > 0) {
            auto* p2 = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
            while (true) {
                if (HandleToUlong(p2->UniqueProcessId) == info.parentPid) {
                    info.parentImageName = native::unicodeToWstring(p2->ImageName);
                    break;
                }
                if (p2->NextEntryOffset == 0) break;
                p2 = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
                    reinterpret_cast<BYTE*>(p2) + p2->NextEntryOffset);
            }
        }
    }

    // Get command line
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) {
        ULONG cmdBufSize = 8192;
        std::vector<BYTE> cmdBuf(cmdBufSize);
        NTSTATUS st = api.NtQueryInformationProcess(hProcess,
            native::ProcessCommandLineInformation, cmdBuf.data(), cmdBufSize, &cmdBufSize);
        if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) {
            cmdBuf.resize(cmdBufSize);
            st = api.NtQueryInformationProcess(hProcess,
                native::ProcessCommandLineInformation, cmdBuf.data(), cmdBufSize, &cmdBufSize);
        }
        if (st == STATUS_SUCCESS) {
            auto* ustr = reinterpret_cast<UNICODE_STRING*>(cmdBuf.data());
            info.commandLine = native::unicodeToWstring(*ustr);
        }
        CloseHandle(hProcess);
    }

    info.cmdLength = info.commandLine.length();
    return info;
}

// ============================================================================
// Collect command lines for all processes
// ============================================================================
std::vector<CommandLineInfo> collectAllCommandLines() {
    std::vector<CommandLineInfo> results;
    auto& api = native::NativeApi::instance();
    if (!api.isInitialized()) return results;

    ULONG bufSize = 2 * 1024 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    do {
        buffer.resize(bufSize);
        status = api.NtQuerySystemInformation(
            native::SystemProcessInformation_Ex,
            buffer.data(), bufSize, &bufSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufSize < 64 * 1024 * 1024);
    if (status != STATUS_SUCCESS) return results;

    // Build parent name map
    std::unordered_map<DWORD, std::wstring> nameMap;
    auto* scan = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        DWORD scanPid = HandleToUlong(scan->UniqueProcessId);
        nameMap[scanPid] = native::unicodeToWstring(scan->ImageName);
        if (scan->NextEntryOffset == 0) break;
        scan = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(scan) + scan->NextEntryOffset);
    }

    auto now = std::chrono::system_clock::now();
    auto* proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(buffer.data());
    while (true) {
        DWORD pid = HandleToUlong(proc->UniqueProcessId);
        if (pid > 4) {
            CommandLineInfo info;
            info.pid = pid;
            info.parentPid = HandleToUlong(proc->InheritedFromUniqueProcessId);
            info.imageName = native::unicodeToWstring(proc->ImageName);
            info.firstSeen = now;

            auto it = nameMap.find(info.parentPid);
            if (it != nameMap.end()) info.parentImageName = it->second;

            // Get command line
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                ULONG cmdBufSize = 8192;
                std::vector<BYTE> cmdBuf(cmdBufSize);
                NTSTATUS st = api.NtQueryInformationProcess(hProcess,
                    native::ProcessCommandLineInformation, cmdBuf.data(), cmdBufSize, &cmdBufSize);
                if (st == STATUS_INFO_LENGTH_MISMATCH || st == STATUS_BUFFER_TOO_SMALL) {
                    cmdBuf.resize(cmdBufSize);
                    st = api.NtQueryInformationProcess(hProcess,
                        native::ProcessCommandLineInformation, cmdBuf.data(), cmdBufSize, &cmdBufSize);
                }
                if (st == STATUS_SUCCESS) {
                    auto* ustr = reinterpret_cast<UNICODE_STRING*>(cmdBuf.data());
                    info.commandLine = native::unicodeToWstring(*ustr);
                }
                CloseHandle(hProcess);
            }
            info.cmdLength = info.commandLine.length();
            results.push_back(std::move(info));
        }

        if (proc->NextEntryOffset == 0) break;
        proc = reinterpret_cast<native::SYSTEM_PROCESS_INFORMATION_EX*>(
            reinterpret_cast<BYTE*>(proc) + proc->NextEntryOffset);
    }
    return results;
}

} // namespace commandline_intelligence
} // namespace zerophase
