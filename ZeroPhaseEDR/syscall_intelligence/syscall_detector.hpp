#pragma once
#ifndef ZEROPHASE_SYSCALL_DETECTOR_HPP
#define ZEROPHASE_SYSCALL_DETECTOR_HPP

#include "syscall_info.hpp"

namespace zerophase {
namespace syscall_intelligence {

class SyscallDetector {
public:
    SyscallDetector();

    // Build the syscall table from ntdll exports (current process or remote)
    std::vector<SyscallEntry> buildSyscallTable(DWORD pid = 0);

    // Verify syscall stub integrity for a process
    SyscallScanResult scanProcess(DWORD pid);

    // Scan for direct syscall instructions outside ntdll
    std::vector<DirectSyscallFinding> scanDirectSyscalls(DWORD pid);

    // Compare in-memory ntdll with on-disk version
    int verifyNtdllIntegrity(DWORD pid);

    // Display
    static void displaySyscallTable(const std::vector<SyscallEntry>& table, bool hookedOnly = false);
    static void displayScanResult(const SyscallScanResult& result);
    static void displayDirectSyscalls(const std::vector<DirectSyscallFinding>& findings);

private:
    // Parse PE export table to find Nt* functions
    struct ExportEntry {
        std::string name;
        DWORD rva;
        PVOID address;
    };
    std::vector<ExportEntry> parseNtdllExports(HANDLE hProcess, PVOID ntdllBase);

    // Verify a single syscall stub
    StubStatus verifyStub(HANDLE hProcess, PVOID stubAddress, BYTE* rawBytes,
                          DWORD& outSyscallNum, PVOID& outHookTarget);

    // Resolve which module an address belongs to
    std::string resolveModule(HANDLE hProcess, PVOID address);

    // Get ntdll base address for a process
    PVOID getNtdllBase(DWORD pid);
};

} // namespace syscall_intelligence
} // namespace zerophase

#endif
