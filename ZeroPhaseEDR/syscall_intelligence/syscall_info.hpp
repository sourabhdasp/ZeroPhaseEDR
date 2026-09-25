#pragma once
/*
 * ZeroPhase EDR - Syscall Intelligence: Syscall Info
 *
 * User-mode syscall analysis capabilities:
 * - Syscall stub integrity verification (detect ntdll hooks)
 * - Direct syscall detection (syscall/sysenter outside ntdll)
 * - Syscall number to function name mapping
 * - ntdll in-memory vs on-disk comparison
 * - Hook/trampoline pattern detection
 *
 * On x64 Windows, every Nt* function in ntdll has this prologue:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX 00 00    mov eax, <syscall_number>
 *   ...
 *   0F 05             syscall
 *   C3                ret
 *
 * If these bytes are modified, the function is hooked.
 */

#ifndef ZEROPHASE_SYSCALL_INFO_HPP
#define ZEROPHASE_SYSCALL_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace syscall_intelligence {

// ============================================================================
// Syscall stub status
// ============================================================================
enum class StubStatus : int {
    Clean       = 0,   // Stub matches expected pattern
    Hooked      = 1,   // First bytes replaced with a JMP/detour
    Patched     = 2,   // Some bytes modified but not a standard hook
    Missing     = 3,   // Function not found
    Unknown     = 4,
};

inline const char* stubStatusToString(StubStatus s) {
    switch (s) {
        case StubStatus::Clean:   return "CLEAN";
        case StubStatus::Hooked:  return "HOOKED";
        case StubStatus::Patched: return "PATCHED";
        case StubStatus::Missing: return "MISSING";
        default:                  return "UNKNOWN";
    }
}

// ============================================================================
// Syscall function info (from ntdll export table)
// ============================================================================
struct SyscallEntry {
    std::string functionName;     // e.g., "NtCreateFile"
    DWORD  syscallNumber  = 0;   // e.g., 0x0055
    PVOID  address        = nullptr;  // Address in ntdll
    PVOID  rva            = nullptr;  // RVA within ntdll
    StubStatus status     = StubStatus::Unknown;

    // Hook details (if hooked)
    PVOID  hookTarget     = nullptr;  // Where the hook jumps to
    std::string hookModule;           // Module containing the hook target
    std::string hookDescription;

    // Raw first bytes for analysis
    BYTE   rawBytes[16]   = {};

    void displayCompact() const {
        printf("  %-4u  0x%04X  %-8s  %-40s",
            syscallNumber, syscallNumber, stubStatusToString(status),
            functionName.c_str());
        if (status == StubStatus::Hooked && !hookModule.empty())
            printf("  -> %s", hookModule.c_str());
        printf("\n");
    }
};

// ============================================================================
// Direct syscall finding (syscall instruction outside ntdll)
// ============================================================================
struct DirectSyscallFinding {
    DWORD  pid             = 0;
    std::wstring imageName;
    PVOID  address         = nullptr;
    SIZE_T regionSize      = 0;
    DWORD  memoryType      = 0;
    DWORD  memoryProtect   = 0;
    std::wstring moduleName;      // Module containing the instruction (or empty)
    int    syscallCount    = 0;   // Number of syscall instructions found
    int    sysenterCount   = 0;   // Number of sysenter instructions found
    bool   inNtdll         = false;
    std::string description;
};

// ============================================================================
// Hook detection result for a process
// ============================================================================
struct SyscallScanResult {
    DWORD  pid             = 0;
    std::wstring imageName;

    // Syscall table
    std::vector<SyscallEntry> syscallTable;
    int    totalFunctions  = 0;
    int    cleanCount      = 0;
    int    hookedCount     = 0;
    int    patchedCount    = 0;

    // Direct syscall findings
    std::vector<DirectSyscallFinding> directSyscalls;

    // ntdll integrity
    bool   ntdllIntact     = true;
    int    ntdllPatchCount = 0;

    bool   scanned         = false;
};

} // namespace syscall_intelligence
} // namespace zerophase

#endif // ZEROPHASE_SYSCALL_INFO_HPP
