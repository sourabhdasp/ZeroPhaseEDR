/*
 * ZeroPhase EDR - Thread Intelligence: Stack Walker Implementation
 *
 * Uses StackWalk64 from DbgHelp to capture thread call stacks.
 * Analyzes frames for suspicious patterns like:
 * - Return addresses outside loaded modules (ROP / shellcode)
 * - Stack pointer outside expected range (stack pivoting)
 * - Unbacked executable memory in the call chain
 */

#include "stack_walker.hpp"

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Constructor / Destructor
// ============================================================================
StackWalker::StackWalker() {
    // SymInitialize will be called per-process when walking
    initialized_ = true;
}

StackWalker::~StackWalker() {
    // Nothing to clean up at class level
}

// ============================================================================
// Walk the call stack of a thread
// ============================================================================
StackWalkResult StackWalker::walkThread(DWORD threadId, DWORD ownerPid) {
    std::lock_guard<std::mutex> lock(walkMutex_);

    StackWalkResult result;
    result.threadId = threadId;
    result.ownerPid = ownerPid;

    // Open the process and thread
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ownerPid);
    if (!hProcess) {
        result.errorMessage = "Cannot open process";
        return result;
    }

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
        FALSE, threadId);
    if (!hThread) {
        result.errorMessage = "Cannot open thread";
        CloseHandle(hProcess);
        return result;
    }

    // Initialize symbol handler for this process
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    BOOL symInit = SymInitialize(hProcess, NULL, TRUE);

    // Suspend the thread to get a consistent context
    DWORD suspendCount = SuspendThread(hThread);
    if (suspendCount == (DWORD)-1) {
        result.errorMessage = "Cannot suspend thread";
        if (symInit) SymCleanup(hProcess);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }

    // Get thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        result.errorMessage = "Cannot get thread context";
        ResumeThread(hThread);
        if (symInit) SymCleanup(hProcess);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return result;
    }

    // Set up the initial stack frame
    STACKFRAME64 stackFrame = {};
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset    = ctx.Rip;
    stackFrame.AddrPC.Mode      = AddrModeFlat;
    stackFrame.AddrFrame.Offset = ctx.Rbp;
    stackFrame.AddrFrame.Mode   = AddrModeFlat;
    stackFrame.AddrStack.Offset = ctx.Rsp;
    stackFrame.AddrStack.Mode   = AddrModeFlat;

    // Get module ranges for address resolution
    auto modules = getProcessModuleRanges(ownerPid);

    // Walk the stack
    const int MAX_FRAMES = 128;
    for (int i = 0; i < MAX_FRAMES; i++) {
        BOOL ok = StackWalk64(
            machineType, hProcess, hThread,
            &stackFrame, &ctx,
            NULL,       // ReadMemoryRoutine (use default)
            SymFunctionTableAccess64,
            SymGetModuleBase64,
            NULL        // TranslateAddress (not needed for x64)
        );

        if (!ok || stackFrame.AddrPC.Offset == 0) break;

        StackFrame frame;
        frame.address       = stackFrame.AddrPC.Offset;
        frame.returnAddress = stackFrame.AddrReturn.Offset;
        frame.framePointer  = stackFrame.AddrFrame.Offset;
        frame.stackPointer  = stackFrame.AddrStack.Offset;

        // Resolve module
        frame.moduleName = resolveAddressToModule(
            reinterpret_cast<PVOID>(frame.address), modules);
        frame.inLoadedModule = !frame.moduleName.empty();

        result.frames.push_back(std::move(frame));
    }

    // Resume the thread
    ResumeThread(hThread);

    // Clean up
    if (symInit) SymCleanup(hProcess);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    result.success = true;
    result.totalFrames = static_cast<int>(result.frames.size());

    // Analyze the stack
    analyzeStack(result, modules);

    return result;
}

// ============================================================================
// Analyze stack walk results for suspicious patterns
// ============================================================================
void StackWalker::analyzeStack(StackWalkResult& result, const std::vector<ModuleRange>& modules) {
    result.unresolvedFrames = 0;
    result.suspiciousFrames = 0;
    result.stackPivotDetected = false;

    for (auto& frame : result.frames) {
        // Check if address is in a loaded module
        if (!frame.inLoadedModule && frame.address != 0) {
            result.unresolvedFrames++;
            frame.isSuspicious = true;
            frame.suspiciousReason = "Return address not in any loaded module";
            result.suspiciousFrames++;
        }
    }

    // Check for stack pivot: consecutive frames with wildly different stack pointers
    for (size_t i = 1; i < result.frames.size(); i++) {
        if (result.frames[i].stackPointer != 0 && result.frames[i-1].stackPointer != 0) {
            DWORD64 diff;
            if (result.frames[i].stackPointer > result.frames[i-1].stackPointer) {
                diff = result.frames[i].stackPointer - result.frames[i-1].stackPointer;
            } else {
                diff = result.frames[i-1].stackPointer - result.frames[i].stackPointer;
            }
            // If stack pointer jumps more than 1MB, that's suspicious
            if (diff > 1024 * 1024) {
                result.stackPivotDetected = true;
                result.frames[i].isSuspicious = true;
                result.frames[i].suspiciousReason = "Potential stack pivot (large SP jump)";
                result.suspiciousFrames++;
            }
        }
    }
}

// ============================================================================
// Display stack walk results
// ============================================================================
void StackWalker::displayStackWalk(const StackWalkResult& result) {
    std::cout << "\n=== Stack Walk: TID " << result.threadId
              << " (PID " << result.ownerPid << ") ===" << std::endl;
    std::cout << std::string(90, '-') << std::endl;

    if (!result.success) {
        std::cout << "  [!] Stack walk failed: " << result.errorMessage << std::endl;
        return;
    }

    printf("  %-4s %-18s %-18s %-18s %s\n",
        "#", "Address", "Return To", "Stack Ptr", "Module");
    std::cout << "  " << std::string(88, '-') << std::endl;

    for (size_t i = 0; i < result.frames.size(); i++) {
        const auto& f = result.frames[i];
        printf("  [%2zu] 0x%016llX 0x%016llX 0x%016llX %ls%s\n",
            i, f.address, f.returnAddress, f.stackPointer,
            f.moduleName.empty() ? L"<unbacked>" : f.moduleName.c_str(),
            f.isSuspicious ? " [!]" : "");

        if (f.isSuspicious) {
            printf("       ^^ %s\n", f.suspiciousReason.c_str());
        }
    }

    std::cout << "\n  Total frames: " << result.totalFrames << std::endl;
    if (result.unresolvedFrames > 0)
        std::cout << "  [!] Unresolved frames: " << result.unresolvedFrames << std::endl;
    if (result.stackPivotDetected)
        std::cout << "  [!] STACK PIVOT DETECTED" << std::endl;
}

} // namespace thread_intelligence
} // namespace zerophase
