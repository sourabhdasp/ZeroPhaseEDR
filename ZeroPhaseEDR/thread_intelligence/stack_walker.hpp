#pragma once
/*
 * ZeroPhase EDR - Thread Intelligence: Stack Walker
 *
 * Captures and analyzes thread call stacks using the Windows
 * DbgHelp StackWalk64 API. Useful for:
 * - Identifying what code a thread is executing
 * - Detecting stack pivoting (stack pointer outside normal range)
 * - Finding ROP gadgets or unusual return addresses
 */

#ifndef ZEROPHASE_STACK_WALKER_HPP
#define ZEROPHASE_STACK_WALKER_HPP

#include "thread_info.hpp"
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")

namespace zerophase {
namespace thread_intelligence {

// ============================================================================
// Stack frame information
// ============================================================================
struct StackFrame {
    DWORD64 address         = 0;   // Return address / instruction pointer
    DWORD64 returnAddress   = 0;
    DWORD64 framePointer    = 0;
    DWORD64 stackPointer    = 0;
    std::wstring moduleName;       // Module containing this address
    bool    inLoadedModule  = false;
    bool    isSuspicious    = false;
    std::string suspiciousReason;
};

// ============================================================================
// Stack walk result
// ============================================================================
struct StackWalkResult {
    DWORD  threadId          = 0;
    DWORD  ownerPid          = 0;
    bool   success           = false;
    std::string errorMessage;
    std::vector<StackFrame> frames;

    // Analysis results
    int    totalFrames       = 0;
    int    unresolvedFrames  = 0;
    int    suspiciousFrames  = 0;
    bool   stackPivotDetected = false;
};

// ============================================================================
// Stack Walker
// ============================================================================
class StackWalker {
public:
    StackWalker();
    ~StackWalker();

    // Walk the call stack of a thread
    StackWalkResult walkThread(DWORD threadId, DWORD ownerPid);

    // Analyze a stack walk result for suspicious patterns
    void analyzeStack(StackWalkResult& result, const std::vector<ModuleRange>& modules);

    // Display stack walk results
    static void displayStackWalk(const StackWalkResult& result);

private:
    bool initialized_ = false;
    std::mutex walkMutex_;  // DbgHelp is not thread-safe
};

} // namespace thread_intelligence
} // namespace zerophase

#endif // ZEROPHASE_STACK_WALKER_HPP
