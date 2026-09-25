#pragma once
/*
 * ZeroPhase EDR - Injection Intelligence: Injection Detector
 *
 * Multi-signal correlation engine that detects code injection
 * by analyzing memory, threads, and modules of a target process.
 */

#ifndef ZEROPHASE_INJECTION_DETECTOR_HPP
#define ZEROPHASE_INJECTION_DETECTOR_HPP

#include "injection_info.hpp"

namespace zerophase {
namespace injection_intelligence {

class InjectionDetector {
public:
    InjectionDetector() = default;

    // Full injection scan for a single process
    ProcessInjectionResult scanProcess(DWORD pid);

    // Display results
    static void displayResult(const ProcessInjectionResult& result);
    static void displayFindings(const std::vector<InjectionFinding>& findings);

private:
    // Individual detection methods
    void detectRemoteThreads(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);
    void detectPrivateExecutable(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);
    void detectReflectiveDll(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);
    void detectModuleStomping(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);
    void detectProcessHollowing(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);
    void detectPhantomDllHollow(DWORD pid, HANDLE hProcess, ProcessInjectionResult& result);

    // Helpers
    bool readRemoteBytes(HANDLE hProcess, PVOID address, BYTE* buffer, SIZE_T size);
    bool isPEHeader(const BYTE* data, SIZE_T size);
    double quickEntropy(HANDLE hProcess, PVOID address, SIZE_T maxRead = 4096);
};

} // namespace injection_intelligence
} // namespace zerophase

#endif // ZEROPHASE_INJECTION_DETECTOR_HPP
