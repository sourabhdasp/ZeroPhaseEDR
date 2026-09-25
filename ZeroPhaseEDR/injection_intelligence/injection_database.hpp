#pragma once
#ifndef ZEROPHASE_INJECTION_DATABASE_HPP
#define ZEROPHASE_INJECTION_DATABASE_HPP

#include "injection_detector.hpp"

namespace zerophase {
namespace injection_intelligence {

class InjectionDatabase {
public:
    InjectionDatabase() = default;

    // Scan a process and store results
    ProcessInjectionResult scanProcess(DWORD pid);

    // Scan multiple user-session processes
    std::vector<ProcessInjectionResult> scanUserProcesses();

    // Lookups
    std::vector<InjectionFinding> getAllFindings() const;
    std::optional<ProcessInjectionResult> getResult(DWORD pid) const;

    // Stats
    size_t scannedCount() const;
    size_t findingCount() const;

    // Display
    void displayAllFindings() const;
    void displaySummary() const;

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<DWORD, ProcessInjectionResult> results_;
    InjectionDetector detector_;
};

} // namespace injection_intelligence
} // namespace zerophase

#endif
