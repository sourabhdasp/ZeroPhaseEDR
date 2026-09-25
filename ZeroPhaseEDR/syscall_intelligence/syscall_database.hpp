#pragma once
#ifndef ZEROPHASE_SYSCALL_DATABASE_HPP
#define ZEROPHASE_SYSCALL_DATABASE_HPP

#include "syscall_detector.hpp"

namespace zerophase {
namespace syscall_intelligence {

class SyscallDatabase {
public:
    SyscallDatabase() = default;

    SyscallScanResult scanProcess(DWORD pid) {
        auto result = detector_.scanProcess(pid);
        std::unique_lock lock(mutex_);
        results_[pid] = result;
        return result;
    }

    std::vector<SyscallEntry> getSyscallTable(DWORD pid = 0) {
        return detector_.buildSyscallTable(pid);
    }

    size_t scannedCount() const {
        std::shared_lock lock(mutex_);
        return results_.size();
    }

    void displaySummary() const {
        std::shared_lock lock(mutex_);
        std::cout << "\n=== Syscall Intelligence Summary ===" << std::endl;
        std::cout << std::string(80, '-') << std::endl;
        printf("  %-8s %-20s %-8s %-8s %-8s %-8s %s\n",
            "PID", "Image", "Total", "Clean", "Hooked", "Patched", "ntdll");
        std::cout << std::string(80, '-') << std::endl;
        for (const auto& [pid, r] : results_) {
            printf("  %-8u %-20ls %-8d %-8d %-8d %-8d %s\n",
                pid, r.imageName.c_str(), r.totalFunctions,
                r.cleanCount, r.hookedCount, r.patchedCount,
                r.ntdllIntact ? "OK" : "MODIFIED");
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<DWORD, SyscallScanResult> results_;
    SyscallDetector detector_;
};

} // namespace syscall_intelligence
} // namespace zerophase

#endif
