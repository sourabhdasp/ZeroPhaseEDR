#pragma once
/*
 * ZeroPhase EDR - Production Intelligence
 *
 * Performance monitoring and operational metrics:
 * - Scan timing
 * - Memory usage tracking
 * - Module statistics
 * - Health checks
 */

#ifndef ZEROPHASE_PRODUCTION_INFO_HPP
#define ZEROPHASE_PRODUCTION_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace production_intelligence {

struct ScanMetric {
    std::string moduleName;
    int scanCount          = 0;
    double totalTimeMs     = 0.0;
    double lastTimeMs      = 0.0;
    double avgTimeMs       = 0.0;
    int findingsGenerated  = 0;
};

class ProductionMonitor {
public:
    void recordScan(const std::string& module, double elapsedMs, int findings = 0) {
        std::lock_guard lock(mutex_);
        auto& m = metrics_[module];
        m.moduleName = module;
        m.scanCount++;
        m.totalTimeMs += elapsedMs;
        m.lastTimeMs = elapsedMs;
        m.avgTimeMs = m.totalTimeMs / m.scanCount;
        m.findingsGenerated += findings;
    }

    void displayMetrics() const {
        std::lock_guard lock(mutex_);
        std::cout << "\n=== Production Metrics ===" << std::endl;
        std::cout << std::string(90, '-') << std::endl;
        printf("  %-25s %-8s %-12s %-12s %-12s %s\n",
            "Module", "Scans", "Last(ms)", "Avg(ms)", "Total(ms)", "Findings");
        std::cout << std::string(90, '-') << std::endl;

        for (const auto& [name, m] : metrics_) {
            printf("  %-25s %-8d %-12.1f %-12.1f %-12.1f %d\n",
                m.moduleName.c_str(), m.scanCount,
                m.lastTimeMs, m.avgTimeMs, m.totalTimeMs,
                m.findingsGenerated);
        }
    }

    void displayHealth() const {
        std::cout << "\n=== EDR Health Check ===" << std::endl;
        std::cout << std::string(50, '-') << std::endl;

        // Self process info
        PROCESS_MEMORY_COUNTERS_EX pmc = {};
        pmc.cb = sizeof(pmc);
        GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));

        std::cout << "  EDR PID:        " << GetCurrentProcessId() << std::endl;
        std::cout << "  Working Set:    " << native::formatSize(pmc.WorkingSetSize) << std::endl;
        std::cout << "  Private Bytes:  " << native::formatSize(pmc.PrivateUsage) << std::endl;
        std::cout << "  Page Faults:    " << pmc.PageFaultCount << std::endl;

        FILETIME creationTime, exitTime, kernelTime, userTime;
        GetProcessTimes(GetCurrentProcess(), &creationTime, &exitTime, &kernelTime, &userTime);
        ULARGE_INTEGER kt, ut;
        kt.LowPart = kernelTime.dwLowDateTime; kt.HighPart = kernelTime.dwHighDateTime;
        ut.LowPart = userTime.dwLowDateTime; ut.HighPart = userTime.dwHighDateTime;
        printf("  CPU Kernel:     %.2f s\n", kt.QuadPart / 10000000.0);
        printf("  CPU User:       %.2f s\n", ut.QuadPart / 10000000.0);

        std::lock_guard lock(mutex_);
        int totalScans = 0;
        for (const auto& [n, m] : metrics_) totalScans += m.scanCount;
        std::cout << "  Total Scans:    " << totalScans << std::endl;
        std::cout << "  Active Modules: " << metrics_.size() << std::endl;
    }

private:
    mutable std::mutex mutex_;
    std::map<std::string, ScanMetric> metrics_;
};

} // namespace production_intelligence
} // namespace zerophase

#endif
