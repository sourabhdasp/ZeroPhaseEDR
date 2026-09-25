#pragma once
/*
 * ZeroPhase EDR - DLL Intelligence: DLL Monitor
 */

#ifndef ZEROPHASE_DLL_MONITOR_HPP
#define ZEROPHASE_DLL_MONITOR_HPP

#include "dll_database.hpp"

namespace zerophase {
namespace dll_intelligence {

struct DllAlert {
    DWORD  pid;
    std::wstring ownerImageName;
    std::wstring moduleName;
    std::wstring fullPath;
    DllRiskLevel riskLevel;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

class DllMonitor {
public:
    using AlertCallback = std::function<void(const DllAlert&)>;

    DllMonitor(DllDatabase& db);
    ~DllMonitor();

    // Scan a process
    std::vector<DllAlert> scanProcess(DWORD pid, bool verifySignatures = false);

    // Alert callback
    void setAlertCallback(AlertCallback cb) { alertCallback_ = std::move(cb); }

    int scanCount() const { return scanCount_.load(); }
    int alertCount() const { return alertCount_.load(); }

private:
    DllDatabase& db_;
    AlertCallback alertCallback_;
    std::atomic<int> scanCount_{0};
    std::atomic<int> alertCount_{0};
};

} // namespace dll_intelligence
} // namespace zerophase

#endif // ZEROPHASE_DLL_MONITOR_HPP
