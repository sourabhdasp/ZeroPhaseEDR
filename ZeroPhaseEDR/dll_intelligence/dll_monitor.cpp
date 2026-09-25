/*
 * ZeroPhase EDR - DLL Intelligence: DLL Monitor Implementation
 */

#include "dll_monitor.hpp"

namespace zerophase {
namespace dll_intelligence {

DllMonitor::DllMonitor(DllDatabase& db) : db_(db) {}
DllMonitor::~DllMonitor() {}

std::vector<DllAlert> DllMonitor::scanProcess(DWORD pid, bool verifySignatures) {
    auto events = db_.updateProcess(pid, verifySignatures);
    scanCount_++;

    std::vector<DllAlert> alerts;
    for (const auto& evt : events) {
        if (evt.type == DllEventType::Loaded && evt.riskLevel != DllRiskLevel::None) {
            DllAlert alert;
            alert.pid = evt.pid;
            alert.ownerImageName = evt.ownerImageName;
            alert.moduleName = evt.moduleName;
            alert.fullPath = evt.fullPath;
            alert.riskLevel = evt.riskLevel;
            alert.description = "Suspicious DLL loaded: " + native::wstringToString(evt.moduleName);
            alert.timestamp = evt.timestamp;
            alerts.push_back(std::move(alert));
        }
    }

    alertCount_ += static_cast<int>(alerts.size());
    if (alertCallback_) {
        for (const auto& a : alerts) alertCallback_(a);
    }
    return alerts;
}

} // namespace dll_intelligence
} // namespace zerophase
