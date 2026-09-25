#pragma once
#ifndef ZEROPHASE_INJECTION_MONITOR_HPP
#define ZEROPHASE_INJECTION_MONITOR_HPP

#include "injection_database.hpp"

namespace zerophase {
namespace injection_intelligence {

// Placeholder for continuous injection monitoring.
// Future: ETW-based real-time detection of VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
class InjectionMonitor {
public:
    InjectionMonitor(InjectionDatabase& db) : db_(db) {}

    // On-demand scan
    ProcessInjectionResult scanProcess(DWORD pid) { return db_.scanProcess(pid); }

private:
    InjectionDatabase& db_;
};

} // namespace injection_intelligence
} // namespace zerophase

#endif
