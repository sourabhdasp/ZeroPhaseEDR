#pragma once
#ifndef ZEROPHASE_SYSCALL_MONITOR_HPP
#define ZEROPHASE_SYSCALL_MONITOR_HPP
#include "syscall_database.hpp"
namespace zerophase { namespace syscall_intelligence {
class SyscallMonitor {
public:
    SyscallMonitor(SyscallDatabase& db) : db_(db) {}
    SyscallScanResult scanProcess(DWORD pid) { return db_.scanProcess(pid); }
private:
    SyscallDatabase& db_;
};
} }
#endif
