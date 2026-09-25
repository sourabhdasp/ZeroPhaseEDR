#pragma once
#ifndef ZEROPHASE_COMMANDLINE_MONITOR_HPP
#define ZEROPHASE_COMMANDLINE_MONITOR_HPP

#include "commandline_database.hpp"

namespace zerophase {
namespace commandline_intelligence {

// Placeholder for real-time command line monitoring.
// Full implementation will use ETW Process provider to catch
// command lines at process creation time.
class CommandLineMonitor {
public:
    CommandLineMonitor(CommandLineDatabase& db) : db_(db) {}

    void scanOnce() { db_.update(); }

private:
    CommandLineDatabase& db_;
};

} // namespace commandline_intelligence
} // namespace zerophase

#endif
