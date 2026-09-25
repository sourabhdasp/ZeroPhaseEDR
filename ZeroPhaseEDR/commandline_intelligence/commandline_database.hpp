#pragma once
#ifndef ZEROPHASE_COMMANDLINE_DATABASE_HPP
#define ZEROPHASE_COMMANDLINE_DATABASE_HPP

#include "commandline_analyzer.hpp"

namespace zerophase {
namespace commandline_intelligence {

class CommandLineDatabase {
public:
    CommandLineDatabase() = default;

    // Scan all processes and analyze command lines
    void update();

    // Lookups
    std::vector<CommandLineInfo> getAll() const;
    std::vector<CommandLineInfo> getSuspicious() const;
    std::optional<CommandLineInfo> getByPid(DWORD pid) const;

    // Statistics
    size_t totalCount() const;
    size_t suspiciousCount() const;

    // Display
    void displayAll(bool suspiciousOnly = false) const;
    void displaySummary() const;

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<DWORD, CommandLineInfo> entries_;
    CommandLineAnalyzer analyzer_;
};

} // namespace commandline_intelligence
} // namespace zerophase

#endif
