/*
 * ZeroPhase EDR - Command Line Intelligence: Database Implementation
 */

#include "commandline_database.hpp"

namespace zerophase {
namespace commandline_intelligence {

void CommandLineDatabase::update() {
    auto commands = collectAllCommandLines();
    analyzer_.analyzeAll(commands);

    std::unique_lock lock(mutex_);
    entries_.clear();
    for (auto& cmd : commands) {
        entries_[cmd.pid] = std::move(cmd);
    }
}

std::vector<CommandLineInfo> CommandLineDatabase::getAll() const {
    std::shared_lock lock(mutex_);
    std::vector<CommandLineInfo> result;
    for (const auto& [pid, info] : entries_)
        result.push_back(info);
    return result;
}

std::vector<CommandLineInfo> CommandLineDatabase::getSuspicious() const {
    std::shared_lock lock(mutex_);
    std::vector<CommandLineInfo> result;
    for (const auto& [pid, info] : entries_) {
        if (info.riskLevel != CmdRiskLevel::None)
            result.push_back(info);
    }
    std::sort(result.begin(), result.end(),
        [](const CommandLineInfo& a, const CommandLineInfo& b) {
            return a.riskScore > b.riskScore;
        });
    return result;
}

std::optional<CommandLineInfo> CommandLineDatabase::getByPid(DWORD pid) const {
    std::shared_lock lock(mutex_);
    auto it = entries_.find(pid);
    if (it != entries_.end()) return it->second;
    return std::nullopt;
}

size_t CommandLineDatabase::totalCount() const {
    std::shared_lock lock(mutex_);
    return entries_.size();
}

size_t CommandLineDatabase::suspiciousCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [pid, info] : entries_)
        if (info.riskLevel != CmdRiskLevel::None) count++;
    return count;
}

void CommandLineDatabase::displayAll(bool suspiciousOnly) const {
    auto all = suspiciousOnly ? getSuspicious() : getAll();
    CommandLineAnalyzer::displayAnalysis(all, suspiciousOnly);
}

void CommandLineDatabase::displaySummary() const {
    auto all = getAll();
    CommandLineAnalyzer::displaySummary(all);
}

} // namespace commandline_intelligence
} // namespace zerophase
