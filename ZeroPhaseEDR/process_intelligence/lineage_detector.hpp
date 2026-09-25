#pragma once
/*
 * ZeroPhase EDR - Process Intelligence: Lineage Detector
 *
 * Detects anomalous parent-child process relationships.
 * Examples of suspicious lineage:
 * - cmd.exe spawned by Word/Excel/PowerPoint (macro execution)
 * - powershell.exe spawned by w3wp.exe (web shell)
 * - svchost.exe not spawned by services.exe
 * - csrss.exe/lsass.exe with unexpected parent
 */

#ifndef ZEROPHASE_LINEAGE_DETECTOR_HPP
#define ZEROPHASE_LINEAGE_DETECTOR_HPP

#include "process_database.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Lineage Rule: defines an expected or suspicious parent-child relationship
// ============================================================================
struct LineageRule {
    std::wstring childPattern;         // Process name pattern (case-insensitive)
    std::wstring expectedParent;       // Expected parent (empty = any)
    std::wstring suspiciousParent;     // Suspicious parent pattern (empty = none)
    bool         parentRequired;       // If true, child MUST have this parent
    RiskLevel    riskLevel;
    std::string  description;
};

// ============================================================================
// Lineage Alert
// ============================================================================
struct LineageAlert {
    DWORD  childPid;
    DWORD  parentPid;
    std::wstring childName;
    std::wstring parentName;
    RiskLevel    riskLevel;
    std::string  ruleName;
    std::string  description;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Lineage Detector
// ============================================================================
class LineageDetector {
public:
    LineageDetector();

    // Analyze a process against lineage rules
    std::vector<LineageAlert> analyze(const ProcessInfo& proc, const ProcessDatabase& db);

    // Analyze all processes in the database
    std::vector<LineageAlert> analyzeAll(const ProcessDatabase& db);

    // Build and display the process tree
    void displayProcessTree(const ProcessDatabase& db, DWORD rootPid = 0);

    // Display alerts
    static void displayAlerts(const std::vector<LineageAlert>& alerts);

    // Get the built-in rules
    const std::vector<LineageRule>& rules() const { return rules_; }

private:
    std::vector<LineageRule> rules_;

    void initializeRules();
    bool matchesPattern(const std::wstring& name, const std::wstring& pattern) const;
    void printTreeNode(const ProcessDatabase& db, DWORD pid, int depth,
                       std::set<DWORD>& visited) const;
};

} // namespace process_intelligence
} // namespace zerophase

#endif // ZEROPHASE_LINEAGE_DETECTOR_HPP
