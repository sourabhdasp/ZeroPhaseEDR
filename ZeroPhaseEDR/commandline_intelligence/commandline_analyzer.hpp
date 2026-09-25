#pragma once
/*
 * ZeroPhase EDR - Command Line Intelligence: Analyzer
 *
 * Pattern-based command line analysis engine with:
 * - Base64/encoded command detection and decoding
 * - PowerShell obfuscation detection
 * - Download cradle identification
 * - Suspicious tool usage detection
 * - MITRE ATT&CK technique mapping
 */

#ifndef ZEROPHASE_COMMANDLINE_ANALYZER_HPP
#define ZEROPHASE_COMMANDLINE_ANALYZER_HPP

#include "commandline_info.hpp"
#include <regex>

namespace zerophase {
namespace commandline_intelligence {

// ============================================================================
// Analysis rule
// ============================================================================
struct AnalysisRule {
    std::string id;             // Rule ID
    std::string techniqueId;    // MITRE ATT&CK ID
    std::string techniqueName;  // MITRE technique name
    CmdCategory category;
    CmdRiskLevel riskLevel;
    std::wstring processPattern;  // Process name pattern (case-insensitive, empty=any)
    std::wstring cmdPattern;      // Command line pattern (case-insensitive substring)
    std::string description;
    bool useRegex = false;       // If true, cmdPattern is a regex
};

// ============================================================================
// Command Line Analyzer
// ============================================================================
class CommandLineAnalyzer {
public:
    CommandLineAnalyzer();

    // Analyze a single command line
    void analyze(CommandLineInfo& info);

    // Analyze all collected command lines
    void analyzeAll(std::vector<CommandLineInfo>& commands);

    // Get rules
    const std::vector<AnalysisRule>& rules() const { return rules_; }

    // Display analysis results
    static void displayAnalysis(const std::vector<CommandLineInfo>& commands, bool suspiciousOnly = false);
    static void displaySummary(const std::vector<CommandLineInfo>& commands);

private:
    std::vector<AnalysisRule> rules_;

    void initializeRules();

    // Detection helpers
    bool matchesProcess(const std::wstring& imageName, const std::wstring& pattern) const;
    bool matchesCommand(const std::wstring& cmdLine, const std::wstring& pattern, bool useRegex) const;

    // Specific detections
    void detectBase64Encoding(CommandLineInfo& info);
    void detectObfuscation(CommandLineInfo& info);
    void detectDownloadCradles(CommandLineInfo& info);
    void detectLongArguments(CommandLineInfo& info);

    // Base64 decode helper
    std::wstring tryDecodeBase64(const std::wstring& encoded);

    // Compute final risk
    void computeRisk(CommandLineInfo& info);
};

} // namespace commandline_intelligence
} // namespace zerophase

#endif // ZEROPHASE_COMMANDLINE_ANALYZER_HPP
