/*
 * ZeroPhase EDR - Command Line Intelligence: Analyzer Implementation
 *
 * Rule-based command line analysis engine with MITRE ATT&CK mapping.
 */

#include "commandline_analyzer.hpp"
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace zerophase {
namespace commandline_intelligence {

// ============================================================================
// Constructor
// ============================================================================
CommandLineAnalyzer::CommandLineAnalyzer() {
    initializeRules();
}

// ============================================================================
// Initialize detection rules with MITRE ATT&CK mapping
// ============================================================================
void CommandLineAnalyzer::initializeRules() {
    // === Execution ===
    rules_.push_back({"R001", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::Medium, L"powershell", L"-encodedcommand",
        "PowerShell encoded command execution"});
    rules_.push_back({"R002", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::Medium, L"powershell", L"-enc ",
        "PowerShell encoded command (short flag)"});
    rules_.push_back({"R003", "T1059.001", "PowerShell", CmdCategory::DefenseEvasion,
        CmdRiskLevel::High, L"powershell", L"-windowstyle hidden",
        "PowerShell hidden window execution"});
    rules_.push_back({"R004", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"invoke-expression",
        "PowerShell Invoke-Expression (IEX)"});
    rules_.push_back({"R005", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"iex(",
        "PowerShell IEX shorthand"});
    rules_.push_back({"R006", "T1059.001", "PowerShell", CmdCategory::DefenseEvasion,
        CmdRiskLevel::High, L"powershell", L"-noprofile",
        "PowerShell with no profile (evasion)"});
    rules_.push_back({"R007", "T1059.001", "PowerShell", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Medium, L"powershell", L"-executionpolicy bypass",
        "PowerShell execution policy bypass"});
    rules_.push_back({"R008", "T1059.001", "PowerShell", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Medium, L"powershell", L"-ep bypass",
        "PowerShell execution policy bypass (short)"});
    rules_.push_back({"R009", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"downloadstring",
        "PowerShell download string (download cradle)"});
    rules_.push_back({"R010", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"downloadfile",
        "PowerShell download file"});
    rules_.push_back({"R011", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"net.webclient",
        "PowerShell WebClient usage"});
    rules_.push_back({"R012", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::High, L"powershell", L"invoke-webrequest",
        "PowerShell Invoke-WebRequest"});
    rules_.push_back({"R013", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::Critical, L"powershell", L"reflection.assembly",
        "PowerShell reflective assembly loading"});
    rules_.push_back({"R014", "T1059.001", "PowerShell", CmdCategory::Execution,
        CmdRiskLevel::Critical, L"powershell", L"[convert]::frombase64",
        "PowerShell Base64 decode and execute"});

    // === Reconnaissance ===
    rules_.push_back({"R020", "T1033", "System Owner Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Low, L"whoami", L"",
        "System owner/user discovery"});
    rules_.push_back({"R021", "T1082", "System Information Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Low, L"systeminfo", L"",
        "System information discovery"});
    rules_.push_back({"R022", "T1016", "Network Configuration Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Low, L"ipconfig", L"",
        "Network configuration discovery"});
    rules_.push_back({"R023", "T1018", "Remote System Discovery", CmdCategory::Discovery,
        CmdRiskLevel::Medium, L"", L"net view",
        "Remote system discovery via net view"});
    rules_.push_back({"R024", "T1087", "Account Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Medium, L"", L"net user",
        "Account discovery via net user"});
    rules_.push_back({"R025", "T1087", "Account Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Medium, L"", L"net localgroup",
        "Local group enumeration"});
    rules_.push_back({"R026", "T1049", "Network Connections Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Low, L"netstat", L"-an",
        "Network connections discovery"});
    rules_.push_back({"R027", "T1057", "Process Discovery", CmdCategory::Reconnaissance,
        CmdRiskLevel::Low, L"tasklist", L"",
        "Process discovery via tasklist"});
    rules_.push_back({"R028", "T1012", "Query Registry", CmdCategory::Discovery,
        CmdRiskLevel::Low, L"reg", L"query",
        "Registry query"});

    // === Persistence ===
    rules_.push_back({"R030", "T1053.005", "Scheduled Task", CmdCategory::Persistence,
        CmdRiskLevel::Medium, L"schtasks", L"/create",
        "Scheduled task creation"});
    rules_.push_back({"R031", "T1543.003", "Windows Service", CmdCategory::Persistence,
        CmdRiskLevel::High, L"sc", L"create",
        "Service creation"});
    rules_.push_back({"R032", "T1547.001", "Registry Run Key", CmdCategory::Persistence,
        CmdRiskLevel::High, L"reg", L"add.*\\run",
        "Registry Run key modification", true});

    // === Defense Evasion ===
    rules_.push_back({"R040", "T1218.011", "Rundll32", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Medium, L"rundll32", L"javascript:",
        "Rundll32 JavaScript execution"});
    rules_.push_back({"R041", "T1218.005", "Mshta", CmdCategory::DefenseEvasion,
        CmdRiskLevel::High, L"mshta", L"vbscript:",
        "Mshta VBScript execution"});
    rules_.push_back({"R042", "T1218.005", "Mshta", CmdCategory::DefenseEvasion,
        CmdRiskLevel::High, L"mshta", L"javascript:",
        "Mshta JavaScript execution"});
    rules_.push_back({"R043", "T1218.010", "Regsvr32", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Medium, L"regsvr32", L"/s /n /u /i:",
        "Regsvr32 Squiblydoo execution"});
    rules_.push_back({"R044", "T1218.003", "CMSTP", CmdCategory::DefenseEvasion,
        CmdRiskLevel::High, L"cmstp", L"/s /ns",
        "CMSTP UAC bypass"});
    rules_.push_back({"R045", "T1562.001", "Disable Security", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Critical, L"", L"set-mppreference -disablerealtimemonitoring",
        "Windows Defender real-time monitoring disabled"});
    rules_.push_back({"R046", "T1562.001", "Disable Security", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Critical, L"", L"netsh advfirewall set allprofiles state off",
        "Windows Firewall disabled"});
    rules_.push_back({"R047", "T1070.001", "Clear Event Logs", CmdCategory::DefenseEvasion,
        CmdRiskLevel::Critical, L"wevtutil", L"cl",
        "Event log cleared"});

    // === Credential Access ===
    rules_.push_back({"R050", "T1003", "OS Credential Dumping", CmdCategory::CredentialAccess,
        CmdRiskLevel::Critical, L"", L"sekurlsa::logonpasswords",
        "Mimikatz credential dump pattern"});
    rules_.push_back({"R051", "T1003", "OS Credential Dumping", CmdCategory::CredentialAccess,
        CmdRiskLevel::Critical, L"", L"lsadump::sam",
        "Mimikatz SAM dump pattern"});
    rules_.push_back({"R052", "T1003.001", "LSASS Memory", CmdCategory::CredentialAccess,
        CmdRiskLevel::Critical, L"", L"comsvcs.dll, minidump",
        "LSASS process dump via comsvcs"});
    rules_.push_back({"R053", "T1003.001", "LSASS Memory", CmdCategory::CredentialAccess,
        CmdRiskLevel::High, L"procdump", L"lsass",
        "LSASS process dump via procdump"});

    // === Exfiltration / Ingress Tool Transfer ===
    rules_.push_back({"R060", "T1105", "Ingress Tool Transfer", CmdCategory::Exfiltration,
        CmdRiskLevel::Medium, L"certutil", L"-urlcache",
        "Certutil download (LOLBin)"});
    rules_.push_back({"R061", "T1105", "Ingress Tool Transfer", CmdCategory::Exfiltration,
        CmdRiskLevel::Medium, L"bitsadmin", L"/transfer",
        "BITSAdmin file transfer"});
    rules_.push_back({"R062", "T1105", "Ingress Tool Transfer", CmdCategory::Exfiltration,
        CmdRiskLevel::Medium, L"curl", L"-o",
        "cURL file download"});

    // === Lateral Movement ===
    rules_.push_back({"R070", "T1021.006", "WinRM", CmdCategory::LateralMovement,
        CmdRiskLevel::High, L"", L"invoke-command -computername",
        "PowerShell remoting to another machine"});
    rules_.push_back({"R071", "T1047", "WMI", CmdCategory::LateralMovement,
        CmdRiskLevel::High, L"wmic", L"/node:",
        "WMI remote execution"});

    // === Impact ===
    rules_.push_back({"R080", "T1490", "Inhibit Recovery", CmdCategory::Impact,
        CmdRiskLevel::Critical, L"", L"vssadmin delete shadows",
        "Volume shadow copy deletion (ransomware indicator)"});
    rules_.push_back({"R081", "T1490", "Inhibit Recovery", CmdCategory::Impact,
        CmdRiskLevel::Critical, L"", L"bcdedit.*recoveryenabled.*no",
        "Boot recovery disabled (ransomware indicator)", true});
    rules_.push_back({"R082", "T1490", "Inhibit Recovery", CmdCategory::Impact,
        CmdRiskLevel::Critical, L"", L"wbadmin delete catalog",
        "Backup catalog deletion (ransomware indicator)"});
}

// ============================================================================
// Pattern matching helpers
// ============================================================================
bool CommandLineAnalyzer::matchesProcess(const std::wstring& imageName, const std::wstring& pattern) const {
    if (pattern.empty()) return true;
    std::wstring lower = imageName;
    std::wstring lowerPat = pattern;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    std::transform(lowerPat.begin(), lowerPat.end(), lowerPat.begin(), ::towlower);
    return lower.find(lowerPat) != std::wstring::npos;
}

bool CommandLineAnalyzer::matchesCommand(const std::wstring& cmdLine, const std::wstring& pattern, bool useRegex) const {
    if (pattern.empty()) return true;

    std::wstring lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (useRegex) {
        try {
            std::wstring lowerPat = pattern;
            std::transform(lowerPat.begin(), lowerPat.end(), lowerPat.begin(), ::towlower);
            std::wregex re(lowerPat, std::regex::icase);
            return std::regex_search(lower, re);
        } catch (...) {
            return false;
        }
    }

    std::wstring lowerPat = pattern;
    std::transform(lowerPat.begin(), lowerPat.end(), lowerPat.begin(), ::towlower);
    return lower.find(lowerPat) != std::wstring::npos;
}

// ============================================================================
// Base64 detection and decoding
// ============================================================================
void CommandLineAnalyzer::detectBase64Encoding(CommandLineInfo& info) {
    std::wstring lower = info.commandLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // Check for PowerShell -EncodedCommand or -enc
    bool hasPsEnc = (lower.find(L"-encodedcommand") != std::wstring::npos ||
                     lower.find(L"-enc ") != std::wstring::npos ||
                     lower.find(L"-e ") != std::wstring::npos);

    if (hasPsEnc) {
        info.hasEncodedContent = true;
        // Try to extract and decode the base64 payload
        // Find the argument after -enc/-encodedcommand
        std::wstring cmdLine = info.commandLine;
        size_t encPos = std::wstring::npos;

        // Try different flag variants
        for (const auto& flag : {L"-encodedcommand ", L"-EncodedCommand ", L"-enc ", L"-e "}) {
            encPos = cmdLine.find(flag);
            if (encPos != std::wstring::npos) {
                encPos += wcslen(flag);
                break;
            }
        }

        if (encPos != std::wstring::npos) {
            // Extract the base64 string (to end of line or next space-dash)
            std::wstring b64 = cmdLine.substr(encPos);
            // Trim trailing spaces
            while (!b64.empty() && b64.back() == L' ') b64.pop_back();
            // Remove surrounding quotes
            if (b64.size() >= 2 && b64.front() == L'"' && b64.back() == L'"')
                b64 = b64.substr(1, b64.size() - 2);

            info.decodedContent = tryDecodeBase64(b64);
        }
    }

    // Check for general base64 patterns (long base64-like strings)
    if (!info.hasEncodedContent) {
        // Look for very long base64-like arguments (>100 chars of [A-Za-z0-9+/=])
        std::wregex b64regex(L"[A-Za-z0-9+/=]{100,}");
        if (std::regex_search(info.commandLine, b64regex)) {
            info.hasEncodedContent = true;
        }
    }
}

std::wstring CommandLineAnalyzer::tryDecodeBase64(const std::wstring& encoded) {
    if (encoded.empty()) return L"";

    // Convert wide string to narrow for base64 decode
    std::string narrow = native::wstringToString(encoded);

    // Windows CryptStringToBinary for base64 decode
    DWORD decodedSize = 0;
    if (!CryptStringToBinaryA(narrow.c_str(), (DWORD)narrow.size(),
        CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
        return L"";
    }

    std::vector<BYTE> decoded(decodedSize);
    if (!CryptStringToBinaryA(narrow.c_str(), (DWORD)narrow.size(),
        CRYPT_STRING_BASE64, decoded.data(), &decodedSize, nullptr, nullptr)) {
        return L"";
    }

    // PowerShell encoded commands are UTF-16LE
    if (decodedSize >= 2) {
        // Check for BOM or valid UTF-16LE
        const wchar_t* wstr = reinterpret_cast<const wchar_t*>(decoded.data());
        size_t wlen = decodedSize / sizeof(wchar_t);

        // Validate it looks like text
        bool looksLikeText = true;
        for (size_t i = 0; i < wlen && i < 50; i++) {
            if (wstr[i] == 0 && i < wlen - 1) { looksLikeText = false; break; }
        }
        if (looksLikeText && wlen > 0) {
            return std::wstring(wstr, wlen);
        }
    }

    // Try as ASCII/UTF-8
    std::string ascii(decoded.begin(), decoded.end());
    return native::stringToWstring(ascii);
}

// ============================================================================
// Obfuscation detection
// ============================================================================
void CommandLineAnalyzer::detectObfuscation(CommandLineInfo& info) {
    const std::wstring& cmd = info.commandLine;
    if (cmd.empty()) return;

    // 1. Caret insertion (cmd.exe obfuscation): p^o^w^e^r^s^h^e^l^l
    int caretCount = 0;
    for (wchar_t c : cmd) {
        if (c == L'^') caretCount++;
    }
    if (caretCount > 3) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("Caret insertion obfuscation detected (" + std::to_string(caretCount) + " carets)");
    }

    // 2. Environment variable expansion: %COMSPEC%, %SYSTEMROOT%
    std::wstring lower = cmd;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower.find(L"%comspec%") != std::wstring::npos) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("Environment variable expansion used (%COMSPEC%)");
    }

    // 3. String concatenation in PowerShell: ('po'+'wer'+'shell')
    if (lower.find(L"'+'" ) != std::wstring::npos || lower.find(L"\"+'") != std::wstring::npos) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("String concatenation obfuscation detected");
    }

    // 4. Tick marks in PowerShell: po`wer`shell
    int tickCount = 0;
    for (wchar_t c : cmd) {
        if (c == L'`') tickCount++;
    }
    if (tickCount > 2) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("Backtick obfuscation detected");
    }

    // 5. Character code construction: [char]112 + [char]111 + ...
    if (lower.find(L"[char]") != std::wstring::npos) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("Character code obfuscation ([char]N)");
    }

    // 6. Replace/format string obfuscation
    if (lower.find(L"-replace") != std::wstring::npos && lower.find(L"-f ") != std::wstring::npos) {
        info.hasObfuscation = true;
        info.riskReasons.push_back("String replacement obfuscation");
    }
}

// ============================================================================
// Download cradle detection
// ============================================================================
void CommandLineAnalyzer::detectDownloadCradles(CommandLineInfo& info) {
    std::wstring lower = info.commandLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    // PowerShell download cradles
    bool hasDownload = (lower.find(L"downloadstring") != std::wstring::npos ||
                        lower.find(L"downloadfile") != std::wstring::npos ||
                        lower.find(L"invoke-webrequest") != std::wstring::npos ||
                        lower.find(L"iwr ") != std::wstring::npos ||
                        lower.find(L"wget ") != std::wstring::npos ||
                        lower.find(L"curl ") != std::wstring::npos ||
                        lower.find(L"net.webclient") != std::wstring::npos ||
                        lower.find(L"start-bitstransfer") != std::wstring::npos);

    bool hasExec = (lower.find(L"iex") != std::wstring::npos ||
                    lower.find(L"invoke-expression") != std::wstring::npos ||
                    lower.find(L"| &") != std::wstring::npos);

    // certutil download
    bool hasCertutil = (lower.find(L"certutil") != std::wstring::npos &&
                        (lower.find(L"-urlcache") != std::wstring::npos ||
                         lower.find(L"-split") != std::wstring::npos));

    if ((hasDownload && hasExec) || hasCertutil) {
        info.hasDownloadCradle = true;
        info.riskReasons.push_back("Download and execute pattern detected");
    }
}

// ============================================================================
// Long argument detection
// ============================================================================
void CommandLineAnalyzer::detectLongArguments(CommandLineInfo& info) {
    if (info.cmdLength > 500) {
        info.hasLongArgument = true;
        info.riskReasons.push_back("Unusually long command line (" + std::to_string(info.cmdLength) + " chars)");
    }
}

// ============================================================================
// Analyze a single command line
// ============================================================================
void CommandLineAnalyzer::analyze(CommandLineInfo& info) {
    if (info.commandLine.empty()) return;

    // Run specific detections
    detectBase64Encoding(info);
    detectObfuscation(info);
    detectDownloadCradles(info);
    detectLongArguments(info);

    // Run pattern rules
    for (const auto& rule : rules_) {
        if (matchesProcess(info.imageName, rule.processPattern) &&
            matchesCommand(info.commandLine, rule.cmdPattern, rule.useRegex)) {
            DetectedTechnique tech;
            tech.techniqueId = rule.techniqueId;
            tech.techniqueName = rule.techniqueName;
            tech.category = rule.category;
            tech.riskLevel = rule.riskLevel;
            tech.description = rule.description;
            tech.matchedPattern = native::wstringToString(rule.cmdPattern);
            info.techniques.push_back(std::move(tech));
        }
    }

    // Compute final risk
    computeRisk(info);
}

void CommandLineAnalyzer::analyzeAll(std::vector<CommandLineInfo>& commands) {
    for (auto& cmd : commands) {
        analyze(cmd);
    }
}

// ============================================================================
// Compute risk from all findings
// ============================================================================
void CommandLineAnalyzer::computeRisk(CommandLineInfo& info) {
    info.riskScore = 0;

    // Score from techniques
    for (const auto& t : info.techniques) {
        switch (t.riskLevel) {
            case CmdRiskLevel::Critical: info.riskScore += 40; break;
            case CmdRiskLevel::High:     info.riskScore += 25; break;
            case CmdRiskLevel::Medium:   info.riskScore += 15; break;
            case CmdRiskLevel::Low:      info.riskScore += 5; break;
            default: break;
        }
    }

    // Bonus for encoded content
    if (info.hasEncodedContent) info.riskScore += 20;
    if (info.hasObfuscation) info.riskScore += 15;
    if (info.hasDownloadCradle) info.riskScore += 30;
    if (info.hasLongArgument) info.riskScore += 5;

    // Cap at 100
    if (info.riskScore > 100) info.riskScore = 100;

    // Set risk level
    if (info.riskScore >= 70)
        info.riskLevel = CmdRiskLevel::Critical;
    else if (info.riskScore >= 50)
        info.riskLevel = CmdRiskLevel::High;
    else if (info.riskScore >= 25)
        info.riskLevel = CmdRiskLevel::Medium;
    else if (info.riskScore >= 5)
        info.riskLevel = CmdRiskLevel::Low;
}

// ============================================================================
// Display
// ============================================================================
void CommandLineAnalyzer::displayAnalysis(const std::vector<CommandLineInfo>& commands, bool suspiciousOnly) {
    std::cout << "\n=== Command Line Analysis ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;

    int displayed = 0;
    for (const auto& cmd : commands) {
        if (suspiciousOnly && cmd.riskLevel == CmdRiskLevel::None) continue;
        if (cmd.commandLine.empty()) continue;
        cmd.display();
        std::cout << std::endl;
        displayed++;
    }

    if (displayed == 0) {
        std::cout << "  [+] No " << (suspiciousOnly ? "suspicious " : "")
                  << "command lines found." << std::endl;
    } else {
        std::cout << "  Total: " << displayed << " command line(s) displayed" << std::endl;
    }
}

void CommandLineAnalyzer::displaySummary(const std::vector<CommandLineInfo>& commands) {
    std::cout << "\n=== Command Line Summary ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    int total = 0, withCmd = 0;
    int critical = 0, high = 0, medium = 0, low = 0;
    int encoded = 0, obfuscated = 0, download = 0;
    std::map<std::string, int> techniqueCounts;

    for (const auto& cmd : commands) {
        total++;
        if (!cmd.commandLine.empty()) withCmd++;
        switch (cmd.riskLevel) {
            case CmdRiskLevel::Critical: critical++; break;
            case CmdRiskLevel::High:     high++; break;
            case CmdRiskLevel::Medium:   medium++; break;
            case CmdRiskLevel::Low:      low++; break;
            default: break;
        }
        if (cmd.hasEncodedContent) encoded++;
        if (cmd.hasObfuscation) obfuscated++;
        if (cmd.hasDownloadCradle) download++;
        for (const auto& t : cmd.techniques) {
            techniqueCounts[t.techniqueId + " " + t.techniqueName]++;
        }
    }

    printf("  Processes:   %d total, %d with command lines\n", total, withCmd);
    printf("  Risk:        Critical: %d  High: %d  Medium: %d  Low: %d\n",
        critical, high, medium, low);
    printf("  Indicators:  Encoded: %d  Obfuscated: %d  Download: %d\n",
        encoded, obfuscated, download);

    if (!techniqueCounts.empty()) {
        std::cout << "\n  Detected techniques:" << std::endl;
        for (const auto& [name, count] : techniqueCounts) {
            printf("    [%d] %s\n", count, name.c_str());
        }
    }
}

} // namespace commandline_intelligence
} // namespace zerophase
