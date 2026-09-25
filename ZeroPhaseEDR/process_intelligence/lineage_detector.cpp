/*
 * ZeroPhase EDR - Process Intelligence: Lineage Detector Implementation
 *
 * Implements parent-child anomaly detection using a rule-based system.
 * Rules are based on common attack patterns documented in MITRE ATT&CK.
 */

#include "lineage_detector.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Constructor
// ============================================================================
LineageDetector::LineageDetector() {
    initializeRules();
}

// ============================================================================
// Initialize built-in lineage rules
// ============================================================================
void LineageDetector::initializeRules() {
    // Rule: svchost.exe should only be spawned by services.exe
    rules_.push_back({
        L"svchost.exe", L"services.exe", L"", true,
        RiskLevel::Critical,
        "svchost.exe not spawned by services.exe (possible masquerading)"
    });

    // Rule: csrss.exe should only be spawned by smss.exe
    rules_.push_back({
        L"csrss.exe", L"smss.exe", L"", true,
        RiskLevel::Critical,
        "csrss.exe not spawned by smss.exe (possible masquerading)"
    });

    // Rule: lsass.exe should only be spawned by wininit.exe
    rules_.push_back({
        L"lsass.exe", L"wininit.exe", L"", true,
        RiskLevel::Critical,
        "lsass.exe not spawned by wininit.exe (possible credential theft)"
    });

    // Rule: smss.exe should only be spawned by System (PID 4) or itself
    rules_.push_back({
        L"smss.exe", L"", L"", false,
        RiskLevel::High,
        "smss.exe with unexpected parent"
    });

    // Rule: cmd.exe or powershell.exe spawned by Office apps (T1204 - User Execution)
    rules_.push_back({
        L"cmd.exe", L"", L"winword.exe", false,
        RiskLevel::High,
        "cmd.exe spawned by Microsoft Word (possible macro execution)"
    });
    rules_.push_back({
        L"cmd.exe", L"", L"excel.exe", false,
        RiskLevel::High,
        "cmd.exe spawned by Microsoft Excel (possible macro execution)"
    });
    rules_.push_back({
        L"cmd.exe", L"", L"powerpnt.exe", false,
        RiskLevel::High,
        "cmd.exe spawned by PowerPoint (possible macro execution)"
    });
    rules_.push_back({
        L"powershell.exe", L"", L"winword.exe", false,
        RiskLevel::Critical,
        "powershell.exe spawned by Word (highly suspicious macro)"
    });
    rules_.push_back({
        L"powershell.exe", L"", L"excel.exe", false,
        RiskLevel::Critical,
        "powershell.exe spawned by Excel (highly suspicious macro)"
    });

    // Rule: Shell spawned by IIS worker (web shell - T1505.003)
    rules_.push_back({
        L"cmd.exe", L"", L"w3wp.exe", false,
        RiskLevel::Critical,
        "cmd.exe spawned by IIS worker (possible web shell)"
    });
    rules_.push_back({
        L"powershell.exe", L"", L"w3wp.exe", false,
        RiskLevel::Critical,
        "powershell.exe spawned by IIS worker (possible web shell)"
    });

    // Rule: whoami/ipconfig/net spawned by unusual parents
    rules_.push_back({
        L"whoami.exe", L"", L"w3wp.exe", false,
        RiskLevel::High,
        "whoami.exe spawned by IIS worker (reconnaissance after web shell)"
    });

    // Rule: Scripting engines spawned by unusual parents
    rules_.push_back({
        L"cscript.exe", L"", L"winword.exe", false,
        RiskLevel::High,
        "cscript.exe spawned by Word (script execution from macro)"
    });
    rules_.push_back({
        L"wscript.exe", L"", L"winword.exe", false,
        RiskLevel::High,
        "wscript.exe spawned by Word (script execution from macro)"
    });
    rules_.push_back({
        L"mshta.exe", L"", L"winword.exe", false,
        RiskLevel::High,
        "mshta.exe spawned by Word (HTA execution from macro)"
    });

    // Rule: certutil.exe used for download (T1105 - Ingress Tool Transfer)
    rules_.push_back({
        L"certutil.exe", L"", L"cmd.exe", false,
        RiskLevel::Medium,
        "certutil.exe spawned by cmd (possible download abuse)"
    });
    rules_.push_back({
        L"certutil.exe", L"", L"powershell.exe", false,
        RiskLevel::Medium,
        "certutil.exe spawned by PowerShell (possible download abuse)"
    });

    // Rule: rundll32.exe spawned by Office (T1218.011)
    rules_.push_back({
        L"rundll32.exe", L"", L"winword.exe", false,
        RiskLevel::High,
        "rundll32.exe spawned by Word (possible DLL proxy execution)"
    });

    // Rule: regsvr32.exe spawned by shell (T1218.010)
    rules_.push_back({
        L"regsvr32.exe", L"", L"cmd.exe", false,
        RiskLevel::Medium,
        "regsvr32.exe spawned by cmd (possible Squiblydoo attack)"
    });
}

// ============================================================================
// Case-insensitive pattern matching
// ============================================================================
bool LineageDetector::matchesPattern(const std::wstring& name, const std::wstring& pattern) const {
    if (pattern.empty()) return false;

    std::wstring lowerName = name;
    std::wstring lowerPattern = pattern;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::towlower);

    // Check if the name ends with the pattern (e.g., "C:\...\cmd.exe" matches "cmd.exe")
    if (lowerName.length() >= lowerPattern.length()) {
        return lowerName.substr(lowerName.length() - lowerPattern.length()) == lowerPattern;
    }
    return lowerName == lowerPattern;
}

// ============================================================================
// Analyze a single process
// ============================================================================
std::vector<LineageAlert> LineageDetector::analyze(const ProcessInfo& proc, const ProcessDatabase& db) {
    std::vector<LineageAlert> alerts;

    // Get parent info
    auto parentOpt = db.getByPid(proc.parentPid);
    std::wstring parentName = parentOpt ? parentOpt->imageName : L"<unknown>";

    for (const auto& rule : rules_) {
        // Check if this process matches the child pattern
        if (!matchesPattern(proc.imageName, rule.childPattern))
            continue;

        bool triggered = false;

        // Check "parent required" rules
        if (rule.parentRequired && !rule.expectedParent.empty()) {
            if (!matchesPattern(parentName, rule.expectedParent)) {
                // Special case: some processes (like smss.exe) can be spawned by themselves
                if (rule.childPattern == L"smss.exe" &&
                    (proc.parentPid == 4 || matchesPattern(parentName, L"smss.exe")))
                    continue;
                triggered = true;
            }
        }

        // Check "suspicious parent" rules
        if (!rule.suspiciousParent.empty()) {
            if (matchesPattern(parentName, rule.suspiciousParent)) {
                triggered = true;
            }
        }

        if (triggered) {
            LineageAlert alert;
            alert.childPid = proc.pid;
            alert.parentPid = proc.parentPid;
            alert.childName = proc.imageName;
            alert.parentName = parentName;
            alert.riskLevel = rule.riskLevel;
            alert.description = rule.description;
            alert.timestamp = std::chrono::system_clock::now();
            alerts.push_back(alert);
        }
    }

    return alerts;
}

// ============================================================================
// Analyze all processes in the database
// ============================================================================
std::vector<LineageAlert> LineageDetector::analyzeAll(const ProcessDatabase& db) {
    std::vector<LineageAlert> allAlerts;
    auto processes = db.getAll();

    for (const auto& proc : processes) {
        auto alerts = analyze(proc, db);
        allAlerts.insert(allAlerts.end(), alerts.begin(), alerts.end());
    }

    // Sort by risk level (highest first)
    std::sort(allAlerts.begin(), allAlerts.end(),
        [](const LineageAlert& a, const LineageAlert& b) {
            return static_cast<int>(a.riskLevel) > static_cast<int>(b.riskLevel);
        });

    return allAlerts;
}

// ============================================================================
// Display process tree
// ============================================================================
void LineageDetector::printTreeNode(const ProcessDatabase& db, DWORD pid,
                                     int depth, std::set<DWORD>& visited) const {
    if (visited.count(pid) || depth > 20) return;
    visited.insert(pid);

    auto procOpt = db.getByPid(pid);
    if (!procOpt) return;

    const auto& proc = *procOpt;

    // Indentation with tree characters
    for (int i = 0; i < depth; i++) std::cout << "  │ ";
    if (depth > 0) std::cout << "├─";
    else std::cout << "  ";

    printf("[%u] %ls", proc.pid, proc.imageName.c_str());
    if (!proc.integrityLevel.empty() && proc.integrityLevel != "Unknown")
        printf(" (%s)", proc.integrityLevel.c_str());
    if (proc.isElevated)
        printf(" [ELEVATED]");
    printf("\n");

    // Recurse into children
    auto children = db.getChildPids(pid);
    std::sort(children.begin(), children.end());
    for (DWORD childPid : children) {
        printTreeNode(db, childPid, depth + 1, visited);
    }
}

void LineageDetector::displayProcessTree(const ProcessDatabase& db, DWORD rootPid) {
    std::cout << "\n=== Process Tree ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    std::set<DWORD> visited;

    if (rootPid != 0) {
        // Show tree from a specific root
        printTreeNode(db, rootPid, 0, visited);
    } else {
        // Show from all roots (processes whose parent isn't in the database)
        auto all = db.getAll();
        std::vector<DWORD> roots;
        for (const auto& proc : all) {
            if (!db.getByPid(proc.parentPid).has_value() || proc.parentPid == 0) {
                roots.push_back(proc.pid);
            }
        }
        std::sort(roots.begin(), roots.end());
        for (DWORD root : roots) {
            printTreeNode(db, root, 0, visited);
        }
    }
}

// ============================================================================
// Display alerts
// ============================================================================
void LineageDetector::displayAlerts(const std::vector<LineageAlert>& alerts) {
    std::cout << "\n=== Lineage Alerts ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    if (alerts.empty()) {
        std::cout << "  [+] No lineage anomalies detected." << std::endl;
        return;
    }

    std::cout << "  [!] " << alerts.size() << " alert(s) found:" << std::endl << std::endl;

    for (size_t i = 0; i < alerts.size(); i++) {
        const auto& a = alerts[i];
        printf("  [%zu] [%s] %s\n", i + 1, riskLevelToString(a.riskLevel), a.description.c_str());
        printf("       Child:  PID %u (%ls)\n", a.childPid, a.childName.c_str());
        printf("       Parent: PID %u (%ls)\n", a.parentPid, a.parentName.c_str());
        std::cout << std::endl;
    }
}

} // namespace process_intelligence
} // namespace zerophase
