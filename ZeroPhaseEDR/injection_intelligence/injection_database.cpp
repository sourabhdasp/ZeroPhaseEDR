/*
 * ZeroPhase EDR - Injection Intelligence: Database Implementation
 */

#include "injection_database.hpp"

namespace zerophase {
namespace injection_intelligence {

ProcessInjectionResult InjectionDatabase::scanProcess(DWORD pid) {
    auto result = detector_.scanProcess(pid);
    std::unique_lock lock(mutex_);
    results_[pid] = result;
    return result;
}

std::vector<ProcessInjectionResult> InjectionDatabase::scanUserProcesses() {
    std::vector<ProcessInjectionResult> allResults;

    // Get all processes in user sessions
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return allResults;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    std::vector<DWORD> pids;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    for (DWORD pid : pids) {
        auto result = scanProcess(pid);
        if (result.scanned) {
            allResults.push_back(std::move(result));
        }
    }
    return allResults;
}

std::vector<InjectionFinding> InjectionDatabase::getAllFindings() const {
    std::shared_lock lock(mutex_);
    std::vector<InjectionFinding> findings;
    for (const auto& [pid, result] : results_) {
        findings.insert(findings.end(), result.findings.begin(), result.findings.end());
    }
    // Sort by risk
    std::sort(findings.begin(), findings.end(),
        [](const InjectionFinding& a, const InjectionFinding& b) {
            return static_cast<int>(a.riskLevel) > static_cast<int>(b.riskLevel);
        });
    return findings;
}

std::optional<ProcessInjectionResult> InjectionDatabase::getResult(DWORD pid) const {
    std::shared_lock lock(mutex_);
    auto it = results_.find(pid);
    if (it != results_.end()) return it->second;
    return std::nullopt;
}

size_t InjectionDatabase::scannedCount() const {
    std::shared_lock lock(mutex_);
    return results_.size();
}

size_t InjectionDatabase::findingCount() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [pid, r] : results_) count += r.findings.size();
    return count;
}

void InjectionDatabase::displayAllFindings() const {
    auto findings = getAllFindings();
    std::cout << "\n=== All Injection Findings ===" << std::endl;
    std::cout << std::string(90, '-') << std::endl;

    if (findings.empty()) {
        std::cout << "  [+] No injection indicators detected across "
                  << scannedCount() << " scanned processes." << std::endl;
        return;
    }

    std::cout << "  [!] " << findings.size() << " finding(s) across "
              << scannedCount() << " processes:" << std::endl;
    InjectionDetector::displayFindings(findings);
}

void InjectionDatabase::displaySummary() const {
    std::shared_lock lock(mutex_);
    std::cout << "\n=== Injection Scan Summary ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    int total = 0, withFindings = 0;
    int critical = 0, high = 0, medium = 0, low = 0;
    std::map<InjectionType, int> typeCounts;

    for (const auto& [pid, r] : results_) {
        total++;
        if (!r.findings.empty()) withFindings++;
        for (const auto& f : r.findings) {
            typeCounts[f.type]++;
            switch (f.riskLevel) {
                case InjectionRisk::Critical: critical++; break;
                case InjectionRisk::High:     high++; break;
                case InjectionRisk::Medium:   medium++; break;
                case InjectionRisk::Low:      low++; break;
                default: break;
            }
        }
    }

    printf("  Processes scanned: %d\n", total);
    printf("  With findings:     %d\n", withFindings);
    printf("  Risk breakdown:    Critical: %d  High: %d  Medium: %d  Low: %d\n",
        critical, high, medium, low);

    if (!typeCounts.empty()) {
        std::cout << "\n  Injection types detected:" << std::endl;
        for (const auto& [type, count] : typeCounts) {
            printf("    [%d] %s\n", count, injectionTypeToString(type));
        }
    }
}

} // namespace injection_intelligence
} // namespace zerophase
