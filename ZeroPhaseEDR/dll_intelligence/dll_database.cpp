/*
 * ZeroPhase EDR - DLL Intelligence: DLL Database Implementation
 */

#include "dll_database.hpp"

namespace zerophase {
namespace dll_intelligence {

// ============================================================================
// Update: scan process DLLs and diff
// ============================================================================
std::vector<DllEvent> DllDatabase::updateProcess(DWORD pid, bool verifySignatures) {
    auto snapshot = enumerateProcessDlls(pid, verifySignatures);
    std::vector<DllEvent> events;
    auto now = std::chrono::system_clock::now();

    std::unique_lock lock(mutex_);
    updateCount_++;

    auto& dlls = processDlls_[pid];

    // Current base addresses
    std::set<ULONG_PTR> currentAddrs;
    for (const auto& d : snapshot) {
        currentAddrs.insert(reinterpret_cast<ULONG_PTR>(d.baseAddress));
    }

    // Detect new DLLs
    for (auto& d : snapshot) {
        ULONG_PTR addr = reinterpret_cast<ULONG_PTR>(d.baseAddress);
        if (dlls.find(addr) == dlls.end()) {
            if (updateCount_ > 1) {
                DllEvent evt;
                evt.type = DllEventType::Loaded;
                evt.pid = pid;
                evt.ownerImageName = d.ownerImageName;
                evt.moduleName = d.moduleName;
                evt.fullPath = d.fullPath;
                evt.baseAddress = d.baseAddress;
                evt.riskLevel = d.riskLevel;
                evt.timestamp = now;
                events.push_back(evt);
            }
            dlls[addr] = std::move(d);
        } else {
            // Update existing
            dlls[addr].lastUpdated = now;
        }
    }

    // Detect unloaded DLLs
    std::vector<ULONG_PTR> unloaded;
    for (const auto& [addr, info] : dlls) {
        if (currentAddrs.find(addr) == currentAddrs.end()) {
            unloaded.push_back(addr);
            DllEvent evt;
            evt.type = DllEventType::Unloaded;
            evt.pid = pid;
            evt.ownerImageName = info.ownerImageName;
            evt.moduleName = info.moduleName;
            evt.fullPath = info.fullPath;
            evt.baseAddress = info.baseAddress;
            evt.riskLevel = info.riskLevel;
            evt.timestamp = now;
            events.push_back(evt);
        }
    }
    for (ULONG_PTR addr : unloaded) {
        dlls.erase(addr);
    }

    recentEvents_.insert(recentEvents_.end(), events.begin(), events.end());
    if (recentEvents_.size() > 2000)
        recentEvents_.erase(recentEvents_.begin(), recentEvents_.begin() + (recentEvents_.size() - 2000));

    return events;
}

// ============================================================================
// Lookups
// ============================================================================
std::vector<DllInfo> DllDatabase::getDllsForProcess(DWORD pid) const {
    std::shared_lock lock(mutex_);
    std::vector<DllInfo> result;
    auto it = processDlls_.find(pid);
    if (it != processDlls_.end()) {
        for (const auto& [addr, info] : it->second)
            result.push_back(info);
        std::sort(result.begin(), result.end(),
            [](const DllInfo& a, const DllInfo& b) { return a.baseAddress < b.baseAddress; });
    }
    return result;
}

std::vector<DllInfo> DllDatabase::getSuspiciousDlls() const {
    std::shared_lock lock(mutex_);
    std::vector<DllInfo> result;
    for (const auto& [pid, dlls] : processDlls_) {
        for (const auto& [addr, info] : dlls) {
            if (info.riskLevel != DllRiskLevel::None)
                result.push_back(info);
        }
    }
    std::sort(result.begin(), result.end(),
        [](const DllInfo& a, const DllInfo& b) { return a.riskScore > b.riskScore; });
    return result;
}

std::vector<DllInfo> DllDatabase::getUnsignedDlls() const {
    std::shared_lock lock(mutex_);
    std::vector<DllInfo> result;
    for (const auto& [pid, dlls] : processDlls_) {
        for (const auto& [addr, info] : dlls) {
            if (info.signatureStatus == SignatureStatus::NotSigned)
                result.push_back(info);
        }
    }
    return result;
}

ProcessDllSummary DllDatabase::getProcessSummary(DWORD pid) const {
    auto dlls = getDllsForProcess(pid);
    return computeDllSummary(dlls, pid);
}

// ============================================================================
// Statistics
// ============================================================================
size_t DllDatabase::trackedProcesses() const {
    std::shared_lock lock(mutex_);
    return processDlls_.size();
}

size_t DllDatabase::totalDlls() const {
    std::shared_lock lock(mutex_);
    size_t total = 0;
    for (const auto& [pid, dlls] : processDlls_) total += dlls.size();
    return total;
}

size_t DllDatabase::suspiciousDlls() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [pid, dlls] : processDlls_)
        for (const auto& [addr, info] : dlls)
            if (info.riskLevel != DllRiskLevel::None) count++;
    return count;
}

const std::vector<DllEvent>& DllDatabase::recentEvents() const {
    return recentEvents_;
}

// ============================================================================
// Display
// ============================================================================
void DllDatabase::displayProcessDlls(DWORD pid) const {
    auto dlls = getDllsForProcess(pid);

    std::cout << "\n=== DLL Intelligence: PID " << pid << " ===" << std::endl;
    std::cout << std::string(110, '-') << std::endl;
    printf("  %-18s %-10s %-10s %-14s %-8s %s\n",
        "Base Address", "Size", "Signature", "Location", "Risk", "Module");
    std::cout << std::string(110, '-') << std::endl;

    for (const auto& d : dlls) {
        d.displayCompact();
    }

    auto summary = computeDllSummary(dlls, pid);
    std::cout << std::string(110, '-') << std::endl;
    std::cout << "  Total: " << summary.totalDlls << " DLLs";
    if (summary.signedCount > 0) std::cout << "  Signed: " << summary.signedCount;
    if (summary.unsignedCount > 0) std::cout << "  Unsigned: " << summary.unsignedCount;
    if (summary.suspiciousCount > 0) std::cout << "  [!] Suspicious: " << summary.suspiciousCount;
    if (summary.phantomCount > 0) std::cout << "  [!] Phantom: " << summary.phantomCount;
    std::cout << std::endl;
}

void DllDatabase::displaySuspicious() const {
    auto suspicious = getSuspiciousDlls();

    std::cout << "\n=== Suspicious DLLs ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    if (suspicious.empty()) {
        std::cout << "  [+] No suspicious DLLs detected." << std::endl;
        return;
    }

    std::cout << "  [!] " << suspicious.size() << " suspicious DLL(s):" << std::endl << std::endl;
    for (const auto& d : suspicious) {
        printf("  PID: %u (%ls)\n", d.ownerPid, d.ownerImageName.c_str());
        d.display();
        std::cout << std::endl;
    }
}

void DllDatabase::displayUnsigned() const {
    auto unsgn = getUnsignedDlls();

    std::cout << "\n=== Unsigned DLLs ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    if (unsgn.empty()) {
        std::cout << "  [+] No unsigned DLLs found (or signatures not checked)." << std::endl;
        return;
    }

    printf("  %-8s %-30s %-14s %s\n", "PID", "Module", "Location", "Path");
    std::cout << std::string(100, '-') << std::endl;
    for (const auto& d : unsgn) {
        printf("  %-8u %-30ls %-14s %ls\n",
            d.ownerPid, d.moduleName.c_str(),
            dllLocationToString(d.location),
            d.fullPath.c_str());
    }
    std::cout << "\n  Total: " << unsgn.size() << " unsigned DLLs" << std::endl;
}

void DllDatabase::displayRecentEvents(int maxEvents) const {
    std::shared_lock lock(mutex_);

    std::cout << "\n=== Recent DLL Events ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    if (recentEvents_.empty()) {
        std::cout << "  (no events since monitoring started)" << std::endl;
        return;
    }

    int start = (int)recentEvents_.size() - maxEvents;
    if (start < 0) start = 0;

    for (int i = start; i < (int)recentEvents_.size(); i++) {
        const auto& evt = recentEvents_[i];
        printf("  %s PID %u: %ls (%ls)",
            evt.type == DllEventType::Loaded ? "[+] LOADED" : "[-] UNLOADED",
            evt.pid, evt.moduleName.c_str(), evt.ownerImageName.c_str());
        if (evt.riskLevel != DllRiskLevel::None)
            printf(" [%s]", dllRiskToString(evt.riskLevel));
        printf("\n");
    }
}

} // namespace dll_intelligence
} // namespace zerophase
