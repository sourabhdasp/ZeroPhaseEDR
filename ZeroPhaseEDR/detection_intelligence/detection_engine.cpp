/*
 * ZeroPhase EDR - Detection Intelligence: Engine Implementation
 */

#include "detection_engine.hpp"

namespace zerophase {
namespace detection_intelligence {

void DetectionEngine::addEvent(DetectionSeverity severity, DetectionSource source,
    DWORD pid, const std::wstring& imageName,
    const std::string& title, const std::string& description,
    const std::string& mitreId, const std::string& mitreTactic,
    const std::vector<std::string>& evidence)
{
    std::unique_lock lock(mutex_);
    DetectionEvent evt;
    evt.id = nextId_++;
    evt.severity = severity;
    evt.source = source;
    evt.pid = pid;
    evt.imageName = imageName;
    evt.title = title;
    evt.description = description;
    evt.mitreId = mitreId;
    evt.mitreTactic = mitreTactic;
    evt.evidence = evidence;
    evt.timestamp = std::chrono::system_clock::now();
    events_.push_back(std::move(evt));
}

std::vector<DetectionEvent> DetectionEngine::getAllEvents() const {
    std::shared_lock lock(mutex_);
    return events_;
}

std::vector<DetectionEvent> DetectionEngine::getEventsBySeverity(DetectionSeverity minSev) const {
    std::shared_lock lock(mutex_);
    std::vector<DetectionEvent> result;
    for (const auto& e : events_)
        if (static_cast<int>(e.severity) >= static_cast<int>(minSev))
            result.push_back(e);
    return result;
}

std::vector<DetectionEvent> DetectionEngine::getEventsForPid(DWORD pid) const {
    std::shared_lock lock(mutex_);
    std::vector<DetectionEvent> result;
    for (const auto& e : events_)
        if (e.pid == pid) result.push_back(e);
    return result;
}

std::vector<ProcessRiskProfile> DetectionEngine::buildRiskProfiles() const {
    std::shared_lock lock(mutex_);
    std::map<DWORD, ProcessRiskProfile> profiles;

    for (const auto& e : events_) {
        auto& p = profiles[e.pid];
        p.pid = e.pid;
        if (p.imageName.empty()) p.imageName = e.imageName;
        p.totalFindings++;
        switch (e.severity) {
            case DetectionSeverity::Critical: p.criticalCount++; break;
            case DetectionSeverity::High:     p.highCount++; break;
            case DetectionSeverity::Medium:   p.mediumCount++; break;
            default: break;
        }
        std::string src = sourceToString(e.source);
        if (std::find(p.sources.begin(), p.sources.end(), src) == p.sources.end())
            p.sources.push_back(src);
    }

    std::vector<ProcessRiskProfile> result;
    for (auto& [pid, p] : profiles) {
        p.overallScore = std::min(100, p.criticalCount * 30 + p.highCount * 15 + p.mediumCount * 5);
        result.push_back(std::move(p));
    }
    std::sort(result.begin(), result.end(),
        [](const ProcessRiskProfile& a, const ProcessRiskProfile& b) {
            return a.overallScore > b.overallScore;
        });
    return result;
}

size_t DetectionEngine::totalEvents() const {
    std::shared_lock lock(mutex_);
    return events_.size();
}

size_t DetectionEngine::criticalCount() const {
    std::shared_lock lock(mutex_);
    size_t c = 0;
    for (const auto& e : events_)
        if (e.severity == DetectionSeverity::Critical) c++;
    return c;
}

void DetectionEngine::displayAllEvents(DetectionSeverity minSev) const {
    auto evts = getEventsBySeverity(minSev);
    std::cout << "\n=== Detection Events (>=" << severityToString(minSev) << ") ===" << std::endl;
    std::cout << std::string(90, '-') << std::endl;
    if (evts.empty()) { std::cout << "  [+] No events." << std::endl; return; }
    for (const auto& e : evts) { e.display(); std::cout << std::endl; }
    std::cout << "  Total: " << evts.size() << " events" << std::endl;
}

void DetectionEngine::displayRiskProfiles() const {
    auto profiles = buildRiskProfiles();
    std::cout << "\n=== Process Risk Profiles ===" << std::endl;
    std::cout << std::string(100, '-') << std::endl;
    printf("  %-8s %-8s %-5s %-5s %-5s %-5s %-20ls %s\n",
        "PID", "Score", "Total", "Crit", "High", "Med", L"Image", "Sources");
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& p : profiles) {
        if (p.overallScore == 0) continue;
        std::string srcs;
        for (size_t i = 0; i < p.sources.size(); i++) {
            if (i > 0) srcs += ",";
            srcs += p.sources[i];
        }
        printf("  %-8u %-8d %-5d %-5d %-5d %-5d %-20ls %s\n",
            p.pid, p.overallScore, p.totalFindings,
            p.criticalCount, p.highCount, p.mediumCount,
            p.imageName.c_str(), srcs.c_str());
    }
}

void DetectionEngine::displayDashboard() const {
    std::shared_lock lock(mutex_);
    std::cout << "\n  ╔═══════════════════════════════════════════════╗" << std::endl;
    std::cout << "  ║        ZeroPhase EDR - Detection Dashboard     ║" << std::endl;
    std::cout << "  ╠═══════════════════════════════════════════════╣" << std::endl;

    int crit = 0, high = 0, med = 0, low = 0, info = 0;
    std::map<DetectionSource, int> bySrc;
    for (const auto& e : events_) {
        switch (e.severity) {
            case DetectionSeverity::Critical: crit++; break;
            case DetectionSeverity::High:     high++; break;
            case DetectionSeverity::Medium:   med++; break;
            case DetectionSeverity::Low:      low++; break;
            case DetectionSeverity::Info:     info++; break;
        }
        bySrc[e.source]++;
    }

    printf("  ║  Total Events: %-6zu                          ║\n", events_.size());
    printf("  ║  CRITICAL: %-4d  HIGH: %-4d  MEDIUM: %-4d      ║\n", crit, high, med);
    printf("  ║  LOW:      %-4d  INFO: %-4d                    ║\n", low, info);
    std::cout << "  ╠═══════════════════════════════════════════════╣" << std::endl;
    std::cout << "  ║  By Source:                                   ║" << std::endl;
    for (const auto& [src, count] : bySrc)
        printf("  ║    %-12s: %-6d                          ║\n", sourceToString(src), count);
    std::cout << "  ╚═══════════════════════════════════════════════╝" << std::endl;
}

void DetectionEngine::clearAll() {
    std::unique_lock lock(mutex_);
    events_.clear();
    nextId_ = 1;
}

} // namespace detection_intelligence
} // namespace zerophase
