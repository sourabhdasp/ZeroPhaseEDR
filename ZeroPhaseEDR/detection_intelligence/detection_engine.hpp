#pragma once
#ifndef ZEROPHASE_DETECTION_ENGINE_HPP
#define ZEROPHASE_DETECTION_ENGINE_HPP

#include "detection_info.hpp"

namespace zerophase {
namespace detection_intelligence {

class DetectionEngine {
public:
    DetectionEngine() = default;

    // Add a detection event from any source
    void addEvent(DetectionSeverity severity, DetectionSource source,
                  DWORD pid, const std::wstring& imageName,
                  const std::string& title, const std::string& description,
                  const std::string& mitreId = "", const std::string& mitreTactic = "",
                  const std::vector<std::string>& evidence = {});

    // Get events
    std::vector<DetectionEvent> getAllEvents() const;
    std::vector<DetectionEvent> getEventsBySeverity(DetectionSeverity minSeverity) const;
    std::vector<DetectionEvent> getEventsForPid(DWORD pid) const;

    // Build per-process risk profiles
    std::vector<ProcessRiskProfile> buildRiskProfiles() const;

    // Statistics
    size_t totalEvents() const;
    size_t criticalCount() const;

    // Display
    void displayAllEvents(DetectionSeverity minSeverity = DetectionSeverity::Info) const;
    void displayRiskProfiles() const;
    void displayDashboard() const;

    // Clear
    void clearAll();

private:
    mutable std::shared_mutex mutex_;
    std::vector<DetectionEvent> events_;
    DWORD nextId_ = 1;
};

} // namespace detection_intelligence
} // namespace zerophase

#endif
