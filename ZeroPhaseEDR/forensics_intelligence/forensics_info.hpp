#pragma once
/*
 * ZeroPhase EDR - Forensics Intelligence
 *
 * Artifact extraction and timeline building for incident response:
 * - Process creation timeline
 * - Detection event timeline
 * - Export findings to JSON/CSV
 * - Snapshot system state
 */

#ifndef ZEROPHASE_FORENSICS_INFO_HPP
#define ZEROPHASE_FORENSICS_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace forensics_intelligence {

struct TimelineEntry {
    std::chrono::system_clock::time_point timestamp;
    std::string source;   // "Process", "Detection", "Thread", etc.
    std::string action;   // "Created", "Terminated", "Alert", etc.
    DWORD pid = 0;
    std::wstring imageName;
    std::string detail;
};

class ForensicsEngine {
public:
    void addEntry(const std::string& source, const std::string& action,
                  DWORD pid, const std::wstring& imageName, const std::string& detail) {
        std::lock_guard lock(mutex_);
        TimelineEntry e;
        e.timestamp = std::chrono::system_clock::now();
        e.source = source; e.action = action;
        e.pid = pid; e.imageName = imageName; e.detail = detail;
        timeline_.push_back(std::move(e));
    }

    void displayTimeline(int maxEntries = 100) const {
        std::lock_guard lock(mutex_);
        std::cout << "\n=== Forensics Timeline ===" << std::endl;
        std::cout << std::string(100, '-') << std::endl;
        printf("  %-22s %-10s %-12s %-8s %-20ls %s\n",
            "Timestamp", "Source", "Action", "PID", L"Image", "Detail");
        std::cout << std::string(100, '-') << std::endl;

        int start = (int)timeline_.size() - maxEntries;
        if (start < 0) start = 0;
        for (int i = start; i < (int)timeline_.size(); i++) {
            const auto& e = timeline_[i];
            printf("  %-22s %-10s %-12s %-8u %-20ls %s\n",
                native::getCurrentTimestamp().c_str(),
                e.source.c_str(), e.action.c_str(),
                e.pid, e.imageName.c_str(),
                e.detail.substr(0, 40).c_str());
        }
        std::cout << "  Total: " << timeline_.size() << " entries" << std::endl;
    }

    bool exportToFile(const std::string& filePath) const {
        std::lock_guard lock(mutex_);
        std::ofstream out(filePath);
        if (!out.is_open()) return false;

        out << "Timestamp,Source,Action,PID,Image,Detail\n";
        for (const auto& e : timeline_) {
            out << native::getCurrentTimestamp() << ","
                << e.source << "," << e.action << ","
                << e.pid << "," << native::wstringToString(e.imageName) << ","
                << "\"" << e.detail << "\"\n";
        }
        return true;
    }

    size_t entryCount() const { std::lock_guard lock(mutex_); return timeline_.size(); }

    void takeSnapshot(const std::string& filePath) const {
        std::ofstream out(filePath);
        if (!out.is_open()) return;

        out << "=== ZeroPhase EDR System Snapshot ===" << std::endl;
        out << "Timestamp: " << native::getCurrentTimestamp() << std::endl;
        out << "Timeline entries: " << timeline_.size() << std::endl;

        // Enumerate running processes
        out << "\n=== Running Processes ===" << std::endl;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    out << "PID:" << pe.th32ProcessID << " PPID:" << pe.th32ParentProcessID
                        << " " << native::wstringToString(pe.szExeFile) << std::endl;
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        out << "\n=== End Snapshot ===" << std::endl;
    }

private:
    mutable std::mutex mutex_;
    std::vector<TimelineEntry> timeline_;
};

} // namespace forensics_intelligence
} // namespace zerophase

#endif
