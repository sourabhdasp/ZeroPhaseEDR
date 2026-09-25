/*
 * ZeroPhase EDR - Process Intelligence: Session Tracker Implementation
 */

#include "session_tracker.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Enumerate active Windows sessions via WTS API
// ============================================================================
std::vector<SessionInfo> SessionTracker::enumerateSessions() {
    sessions_.clear();
    std::vector<SessionInfo> result;

    PWTS_SESSION_INFOW pSessions = nullptr;
    DWORD count = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &count)) {
        return result;
    }

    for (DWORD i = 0; i < count; i++) {
        SessionInfo info;
        info.sessionId   = pSessions[i].SessionId;
        info.stationName = pSessions[i].pWinStationName ? pSessions[i].pWinStationName : L"";
        info.state       = pSessions[i].State;

        // Query username for this session
        LPWSTR pBuffer = nullptr;
        DWORD bytesReturned = 0;

        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, info.sessionId,
            WTSUserName, &pBuffer, &bytesReturned)) {
            if (pBuffer && bytesReturned > sizeof(WCHAR)) {
                info.userName = pBuffer;
            }
            WTSFreeMemory(pBuffer);
        }

        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, info.sessionId,
            WTSDomainName, &pBuffer, &bytesReturned)) {
            if (pBuffer && bytesReturned > sizeof(WCHAR)) {
                info.domainName = pBuffer;
            }
            WTSFreeMemory(pBuffer);
        }

        sessions_[info.sessionId] = info;
        result.push_back(info);
    }

    WTSFreeMemory(pSessions);
    return result;
}

// ============================================================================
// Map processes to sessions (update process counts)
// ============================================================================
void SessionTracker::mapProcessesToSessions(const ProcessDatabase& db) {
    // Reset counts
    for (auto& [id, sess] : sessions_) {
        sess.processCount = 0;
    }

    auto processes = db.getAll();
    for (const auto& proc : processes) {
        auto it = sessions_.find(proc.sessionId);
        if (it != sessions_.end()) {
            it->second.processCount++;
        }
    }
}

// ============================================================================
// Display session information
// ============================================================================
std::string SessionTracker::connectStateToString(WTS_CONNECTSTATE_CLASS state) {
    switch (state) {
        case WTSActive:       return "Active";
        case WTSConnected:    return "Connected";
        case WTSConnectQuery: return "ConnectQuery";
        case WTSShadow:       return "Shadow";
        case WTSDisconnected: return "Disconnected";
        case WTSIdle:         return "Idle";
        case WTSListen:       return "Listen";
        case WTSReset:        return "Reset";
        case WTSDown:         return "Down";
        case WTSInit:         return "Init";
        default:              return "Unknown";
    }
}

void SessionTracker::displaySessions() {
    auto sessions = enumerateSessions();

    std::cout << "\n=== Windows Sessions ===" << std::endl;
    std::cout << std::string(90, '-') << std::endl;
    printf("  %-6s %-15s %-20s %-20s %-12s %s\n",
        "SessID", "Station", "Domain", "User", "State", "Processes");
    std::cout << std::string(90, '-') << std::endl;

    for (const auto& sess : sessions) {
        printf("  %-6u %-15ls %-20ls %-20ls %-12s %d\n",
            sess.sessionId,
            sess.stationName.c_str(),
            sess.domainName.c_str(),
            sess.userName.c_str(),
            connectStateToString(sess.state).c_str(),
            sess.processCount);
    }
    std::cout << "\n  Total sessions: " << sessions.size() << std::endl;
}

// ============================================================================
// Display processes grouped by session
// ============================================================================
void SessionTracker::displayBySession(const ProcessDatabase& db) {
    enumerateSessions();
    mapProcessesToSessions(db);

    std::cout << "\n=== Processes by Session ===" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    auto processes = db.getAll();

    // Group by session
    std::map<DWORD, std::vector<const ProcessInfo*>> bySession;
    for (const auto& proc : processes) {
        bySession[proc.sessionId].push_back(&proc);
    }

    for (const auto& [sessId, procs] : bySession) {
        auto it = sessions_.find(sessId);
        std::wstring user = (it != sessions_.end() && !it->second.userName.empty())
            ? it->second.userName : L"<system>";

        printf("\n  Session %u (%ls) - %zu processes\n",
            sessId, user.c_str(), procs.size());
        std::cout << "  " << std::string(60, '-') << std::endl;

        for (const auto* p : procs) {
            printf("    [%u] %ls\n", p->pid, p->imageName.c_str());
        }
    }
}

} // namespace process_intelligence
} // namespace zerophase
