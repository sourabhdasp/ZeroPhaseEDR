#pragma once
/*
 * ZeroPhase EDR - Process Intelligence: Session Tracker
 *
 * Tracks Windows logon sessions and maps processes to sessions.
 * Useful for detecting:
 * - Processes running in unusual sessions
 * - Lateral movement (new logon sessions)
 * - Service account abuse
 */

#ifndef ZEROPHASE_SESSION_TRACKER_HPP
#define ZEROPHASE_SESSION_TRACKER_HPP

#include "process_database.hpp"

namespace zerophase {
namespace process_intelligence {

// ============================================================================
// Session Information
// ============================================================================
struct SessionInfo {
    DWORD  sessionId       = 0;
    std::wstring userName;
    std::wstring domainName;
    std::wstring stationName;
    WTS_CONNECTSTATE_CLASS state = WTSDisconnected;
    int    processCount    = 0;
};

// ============================================================================
// Session Tracker
// ============================================================================
class SessionTracker {
public:
    // Enumerate all active sessions
    std::vector<SessionInfo> enumerateSessions();

    // Map processes to their sessions
    void mapProcessesToSessions(const ProcessDatabase& db);

    // Display session information
    void displaySessions();

    // Display processes grouped by session
    void displayBySession(const ProcessDatabase& db);

private:
    std::map<DWORD, SessionInfo> sessions_;

    static std::string connectStateToString(WTS_CONNECTSTATE_CLASS state);
};

} // namespace process_intelligence
} // namespace zerophase

#endif // ZEROPHASE_SESSION_TRACKER_HPP
