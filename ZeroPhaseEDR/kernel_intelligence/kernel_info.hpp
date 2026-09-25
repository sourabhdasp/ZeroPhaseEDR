#pragma once
/*
 * ZeroPhase EDR - Kernel Intelligence (User-Mode)
 *
 * User-mode enumeration of kernel-related artifacts:
 * - Loaded kernel drivers via NtQuerySystemInformation
 * - Windows services via SCM API
 * - Driver file integrity (on-disk signature verification)
 * - Suspicious driver/service detection
 */

#ifndef ZEROPHASE_KERNEL_INFO_HPP
#define ZEROPHASE_KERNEL_INFO_HPP

#include "../native.hpp"

namespace zerophase {
namespace kernel_intelligence {

enum class KernelRisk : int { None=0, Low=1, Medium=2, High=3, Critical=4 };

inline const char* kernelRiskToString(KernelRisk r) {
    switch(r) {
        case KernelRisk::None: return "NONE"; case KernelRisk::Low: return "LOW";
        case KernelRisk::Medium: return "MEDIUM"; case KernelRisk::High: return "HIGH";
        case KernelRisk::Critical: return "CRITICAL"; default: return "?";
    }
}

struct DriverInfo {
    PVOID  imageBase      = nullptr;
    ULONG  imageSize      = 0;
    USHORT loadCount      = 0;
    std::string fullPath;
    std::string fileName;
    bool   existsOnDisk   = false;
    bool   isSigned       = false;
    KernelRisk riskLevel  = KernelRisk::None;
    std::vector<std::string> riskReasons;

    void displayCompact() const {
        printf("  0x%016llX %-10s %-5u %-8s %-8s %s\n",
            (ULONGLONG)imageBase, native::formatSize(imageSize).c_str(),
            loadCount, kernelRiskToString(riskLevel),
            existsOnDisk ? (isSigned ? "Signed" : "Unsign") : "PHANTOM",
            fileName.c_str());
    }
};

struct ServiceInfo {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring binaryPath;
    DWORD  serviceType    = 0;
    DWORD  startType      = 0;
    DWORD  currentState   = 0;
    DWORD  pid            = 0;
    KernelRisk riskLevel  = KernelRisk::None;
    std::vector<std::string> riskReasons;

    const char* stateToString() const {
        switch(currentState) {
            case SERVICE_STOPPED: return "Stopped"; case SERVICE_RUNNING: return "Running";
            case SERVICE_PAUSED: return "Paused"; case SERVICE_START_PENDING: return "Starting";
            case SERVICE_STOP_PENDING: return "Stopping"; default: return "Unknown";
        }
    }
    const char* startTypeToString() const {
        switch(startType) {
            case SERVICE_AUTO_START: return "Auto"; case SERVICE_BOOT_START: return "Boot";
            case SERVICE_DEMAND_START: return "Manual"; case SERVICE_DISABLED: return "Disabled";
            case SERVICE_SYSTEM_START: return "System"; default: return "Unknown";
        }
    }
    bool isKernelDriver() const { return serviceType == SERVICE_KERNEL_DRIVER || serviceType == SERVICE_FILE_SYSTEM_DRIVER; }
};

// Free functions
std::vector<DriverInfo> enumerateKernelDrivers();
std::vector<ServiceInfo> enumerateServices(bool driversOnly = false);
void analyzeDriverRisk(DriverInfo& driver);
void analyzeServiceRisk(ServiceInfo& svc);

} // namespace kernel_intelligence
} // namespace zerophase

#endif
