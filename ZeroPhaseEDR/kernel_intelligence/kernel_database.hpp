#pragma once
#ifndef ZEROPHASE_KERNEL_DATABASE_HPP
#define ZEROPHASE_KERNEL_DATABASE_HPP
#include "kernel_info.hpp"
namespace zerophase { namespace kernel_intelligence {

class KernelDatabase {
public:
    void update() {
        std::unique_lock lock(mutex_);
        drivers_ = enumerateKernelDrivers();
        services_ = enumerateServices(false);
    }
    std::vector<DriverInfo> getDrivers() const { std::shared_lock lock(mutex_); return drivers_; }
    std::vector<ServiceInfo> getServices() const { std::shared_lock lock(mutex_); return services_; }
    std::vector<ServiceInfo> getKernelDriverServices() const {
        std::shared_lock lock(mutex_);
        std::vector<ServiceInfo> result;
        for (const auto& s : services_) if (s.isKernelDriver()) result.push_back(s);
        return result;
    }
    std::vector<ServiceInfo> getSuspiciousServices() const {
        std::shared_lock lock(mutex_);
        std::vector<ServiceInfo> result;
        for (const auto& s : services_) if (s.riskLevel != KernelRisk::None) result.push_back(s);
        return result;
    }

    void displayDrivers() const {
        auto drvs = getDrivers();
        std::cout << "\n=== Kernel Drivers ===" << std::endl;
        std::cout << std::string(90, '-') << std::endl;
        printf("  %-18s %-10s %-5s %-8s %-8s %s\n", "Base", "Size", "Loads", "Risk", "Sig", "Driver");
        std::cout << std::string(90, '-') << std::endl;
        for (const auto& d : drvs) d.displayCompact();
        std::cout << "  Total: " << drvs.size() << " drivers" << std::endl;
    }

    void displayServices(bool driversOnly = false) const {
        auto svcs = driversOnly ? getKernelDriverServices() : getServices();
        std::cout << "\n=== " << (driversOnly ? "Kernel Driver Services" : "All Services") << " ===" << std::endl;
        std::cout << std::string(100, '-') << std::endl;
        printf("  %-30ls %-10s %-8s %-8s %-8s %ls\n", L"Name", "State", "Start", "Type", "Risk", L"Binary");
        std::cout << std::string(100, '-') << std::endl;
        for (const auto& s : svcs) {
            std::wstring shortPath = s.binaryPath;
            if (shortPath.length() > 40) shortPath = L"..." + shortPath.substr(shortPath.length()-37);
            printf("  %-30ls %-10s %-8s %-8s %-8s %ls\n",
                s.serviceName.c_str(), s.stateToString(), s.startTypeToString(),
                s.isKernelDriver() ? "Driver" : "Win32",
                kernelRiskToString(s.riskLevel), shortPath.c_str());
        }
        std::cout << "  Total: " << svcs.size() << std::endl;
    }

    void displaySuspicious() const {
        auto sus = getSuspiciousServices();
        std::cout << "\n=== Suspicious Services ===" << std::endl;
        if (sus.empty()) { std::cout << "  [+] None detected." << std::endl; return; }
        for (const auto& s : sus) {
            printf("  [%s] %ls (%ls)\n", kernelRiskToString(s.riskLevel),
                s.serviceName.c_str(), s.displayName.c_str());
            std::cout << "    Binary: " << native::wstringToString(s.binaryPath) << std::endl;
            for (const auto& r : s.riskReasons) printf("    - %s\n", r.c_str());
        }
    }
private:
    mutable std::shared_mutex mutex_;
    std::vector<DriverInfo> drivers_;
    std::vector<ServiceInfo> services_;
};

} }
#endif
