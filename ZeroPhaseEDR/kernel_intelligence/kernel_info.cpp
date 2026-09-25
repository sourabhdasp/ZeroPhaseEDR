/*
 * ZeroPhase EDR - Kernel Intelligence: Implementation
 */

#include "kernel_info.hpp"

namespace zerophase {
namespace kernel_intelligence {

std::vector<DriverInfo> enumerateKernelDrivers() {
    std::vector<DriverInfo> results;
    auto& api = native::NativeApi::instance();
    if (!api.isInitialized()) return results;

    ULONG bufSize = 256 * 1024;
    std::vector<BYTE> buffer;
    NTSTATUS status;
    do {
        buffer.resize(bufSize);
        status = api.NtQuerySystemInformation(
            native::SystemModuleInformation_Ex,
            buffer.data(), bufSize, &bufSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) bufSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && bufSize < 32 * 1024 * 1024);

    if (status != STATUS_SUCCESS) return results;

    auto* modules = reinterpret_cast<native::RTL_PROCESS_MODULES*>(buffer.data());
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        auto& mod = modules->Modules[i];
        DriverInfo drv;
        drv.imageBase = mod.ImageBase;
        drv.imageSize = mod.ImageSize;
        drv.loadCount = mod.LoadCount;
        drv.fullPath = reinterpret_cast<const char*>(mod.FullPathName);
        drv.fileName = reinterpret_cast<const char*>(mod.FullPathName + mod.OffsetToFileName);

        // Convert \SystemRoot\ to C:\Windows\ for disk check
        std::string diskPath = drv.fullPath;
        if (diskPath.find("\\SystemRoot\\") == 0)
            diskPath = "C:\\Windows\\" + diskPath.substr(12);
        else if (diskPath.find("\\??\\") == 0)
            diskPath = diskPath.substr(4);

        drv.existsOnDisk = (GetFileAttributesA(diskPath.c_str()) != INVALID_FILE_ATTRIBUTES);
        analyzeDriverRisk(drv);
        results.push_back(std::move(drv));
    }
    return results;
}

std::vector<ServiceInfo> enumerateServices(bool driversOnly) {
    std::vector<ServiceInfo> results;

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return results;

    DWORD serviceType = driversOnly ? SERVICE_DRIVER : (SERVICE_WIN32 | SERVICE_DRIVER);
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;

    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType,
        SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

    std::vector<BYTE> buffer(bytesNeeded);
    if (EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, serviceType,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
        &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {

        auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < servicesReturned; i++) {
            ServiceInfo svc;
            svc.serviceName = services[i].lpServiceName;
            svc.displayName = services[i].lpDisplayName;
            svc.serviceType = services[i].ServiceStatusProcess.dwServiceType;
            svc.currentState = services[i].ServiceStatusProcess.dwCurrentState;
            svc.pid = services[i].ServiceStatusProcess.dwProcessId;

            // Get binary path and start type
            SC_HANDLE hSvc = OpenServiceW(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (hSvc) {
                DWORD needed = 0;
                QueryServiceConfigW(hSvc, nullptr, 0, &needed);
                if (needed > 0) {
                    std::vector<BYTE> cfgBuf(needed);
                    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                    if (QueryServiceConfigW(hSvc, cfg, needed, &needed)) {
                        if (cfg->lpBinaryPathName)
                            svc.binaryPath = cfg->lpBinaryPathName;
                        svc.startType = cfg->dwStartType;
                    }
                }
                CloseServiceHandle(hSvc);
            }

            analyzeServiceRisk(svc);
            results.push_back(std::move(svc));
        }
    }

    CloseServiceHandle(hSCM);
    return results;
}

void analyzeDriverRisk(DriverInfo& driver) {
    driver.riskLevel = KernelRisk::None;

    if (!driver.existsOnDisk) {
        driver.riskReasons.push_back("Driver not found on disk (phantom driver)");
        driver.riskLevel = KernelRisk::High;
    }
}

void analyzeServiceRisk(ServiceInfo& svc) {
    svc.riskLevel = KernelRisk::None;

    std::wstring lowerPath = svc.binaryPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    // Service binary in temp directory
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos) {
        svc.riskLevel = KernelRisk::High;
        svc.riskReasons.push_back("Service binary in TEMP directory");
    }

    // Service binary in user profile
    if (lowerPath.find(L"\\users\\") != std::wstring::npos &&
        lowerPath.find(L"\\program") == std::wstring::npos) {
        svc.riskLevel = KernelRisk::Medium;
        svc.riskReasons.push_back("Service binary in user profile");
    }

    // Kernel driver with auto-start from unusual location
    if (svc.isKernelDriver() && svc.startType == SERVICE_AUTO_START) {
        if (lowerPath.find(L"\\windows\\") == std::wstring::npos &&
            lowerPath.find(L"\\system32\\") == std::wstring::npos &&
            lowerPath.find(L"\\program files") == std::wstring::npos) {
            svc.riskLevel = KernelRisk::High;
            svc.riskReasons.push_back("Auto-start kernel driver from non-standard path");
        }
    }
}

} // namespace kernel_intelligence
} // namespace zerophase
