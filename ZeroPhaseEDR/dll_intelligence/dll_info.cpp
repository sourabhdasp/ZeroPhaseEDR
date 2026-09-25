/*
 * ZeroPhase EDR - DLL Intelligence: DLL Info Implementation
 *
 * Enumerates loaded DLLs with signature verification, location
 * classification, known-DLL analysis, and sideloading detection.
 */

#include "dll_info.hpp"

namespace zerophase {
namespace dll_intelligence {

// ============================================================================
// Known DLLs list (from HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)
// ============================================================================
static const std::set<std::wstring> g_knownDlls = {
    L"advapi32.dll", L"clbcatq.dll", L"combase.dll", L"comdlg32.dll",
    L"coml2.dll", L"difxapi.dll", L"gdi32.dll", L"gdiplus.dll",
    L"imagehlp.dll", L"imm32.dll", L"kernel32.dll", L"kernelbase.dll",
    L"msctf.dll", L"msvcrt.dll", L"normaliz.dll", L"nsi.dll",
    L"ntdll.dll", L"ole32.dll", L"oleaut32.dll", L"psapi.dll",
    L"rpcrt4.dll", L"sechost.dll", L"setupapi.dll", L"shell32.dll",
    L"shcore.dll", L"shlwapi.dll", L"user32.dll", L"wldap32.dll",
    L"wow64.dll", L"wow64cpu.dll", L"wow64win.dll", L"ws2_32.dll",
};

// ============================================================================
// Verify Authenticode signature using WinVerifyTrust
// ============================================================================
SignatureStatus verifyFileSignature(const std::wstring& filePath, std::wstring& outSignerName) {
    outSignerName.clear();

    if (filePath.empty()) return SignatureStatus::Error;

    // Check if file exists
    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return SignatureStatus::Error;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG result = WinVerifyTrust(NULL, &actionGuid, &trustData);

    // Clean up state
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &trustData);

    switch (result) {
        case ERROR_SUCCESS:
            return SignatureStatus::Valid;
        case TRUST_E_NOSIGNATURE: {
            DWORD err = GetLastError();
            if (err == TRUST_E_NOSIGNATURE || err == TRUST_E_SUBJECT_FORM_UNKNOWN)
                return SignatureStatus::NotSigned;
            return SignatureStatus::Error;
        }
        case TRUST_E_EXPLICIT_DISTRUST:
            return SignatureStatus::Untrusted;
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            return SignatureStatus::Invalid;
        case CRYPT_E_SECURITY_SETTINGS:
            return SignatureStatus::Untrusted;
        default:
            // Could be catalog signed — check that
            return SignatureStatus::NotSigned;
    }
}

// ============================================================================
// Classify DLL location
// ============================================================================
DllLocation classifyDllLocation(const std::wstring& dllPath, const std::wstring& processPath) {
    if (dllPath.empty()) return DllLocation::Unknown;

    std::wstring lowerPath = dllPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    // System32
    if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\system32\\") == 0)
        return DllLocation::System32;

    // SysWOW64
    if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos)
        return DllLocation::SysWOW64;

    // Windows directory
    if (lowerPath.find(L"\\windows\\") != std::wstring::npos)
        return DllLocation::WindowsDir;

    // Program Files
    if (lowerPath.find(L"\\program files\\") != std::wstring::npos ||
        lowerPath.find(L"\\program files (x86)\\") != std::wstring::npos)
        return DllLocation::ProgramFiles;

    // Temp directory
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos)
        return DllLocation::TempDir;

    // Downloads
    if (lowerPath.find(L"\\downloads\\") != std::wstring::npos)
        return DllLocation::DownloadsDir;

    // User profile
    if (lowerPath.find(L"\\users\\") != std::wstring::npos)
        return DllLocation::UserDir;

    // Same directory as the process executable
    if (!processPath.empty()) {
        std::wstring processDir = processPath;
        auto pos = processDir.find_last_of(L'\\');
        if (pos != std::wstring::npos) {
            processDir = processDir.substr(0, pos + 1);
            std::wstring lowerProcDir = processDir;
            std::transform(lowerProcDir.begin(), lowerProcDir.end(), lowerProcDir.begin(), ::towlower);
            if (lowerPath.find(lowerProcDir) == 0)
                return DllLocation::AppDir;
        }
    }

    return DllLocation::Other;
}

// ============================================================================
// Check KnownDLLs
// ============================================================================
bool isKnownDll(const std::wstring& dllName) {
    std::wstring lower = dllName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return g_knownDlls.count(lower) > 0;
}

// ============================================================================
// Enumerate all DLLs for a process
// ============================================================================
std::vector<DllInfo> enumerateProcessDlls(DWORD pid, bool verifySignatures) {
    std::vector<DllInfo> results;

    // Get process image path
    std::wstring processPath;
    {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            wchar_t path[MAX_PATH * 2] = {};
            DWORD size = MAX_PATH * 2;
            if (QueryFullProcessImageNameW(hProc, 0, path, &size))
                processPath.assign(path, size);
            CloseHandle(hProc);
        }
    }

    std::wstring processImageName;
    auto pos = processPath.find_last_of(L'\\');
    if (pos != std::wstring::npos) processImageName = processPath.substr(pos + 1);

    // Enumerate via Toolhelp32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        // Fallback to PSAPI
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return results;

        HMODULE hMods[2048];
        DWORD cbNeeded;
        if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
                DllInfo dll;
                dll.ownerPid = pid;
                dll.ownerImageName = processImageName;
                dll.baseAddress = hMods[i];

                wchar_t modName[MAX_PATH] = {}, modPath[MAX_PATH * 2] = {};
                MODULEINFO mi = {};
                GetModuleBaseNameW(hProcess, hMods[i], modName, MAX_PATH);
                GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH * 2);
                GetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi));

                dll.moduleName = modName;
                dll.fullPath = modPath;
                dll.sizeOfImage = mi.SizeOfImage;
                dll.firstSeen = std::chrono::system_clock::now();
                dll.lastUpdated = dll.firstSeen;

                // Check if file exists on disk
                dll.existsOnDisk = (GetFileAttributesW(modPath) != INVALID_FILE_ATTRIBUTES);
                dll.phantomDll = !dll.existsOnDisk && !dll.fullPath.empty();

                // Location classification
                dll.location = classifyDllLocation(dll.fullPath, processPath);

                // Known DLL check
                dll.isKnownDll = isKnownDll(dll.moduleName);
                dll.isSystemDll = (dll.location == DllLocation::System32 ||
                                   dll.location == DllLocation::SysWOW64);

                // Signature verification (optional, expensive)
                if (verifySignatures && dll.existsOnDisk) {
                    dll.signatureStatus = verifyFileSignature(dll.fullPath, dll.signerName);
                    // Check if Microsoft signed
                    std::wstring lowerSigner = dll.signerName;
                    std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
                    dll.isMicrosoftDll = (lowerSigner.find(L"microsoft") != std::wstring::npos);
                }

                // Risk analysis
                analyzeDllRisk(dll);
                results.push_back(std::move(dll));
            }
        }
        CloseHandle(hProcess);
        return results;
    }

    // Toolhelp32 path
    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    auto now = std::chrono::system_clock::now();

    if (Module32FirstW(snap, &me)) {
        do {
            DllInfo dll;
            dll.ownerPid = pid;
            dll.ownerImageName = processImageName;
            dll.baseAddress = me.modBaseAddr;
            dll.sizeOfImage = me.modBaseSize;
            dll.moduleName = me.szModule;
            dll.fullPath = me.szExePath;
            dll.firstSeen = now;
            dll.lastUpdated = now;

            dll.existsOnDisk = (GetFileAttributesW(me.szExePath) != INVALID_FILE_ATTRIBUTES);
            dll.phantomDll = !dll.existsOnDisk && wcslen(me.szExePath) > 0;

            dll.location = classifyDllLocation(dll.fullPath, processPath);
            dll.isKnownDll = isKnownDll(dll.moduleName);
            dll.isSystemDll = (dll.location == DllLocation::System32 ||
                               dll.location == DllLocation::SysWOW64);

            if (verifySignatures && dll.existsOnDisk) {
                dll.signatureStatus = verifyFileSignature(dll.fullPath, dll.signerName);
                std::wstring lowerSigner = dll.signerName;
                std::transform(lowerSigner.begin(), lowerSigner.end(), lowerSigner.begin(), ::towlower);
                dll.isMicrosoftDll = (lowerSigner.find(L"microsoft") != std::wstring::npos);
            }

            analyzeDllRisk(dll);
            results.push_back(std::move(dll));
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return results;
}

// ============================================================================
// Compute DLL summary
// ============================================================================
ProcessDllSummary computeDllSummary(const std::vector<DllInfo>& dlls, DWORD pid) {
    ProcessDllSummary summary;
    summary.pid = pid;
    summary.totalDlls = static_cast<DWORD>(dlls.size());

    for (const auto& dll : dlls) {
        if (summary.imageName.empty()) summary.imageName = dll.ownerImageName;

        switch (dll.signatureStatus) {
            case SignatureStatus::Valid:         summary.signedCount++; break;
            case SignatureStatus::CatalogSigned: summary.catalogSignedCount++; break;
            case SignatureStatus::NotSigned:     summary.unsignedCount++; break;
            default: break;
        }
        if (dll.riskLevel != DllRiskLevel::None) summary.suspiciousCount++;
        if (dll.phantomDll) summary.phantomCount++;
        if (dll.sideloadSuspect) summary.sideloadCount++;
        if (static_cast<int>(dll.riskLevel) > static_cast<int>(summary.highestRisk))
            summary.highestRisk = dll.riskLevel;
    }
    return summary;
}

// ============================================================================
// Risk analysis for a DLL
// ============================================================================
void analyzeDllRisk(DllInfo& dll) {
    dll.riskScore = 0;
    dll.riskReasons.clear();
    dll.riskLevel = DllRiskLevel::None;
    dll.sideloadSuspect = false;

    // 1. Phantom DLL (loaded but not on disk)
    if (dll.phantomDll) {
        dll.riskScore += 40;
        dll.riskReasons.push_back("DLL not found on disk (phantom/reflective load)");
    }

    // 2. DLL loaded from temp directory
    if (dll.location == DllLocation::TempDir) {
        dll.riskScore += 30;
        dll.riskReasons.push_back("DLL loaded from TEMP directory");
    }

    // 3. DLL loaded from Downloads
    if (dll.location == DllLocation::DownloadsDir) {
        dll.riskScore += 25;
        dll.riskReasons.push_back("DLL loaded from Downloads directory");
    }

    // 4. Known DLL loaded from non-system path (DLL hijacking)
    if (dll.isKnownDll && !dll.isSystemDll && dll.location != DllLocation::Unknown) {
        dll.riskScore += 50;
        dll.sideloadSuspect = true;
        dll.riskReasons.push_back("Known system DLL loaded from non-system path (possible DLL hijacking)");
    }

    // 5. Unsigned DLL (only flag if signatures were checked)
    if (dll.signatureStatus == SignatureStatus::NotSigned) {
        // Unsigned DLL from a non-standard location is more suspicious
        if (dll.location == DllLocation::TempDir || dll.location == DllLocation::DownloadsDir ||
            dll.location == DllLocation::UserDir) {
            dll.riskScore += 20;
            dll.riskReasons.push_back("Unsigned DLL from suspicious location");
        } else if (dll.location != DllLocation::System32 && dll.location != DllLocation::SysWOW64 &&
                   dll.location != DllLocation::WindowsDir) {
            dll.riskScore += 10;
            dll.riskReasons.push_back("Unsigned DLL");
        }
    }

    // 6. Invalid or untrusted signature
    if (dll.signatureStatus == SignatureStatus::Invalid) {
        dll.riskScore += 35;
        dll.riskReasons.push_back("DLL has invalid Authenticode signature");
    }
    if (dll.signatureStatus == SignatureStatus::Untrusted) {
        dll.riskScore += 25;
        dll.riskReasons.push_back("DLL signed by untrusted certificate");
    }

    // 7. DLL sideloading: non-system DLL loaded alongside a system process
    std::wstring lowerOwner = dll.ownerImageName;
    std::transform(lowerOwner.begin(), lowerOwner.end(), lowerOwner.begin(), ::towlower);
    bool isSystemProcess = (lowerOwner == L"svchost.exe" || lowerOwner == L"lsass.exe" ||
                           lowerOwner == L"services.exe" || lowerOwner == L"csrss.exe");
    if (isSystemProcess && dll.location == DllLocation::TempDir) {
        dll.riskScore += 30;
        dll.sideloadSuspect = true;
        dll.riskReasons.push_back("DLL loaded into system process from temp directory");
    }

    // Calculate risk level
    if (dll.riskScore >= 70)
        dll.riskLevel = DllRiskLevel::Critical;
    else if (dll.riskScore >= 50)
        dll.riskLevel = DllRiskLevel::High;
    else if (dll.riskScore >= 30)
        dll.riskLevel = DllRiskLevel::Medium;
    else if (dll.riskScore >= 10)
        dll.riskLevel = DllRiskLevel::Low;
}

} // namespace dll_intelligence
} // namespace zerophase
