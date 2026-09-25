#pragma once
/*
 * ZeroPhase EDR - Native Windows API Declarations
 *
 * Undocumented and semi-documented NT API structures and function prototypes
 * required for deep process/thread/memory introspection from user-mode.
 */

#ifndef ZEROPHASE_NATIVE_HPP
#define ZEROPHASE_NATIVE_HPP

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include <memory>
#include <optional>
#include <queue>
#include <algorithm>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <cstdint>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "psapi.lib")

namespace native {

// ============================================================================
// NTSTATUS Codes
// ============================================================================
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL     ((NTSTATUS)0xC0000023L)
#endif

// ============================================================================
// Process Information Classes (extended beyond winternl.h)
// ============================================================================
enum PROCESSINFOCLASS_EX {
    ProcessBasicInformation_Ex       = 0,
    ProcessDebugPort                 = 7,
    ProcessWow64Information          = 26,
    ProcessImageFileName             = 27,
    ProcessBreakOnTermination        = 29,
    ProcessCommandLineInformation    = 60,
    ProcessProtectionInformation     = 61,
};

// ============================================================================
// System Information Classes
// ============================================================================
enum SYSTEM_INFORMATION_CLASS_EX {
    SystemBasicInformation_Ex        = 0,
    SystemProcessInformation_Ex      = 5,
    SystemModuleInformation_Ex       = 11,
    SystemHandleInformation_Ex       = 16,
    SystemExtendedProcessInformation = 57,
    SystemFullProcessInformation     = 148,
};

// ============================================================================
// Thread Information Classes
// ============================================================================
enum THREADINFOCLASS_EX {
    ThreadBasicInformation_Ex        = 0,
    ThreadTimes                      = 1,
    ThreadQuerySetWin32StartAddress  = 9,
    ThreadIsTerminated               = 20,
};

// ============================================================================
// Memory Information Classes
// ============================================================================
enum MEMORY_INFORMATION_CLASS_EX {
    MemoryBasicInformation_Ex        = 0,
    MemoryWorkingSetInformation      = 1,
    MemoryMappedFilenameInformation  = 2,
    MemoryRegionInformation          = 3,
};

// ============================================================================
// Structures - System Process Information
// ============================================================================
typedef struct _SYSTEM_THREAD_INFORMATION_EX {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    PVOID         StartAddress;
    CLIENT_ID     ClientId;
    LONG          Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         ThreadState;
    ULONG         WaitReason;
} SYSTEM_THREAD_INFORMATION_EX, *PSYSTEM_THREAD_INFORMATION_EX;

typedef struct _SYSTEM_PROCESS_INFORMATION_EX {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    ULONG_PTR      UniqueProcessKey;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  ReadOperationCount;
    LARGE_INTEGER  WriteOperationCount;
    LARGE_INTEGER  OtherOperationCount;
    LARGE_INTEGER  ReadTransferCount;
    LARGE_INTEGER  WriteTransferCount;
    LARGE_INTEGER  OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_EX Threads[1];
} SYSTEM_PROCESS_INFORMATION_EX, *PSYSTEM_PROCESS_INFORMATION_EX;

// ============================================================================
// Structures - PEB (Process Environment Block) - 64-bit
// ============================================================================
typedef struct _PEB_LDR_DATA_EX {
    ULONG      Length;
    BOOLEAN    Initialized;
    HANDLE     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;
    BOOLEAN    ShutdownInProgress;
    HANDLE     ShutdownThreadId;
} PEB_LDR_DATA_EX, *PPEB_LDR_DATA_EX;

typedef struct _RTL_USER_PROCESS_PARAMETERS_EX {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID          Environment;
} RTL_USER_PROCESS_PARAMETERS_EX, *PRTL_USER_PROCESS_PARAMETERS_EX;

typedef struct _LDR_DATA_TABLE_ENTRY_EX {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID  SectionPointer;
            ULONG  CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY_EX, *PLDR_DATA_TABLE_ENTRY_EX;

// ============================================================================
// Structures - System Module Information
// ============================================================================
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ============================================================================
// Native API Function Typedefs
// ============================================================================
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    ULONG            ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    ULONG  MemoryInformationClass,
    PVOID  MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    PVOID  Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

// ============================================================================
// Native API Resolver - Lazy loads NT API functions from ntdll.dll
// ============================================================================
class NativeApi {
public:
    static NativeApi& instance() {
        static NativeApi inst;
        return inst;
    }

    pNtQuerySystemInformation   NtQuerySystemInformation   = nullptr;
    pNtQueryInformationProcess  NtQueryInformationProcess  = nullptr;
    pNtQueryInformationThread   NtQueryInformationThread   = nullptr;
    pNtQueryVirtualMemory       NtQueryVirtualMemory       = nullptr;
    pNtReadVirtualMemory        NtReadVirtualMemory        = nullptr;

    bool isInitialized() const { return initialized_; }

    bool initialize() {
        if (initialized_) return true;

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;

        NtQuerySystemInformation  = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
        NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        NtQueryInformationThread  = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
        NtQueryVirtualMemory      = (pNtQueryVirtualMemory)GetProcAddress(ntdll, "NtQueryVirtualMemory");
        NtReadVirtualMemory       = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");

        initialized_ = (NtQuerySystemInformation && NtQueryInformationProcess &&
                        NtQueryInformationThread && NtQueryVirtualMemory);
        return initialized_;
    }

private:
    NativeApi() { initialize(); }
    bool initialized_ = false;
};

// ============================================================================
// Utility Functions
// ============================================================================
inline std::wstring unicodeToWstring(const UNICODE_STRING& us) {
    if (!us.Buffer || us.Length == 0) return L"";
    return std::wstring(us.Buffer, us.Length / sizeof(WCHAR));
}

inline std::string wstringToString(const std::wstring& ws) {
    if (ws.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &result[0], size, nullptr, nullptr);
    return result;
}

inline std::wstring stringToWstring(const std::string& s) {
    if (s.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], size);
    return result;
}

inline std::string formatTimestamp(const LARGE_INTEGER& ft) {
    if (ft.QuadPart == 0) return "(none)";
    FILETIME fileTime;
    fileTime.dwLowDateTime = ft.LowPart;
    fileTime.dwHighDateTime = ft.HighPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&fileTime, &st);

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buf);
}

inline std::string formatSize(SIZE_T bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int unitIdx = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024.0 && unitIdx < 4) {
        size /= 1024.0;
        unitIdx++;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f %s", size, units[unitIdx]);
    return std::string(buf);
}

inline std::string protectionToString(DWORD protect) {
    std::string result;
    DWORD base = protect & 0xFF;
    switch (base) {
        case PAGE_NOACCESS:          result = "---"; break;
        case PAGE_READONLY:          result = "R--"; break;
        case PAGE_READWRITE:         result = "RW-"; break;
        case PAGE_WRITECOPY:         result = "WC-"; break;
        case PAGE_EXECUTE:           result = "--X"; break;
        case PAGE_EXECUTE_READ:      result = "R-X"; break;
        case PAGE_EXECUTE_READWRITE: result = "RWX"; break;
        case PAGE_EXECUTE_WRITECOPY: result = "WCX"; break;
        default:                     result = "???"; break;
    }
    if (protect & PAGE_GUARD)    result += "|GUARD";
    if (protect & PAGE_NOCACHE)  result += "|NOCACHE";
    return result;
}

inline std::string memoryStateToString(DWORD state) {
    switch (state) {
        case MEM_COMMIT:  return "COMMIT";
        case MEM_RESERVE: return "RESERVE";
        case MEM_FREE:    return "FREE";
        default:          return "UNKNOWN";
    }
}

inline std::string memoryTypeToString(DWORD type) {
    switch (type) {
        case MEM_IMAGE:   return "IMAGE";
        case MEM_MAPPED:  return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default:          return "UNKNOWN";
    }
}

inline std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    struct tm tm_now;
    localtime_s(&tm_now, &time_t_now);

    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03lld",
        tm_now.tm_year + 1900, tm_now.tm_mon + 1, tm_now.tm_mday,
        tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec, ms.count());
    return std::string(buf);
}

inline bool enablePrivilege(const wchar_t* privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

} // namespace native

#endif // ZEROPHASE_NATIVE_HPP
