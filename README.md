<p align="center">
  <img src="ZeroPhaseEDR/ZeroPhaseEDR/zp.png" alt="ZeroPhase EDR" width="200">
</p>

<h1 align="center">ZeroPhase EDR</h1>

<p align="center">
  <strong>Endpoint Detection &amp; Response — User-Mode Agent</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/arch-x64-green?style=flat-square" alt="Architecture">
  <img src="https://img.shields.io/badge/language-C%2B%2B17-orange?style=flat-square" alt="Language">
  <img src="https://img.shields.io/badge/GUI-ImGui%20%2B%20DirectX11-purple?style=flat-square" alt="GUI">
  <img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/phases-11%2F11%20complete-brightgreen?style=flat-square" alt="Phases">
  <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-50%2B%20rules-yellow?style=flat-square" alt="MITRE">
  <img src="https://img.shields.io/badge/detections-10%20injection%20types-critical?style=flat-square&color=d63031" alt="Detections">
</p>

---

## Overview

ZeroPhase EDR is a **user-mode endpoint detection and response agent** for Windows built entirely in C++17. It provides real-time automated scanning across 11 intelligence modules with a professional GUI dashboard powered by Dear ImGui and DirectX11.

ZeroPhase detects threats by correlating signals across process lineage, thread behavior, memory patterns, DLL integrity, command-line analysis, code injection indicators, and syscall tampering — all without a kernel driver.

### Key Capabilities

- **Automatic background scanning** with configurable light / full / deep scan cycles
- **Real-time dashboard** with live charts, severity breakdown, detection source donut, and scan trend
- **50+ MITRE ATT&CK detection rules** covering T1055 (Injection), T1059 (Execution), T1003 (Credential Dumping), T1105 (Tool Transfer), T1490 (Inhibit Recovery), and more
- **10 code injection techniques** detected: remote thread, process hollowing, reflective DLL, module stomping, APC injection, thread hijack, early bird, phantom DLL
- **Authenticode signature verification** for every loaded DLL
- **Syscall stub integrity** checking with ntdll on-disk comparison
- **Shannon entropy analysis** for packed/encrypted code detection
- **Zero external dependencies** beyond the Windows SDK and Dear ImGui

---

## Architecture

```
ZeroPhaseEDR/
├── ZeroPhaseEDR.sln
├── ZeroPhaseEDR/
│   ├── gui_main.cpp                   # GUI entry point (WinMain)
│   ├── native.hpp                     # NT API declarations & utilities
│   ├── resource.rc                    # Embedded icon & version info
│   │
│   ├── gui/                           # Dashboard & rendering
│   │   ├── renderer.hpp               # DirectX11 + ImGui init, resize handling
│   │   ├── theme.hpp                  # Enterprise light theme & color palette
│   │   ├── dashboard.hpp              # Responsive dashboard with charts
│   │   └── auto_scanner.hpp           # Background scanning engine
│   │
│   ├── process_intelligence/          # Phase 1 — Process analysis
│   │   ├── process_info.hpp/cpp       # Rich process info with risk scoring
│   │   ├── process_database.hpp/cpp   # Thread-safe process DB with diffing
│   │   ├── lineage_detector.hpp/cpp   # Parent-child anomaly detection
│   │   └── session_tracker.hpp/cpp    # Windows session enumeration
│   │
│   ├── thread_intelligence/           # Phase 2 — Thread analysis
│   │   ├── thread_info.hpp/cpp        # Thread info with start address resolution
│   │   ├── thread_database.hpp/cpp    # Thread lifecycle tracking
│   │   ├── thread_monitor.hpp/cpp     # Background thread monitor
│   │   └── stack_walker.hpp/cpp       # StackWalk64 call stack capture
│   │
│   ├── memory_intelligence/           # Phase 3 — Memory analysis
│   │   ├── memory_info.hpp/cpp        # Memory region classification & risk
│   │   ├── memory_database.hpp/cpp    # Memory change tracking
│   │   ├── memory_monitor.hpp/cpp     # Memory watch engine
│   │   └── entropy_analysis.hpp/cpp   # Shannon entropy scanner
│   │
│   ├── dll_intelligence/              # Phase 4 — DLL analysis
│   │   ├── dll_info.hpp/cpp           # Authenticode, sideloading, KnownDLL
│   │   ├── dll_database.hpp/cpp       # DLL load/unload tracking
│   │   └── dll_monitor.hpp/cpp        # DLL alert engine
│   │
│   ├── commandline_intelligence/      # Phase 5 — Command line analysis
│   │   ├── commandline_info.hpp/cpp   # Command line collection
│   │   ├── commandline_analyzer.hpp/cpp # 50+ MITRE rules, base64 decode
│   │   ├── commandline_database.hpp/cpp # Analyzed command DB
│   │   └── commandline_monitor.hpp    # Monitor placeholder
│   │
│   ├── injection_intelligence/        # Phase 6 — Injection detection
│   │   ├── injection_info.hpp/cpp     # 10 injection technique types
│   │   ├── injection_detector.hpp/cpp # Multi-signal correlation detector
│   │   ├── injection_database.hpp/cpp # Findings database
│   │   └── injection_monitor.hpp      # Monitor placeholder
│   │
│   ├── syscall_intelligence/          # Phase 7 — Syscall analysis
│   │   ├── syscall_info.hpp/cpp       # Stub status, direct syscall findings
│   │   ├── syscall_detector.hpp/cpp   # ntdll export parsing, stub verify
│   │   ├── syscall_database.hpp       # Scan result DB
│   │   └── syscall_monitor.hpp        # Monitor wrapper
│   │
│   ├── kernel_intelligence/           # Phase 8 — Kernel visibility (user-mode)
│   │   ├── kernel_info.hpp/cpp        # Driver & service enumeration
│   │   └── kernel_database.hpp        # Driver/service DB with display
│   │
│   ├── detection_intelligence/        # Phase 9 — Correlation engine
│   │   ├── detection_info.hpp         # Unified detection event types
│   │   └── detection_engine.hpp/cpp   # Cross-module correlator & dashboard
│   │
│   ├── forensics_intelligence/        # Phase 10 — Forensics
│   │   └── forensics_info.hpp         # Timeline, CSV export, snapshots
│   │
│   ├── production_intelligence/       # Phase 11 — Operational health
│   │   └── production_info.hpp        # Scan metrics, resource monitoring
│   │
│   └── imgui/                         # Dear ImGui library (vendored)
│       ├── imgui.cpp/h
│       ├── imgui_draw.cpp
│       ├── imgui_tables.cpp
│       ├── imgui_widgets.cpp
│       └── backends/
│           ├── imgui_impl_win32.cpp/h
│           └── imgui_impl_dx11.cpp/h
│
└── x64/
    ├── Debug/ZeroPhaseEDR.exe
    └── Release/ZeroPhaseEDR.exe
```

---

## Detection Modules

| Phase | Module | What It Detects | MITRE ATT&CK |
|:---:|--------|-----------------|:---:|
| 1 | **Process Intelligence** | Suspicious parent-child relationships (Word→cmd, IIS→powershell), process masquerading (svchost not from services.exe), session anomalies | T1036, T1055 |
| 2 | **Thread Intelligence** | Threads starting outside loaded modules, RWX start address, stack pivoting, suspended threads with zero context switches | T1055.003 |
| 3 | **Memory Intelligence** | RWX regions, packed/encrypted code (entropy >7.0), PE headers in private memory, protection escalation (RW→RWX), shellcode byte patterns | T1055, T1620 |
| 4 | **DLL Intelligence** | Unsigned DLLs, Known-DLL hijacking (system DLL from non-system path), sideloading, phantom DLLs (loaded but not on disk), invalid signatures | T1574.001, T1574.002 |
| 5 | **Command Line Intelligence** | Encoded PowerShell (-enc), download cradles (IEX+WebClient), obfuscation (caret insertion, string concat, char codes), recon tools, credential dump patterns, defense evasion | T1059, T1105, T1003, T1562 |
| 6 | **Injection Intelligence** | Remote thread injection, process hollowing, reflective DLL loading, module stomping, APC injection, thread hijacking, early bird injection, phantom DLL hollowing | T1055.001–.012, T1620 |
| 7 | **Syscall Intelligence** | ntdll stub hooking (JMP, MOV RAX, FF25 detours), direct syscall usage outside ntdll, ntdll in-memory vs on-disk integrity mismatch | T1562 |
| 8 | **Kernel Intelligence** | Kernel driver enumeration, suspicious services (binary in TEMP/user profile), auto-start drivers from non-standard paths, phantom drivers | T1543.003 |
| 9 | **Detection Engine** | Cross-module event correlation, per-process risk scoring, severity aggregation, unified alert dashboard | — |
| 10 | **Forensics** | Event timeline, CSV export, system state snapshots to disk | — |
| 11 | **Production** | EDR resource usage (working set, CPU), scan performance metrics, health checks | — |

---

## Automatic Scanning

The background scanner runs three scan tiers on a schedule:

| Tier | Interval | Modules | Duration |
|------|----------|---------|----------|
| **Light** | Every 5 seconds | Process database + lineage analysis + command line scan | ~50 ms |
| **Full** | Every 30 seconds | Light + syscall stub integrity check | ~200 ms |
| **Deep** | Every 5 minutes | Full + injection scan + memory entropy on suspicious processes | ~2 sec |

All scans run in a background thread. Findings are deduplicated and pushed to the GUI alert feed in real-time.

---

## GUI Dashboard

The dashboard is built with **Dear ImGui** + **DirectX11** and features:

- **Responsive layout** — all panels scale proportionally from 1024×600 to 4K
- **Pixel-perfect resize** — swap chain buffer recreated on every WM_SIZE event
- **Live stat cards** — processes, scans, detections, critical/high counts
- **Severity breakdown** — horizontal bar chart with colored severity bars and hover tooltips
- **Detection sources** — donut/pie chart showing which modules generated findings
- **Scan trend** — bar + line combo chart with the last 60 scan data points
- **Alert table** — newest-first feed with severity dots, MITRE IDs, and acknowledgment
- **Process monitor** — sortable table with search filter, integrity level color coding
- **Scan controls** — start/stop/pause with live statistics
- **Dark sidebar** — compact navigation with status pill and active indicator

---

## Building

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Windows | 10 or 11 (x64) |
| Visual Studio | 2019, 2022, or 2025 with C++ Desktop workload |
| Windows SDK | 10.0 or later |
| C++ Standard | C++17 |

### Build from Visual Studio

1. Open `ZeroPhaseEDR.sln`
2. Set configuration to **Debug | x64** or **Release | x64**
3. Press **Ctrl+Shift+B**
4. Output: `x64\Debug\ZeroPhaseEDR.exe` or `x64\Release\ZeroPhaseEDR.exe`

### Build from Command Line

```powershell
cd ZeroPhaseEDR
msbuild ZeroPhaseEDR.sln /p:Configuration=Release /p:Platform=x64
```

---

## Running

### Recommended: Run as Administrator

```powershell
# From PowerShell
Start-Process ".\x64\Release\ZeroPhaseEDR.exe" -Verb RunAs
```

Running elevated grants `SeDebugPrivilege`, which allows the EDR to inspect all processes including system services (svchost, lsass, csrss). Without elevation the EDR still works but can only inspect processes owned by your user account.

### Permissions Comparison

| Capability | Standard User | Administrator |
|------------|:---:|:---:|
| Own-session processes | ✅ | ✅ |
| System processes (svchost, lsass) | ❌ | ✅ |
| Kernel module listing | ❌ | ✅ |
| Injection scan (all sessions) | ❌ | ✅ |
| DLL signature verification | ✅ | ✅ |
| Syscall integrity (own process) | ✅ | ✅ |
| Service enumeration | ✅ | ✅ |
| Command line collection | ✅ (own) | ✅ (all) |

---

## How It Works

### Native API Layer

ZeroPhase resolves NT API functions directly from `ntdll.dll` at runtime:

- `NtQuerySystemInformation` — process/thread/module enumeration
- `NtQueryInformationProcess` — command line, PEB, debug status
- `NtQueryInformationThread` — Win32 start address, thread times
- `NtQueryVirtualMemory` — memory region analysis
- `NtReadVirtualMemory` — remote process memory reading

### Detection Philosophy

Instead of signature-based detection, ZeroPhase uses **behavioral signal correlation**:

1. **Enumerate** — continuously snapshot processes, threads, memory, and modules
2. **Enrich** — add context (integrity level, start address resolution, entropy, signatures)
3. **Analyze** — apply rules per module (lineage, risk scoring, pattern matching)
4. **Correlate** — combine findings across modules into per-process risk profiles
5. **Alert** — deduplicate and surface findings with severity and MITRE mapping

### Injection Detection Example

A single process is checked for injection through multiple independent signals:

```
Thread starts outside any loaded module?     → Remote Thread (T1055.003)
Private memory has RWX protection?           → Shellcode region (T1055)
PE header (MZ) found in private memory?      → Reflective DLL (T1620)
DLL .text section entropy > 7.2?             → Module stomping (T1055.001)
PEB ImageBase in PRIVATE (not IMAGE) memory? → Process hollowing (T1055.012)
Memory protection escalated from RW to RWX?  → VirtualProtect abuse (T1055)
```

If multiple signals fire on the same process, confidence increases and severity escalates.

---

## Console Mode

The original console interface is preserved as `main_console.cpp.bak`. To build it instead of the GUI:

1. In the `.vcxproj`, replace `gui_main.cpp` with `main.cpp` (rename the backup)
2. Change `SubSystem` from `Windows` to `Console`
3. Remove the ImGui source files from the build

The console mode provides a menu-driven interface to all 11 modules without the GUI or automatic scanning.

---

## Project Roadmap

- [x] Phase 1–11: All user-mode intelligence modules
- [x] GUI dashboard with DirectX11 + ImGui
- [x] Automatic background scanning
- [x] Real-time charts (bar, donut, trend line)
- [x] Responsive layout with proper swap chain resize
- [ ] ETW-based real-time process/thread event monitoring
- [ ] Kernel driver for syscall interception and minifilter
- [ ] Network traffic analysis module
- [ ] YARA rule integration
- [ ] Central management server for multi-endpoint deployment
- [ ] Automated response actions (quarantine, kill, block)

---

## Technical Notes

**Thread safety.** All intelligence databases use `std::shared_mutex` with reader-writer locking. The auto-scanner runs in its own thread and communicates with the GUI through lock-protected data structures.

**Performance.** Light scans complete in ~50ms. The GUI runs at 60fps vsync. The entire agent uses ~55MB working set including ImGui and DirectX11 overhead.

**Swap chain resize.** On `WM_SIZE`, the renderer defers swap chain resize to the next `beginFrame()` call. The render target view is released, `ResizeBuffers` is called at the new resolution, and a new RTV is created — ensuring pixel-perfect rendering at every window size.

**ntdll parsing.** The syscall detector parses the PE export table of ntdll.dll in the target process's address space, reads each Nt* function's first 16 bytes, and validates the expected `mov r10,rcx; mov eax,SSN` prologue. Five hook patterns are recognized: JMP rel32, JMP [rip+disp], MOV RAX+JMP RAX, PUSH+RET, and partial patches.

---

## Disclaimer

ZeroPhase EDR is a **defensive security tool** built for authorized security monitoring, incident response, and educational purposes. It uses the same Windows APIs that both security products and malware use — process memory reading, thread inspection, and syscall analysis. Some antivirus products may flag it. Add an exclusion for the build directory if needed.

---

<p align="center">
  Built by <strong>ZeroPhase Security</strong><br>
  <sub>User-Mode Agent v1.0 — All 11 Phases Complete</sub>
</p>
