# Windows Modular Implant

A sophisticated, modular Windows-based C++ application designed for advanced system monitoring, reporting, and lateral movement. This project implements state-of-the-art evasion techniques, redundant persistence mechanisms, and comprehensive data exfiltration capabilities.

---

## 1. Project Overview

This implant is a standalone Windows executable that functions as a remote administration and monitoring tool. It is designed to operate stealthily within a target environment, establishing a long-term foothold, collecting system-critical information, and providing lateral movement capabilities across a network.

The system is built with a focus on modularity, allowing new features (tasks) to be easily integrated into the core dispatching logic. It utilizes a beaconing architecture to communicate with a remote Command and Control (C2) server via encrypted HTTP channels.

---

## 2. Key Features

- **Advanced Evasion**:
    - **Indirect Syscalls**: Bypasses EDR/AV user-mode hooks by resolving and jumping to `syscall; ret` gadgets in `ntdll.dll`.
    - **Multi-byte XOR Obfuscation**: Protects sensitive strings (paths, queries, CLSIDs) with a rolling XOR key.
    - **Anti-Sandbox & Detection**: Checks for virtualized environments, debuggers, and low-resource systems before execution.
    - **Junk Logic & Bloat**: Dynamically alters the binary's signature to evade heuristic and ML-based detections.
- **Redundant Persistence**:
    - **UserInitMprLogonScript**: A stealthy registry-based persistence method.
    - **COM Hijacking**: Leverages legitimate CLSIDs (e.g., Work Folders) for stealthy execution.
- **Comprehensive Credential Stealing**:
    - **Chromium-based Browsers**: Extracts passwords and cookies, including support for **v20 App-Bound Encryption** via COM elevation.
    - **Firefox**: Dynamically loads `nss3.dll` for proper profile decryption.
    - **LSASS Dumping**: Captures memory dumps for offline credential harvesting.
- **Lateral Movement**:
    - **WmiExec**: Remote command execution via WMI.
    - **SvcExec**: Remote execution via temporary service creation.
    - **TaskExec**: Remote execution via the Task Scheduler COM API.
    - **Wireless Spreading**: Automated discovery and spreading via WiFi/Bluetooth.
- **System Reconnaissance**:
    - **ADEnum**: Comprehensive Active Directory enumeration (users, groups, computers, admins).
    - **Deep Recon**: Detailed hardware, network, and installed software auditing.
- **Interactive Capabilities**:
    - **Reverse Shell**: Full interactive shell support.
    - **Live Streaming**: Webcam and screen stream capabilities.
    - **Keylogging & Audio**: Stealthy input and microphone recording.

---

## 3. Architecture Overview

The implant follows a dual-execution flow depending on its current context (Dropper, Foothold, or Persisted).

### Execution Flow

```text
Application Start (WinMain)
     │
     ├── Evasion Init (Refresh Ntdll, Resolve Syscalls, Bloat)
     │
     ├── Role Detection
     │   ├── Foothold (IsSystemProcess: explorer.exe, sihost.exe) ──▶ Initialize Beacon ──┐
     │   ├── Persisted (IsRunningFromPersistLocation) ───────────────▶ Initialize Beacon ──┤
     │   └── Dropper (Default) ──────────────────────────────────────▶ Proceed to Install ─┘
     │
     └── Install (Dropper Role)
         ├── Anti-Sandbox Checks
         ├── Establish Persistence (Logon Script / COM)
         ├── Relocation (Inject into explorer.exe/sihost.exe)
         ├── Show Decoy (MessageBox: System Compatibility Error)
         └── Self-Delete (Dropper binary)
```

### Beacon Cycle
Once in the "Foothold" or "Persisted" role, the implant enters the beaconing loop:
1.  **Resolve C2**: Contact the redirector to obtain the active C2 URL.
2.  **Heartbeat**: Send encrypted system metadata and pending task results.
3.  **Tasking**: Receive and process encrypted commands from the C2.
4.  **Dispatch**: Route tasks to specific modules (Lateral, Credential, Capture, etc.).
5.  **Sleep**: Jittered delay between cycles to evade traffic analysis.

---

## 4. Project Structure

The project is organized into modular subdirectories within `src/`:

| Directory | Description |
| :--- | :--- |
| `beacon/` | Core C2 communication logic and task dispatching. |
| `capture/` | Input monitoring: Keylogging, Screen/Webcam capture, Audio. |
| `core/` | Global configuration, Implant ID generation, and constants. |
| `credential/` | Password and cookie extraction from browsers and system memory. |
| `crypto/` | Encryption routines: AES-GCM, Base64, DPAPI, XOR. |
| `decoy/` | Social engineering decoys (e.g., System Error message boxes). |
| `evasion/` | Advanced stealth: Syscalls, Unhooking, Injection, Anti-Sandbox. |
| `execution/` | In-memory execution: .NET assembly loading. |
| `fs/` | Remote file system management (Browse, Upload, Download). |
| `http/` | Secure networking: WinHTTP clients and Redirector resolution. |
| `lateral/` | Domain and network movement: WMI, SCM, Task Scheduler, AD Enum. |
| `network/` | Networking utilities: SOCKS5 proxy implementation. |
| `persistence/` | Redundant installation mechanisms and COM hijacking. |
| `recon/` | System discovery: Sysinfo, WMI helpers, Deep recon. |
| `shell/` | Interactive shell and command-line execution. |
| `streaming/` | Real-time media exfiltration (Screen/Webcam). |
| `utils/` | General utilities: String conversions, Logging, Self-deletion. |
| `wifi/` | Wireless profile extraction and scanning. |

---

## 5. Technical Stack

- **Language**: C++20
- **Build System**: CMake 3.20+
- **Cryptography**: Windows Bcrypt API, Crypt32, AES-GCM (Custom implementation).
- **Networking**: WinHTTP (Native Windows HTTP Services).
- **Database**: SQLite3 (Embedded for browser data parsing).
- **JSON**: nlohmann/json (External dependency).
- **Target OS**: Windows 7/8/10/11 (x64).

---

## 6. Maintenance & Extension

To add a new capability:
1.  Implement the feature in a new or existing module directory.
2.  Register the new `TaskType` in `src/beacon/Task.h`.
3.  Update the string-to-task mapping in `src/beacon/Beacon.cpp`.
4.  Add the logic handler in `src/beacon/TaskDispatcher.cpp`.
5.  Update `CMakeLists.txt` to include new source files.

Refer to `CONTRIBUTING.md` for more details.
