# Architecture Internals

This document provides a deep dive into the internal design, execution flow, and component interactions of the Windows Modular Implant.

---

## 1. Execution Role Model

The implant determines its behavior based on its environment and execution context. This prevents redundant installation and ensures it can recover if a foothold process is terminated.

### Roles
1.  **Dropper**: The initial execution state. The binary is typically running from a suspicious location (e.g., Downloads, Temp). Its primary goal is to install persistence, establish a foothold in a legitimate system process, and then self-delete.
2.  **Foothold (Injected)**: The implant running inside a trusted system process (e.g., `explorer.exe` or `sihost.exe`). This is the primary operational state. It performs beaconing and task execution. It uses IPC (via Registry) to receive its original installer path for persistence maintenance.
3.  **Persisted**: The implant running from its legitimate-looking system directory (e.g., `\Microsoft\Windows\DnsCache\`). This state occurs after a system reboot or logon trigger. It behaves identically to the Foothold role.

---

## 2. Advanced Evasion Architecture

The implant utilizes a multi-layered approach to evade Endpoint Detection and Response (EDR) and Antivirus (AV) solutions.

### Indirect Syscalls
Most EDRs hook Windows APIs (e.g., `NtAllocateVirtualMemory`) in user-mode by placing a `jmp` at the start of the function in `ntdll.dll`.
- **Resolution**: The `SyscallResolver` scans `ntdll.dll` text section for the system service number (SSN) of target functions.
- **Bypass**: Instead of executing the `syscall` instruction directly in its own code (which looks suspicious), it finds a `syscall; ret` gadget within `ntdll.dll` and jumps to it. This makes the syscall appear as if it originated from `ntdll.dll`.

### Dynamic Obfuscation
Sensitive strings like registry paths, browser profile names, and SQL queries are never stored in plaintext.
- **XOR Rolling Key**: All strings are obfuscated using a 4-byte rolling XOR key.
- **On-the-fly Decryption**: Strings are only decrypted in memory just before use and are typically cleared or localized to the stack to minimize the forensic footprint.

### Unhooking
Before performing critical actions, the `Unhooker` module refreshes the `ntdll.dll` in memory. It reads a clean version of the DLL from disk and overwrites the hooked sections in the current process's memory space, effectively removing EDR hooks.

---

## 3. Communication & Beaconing

The implant uses an encrypted heartbeat mechanism to stay in contact with the C2.

### Redirector Layer
The implant does not contact the C2 directly. It first communicates with a **Redirector** (defined in `Config.h`). The redirector provides the actual C2 URL, allowing operators to rotate backend infrastructure without updating the implant.

### Traffic Encryption
All data sent between the implant and C2 is encrypted:
- **AES-256-GCM**: Provides both confidentiality and integrity.
- **Encrypted Payload**: A random 12-byte nonce is prepended to the ciphertext.
- **Custom Headers**: Traffic is disguised using legitimate-looking User-Agents and custom headers (e.g., `X-Telemetry-Key`).

---

## 4. Lateral Movement & Domain Enumeration

The lateral movement modules are designed to blend in with legitimate system administration activities.

- **SvcExec**: Emulates `PsExec` behavior by using the Service Control Manager (SCM). It creates a temporary service on a remote target. To avoid detection, it uses an obfuscated service name ("SystemUpdater").
- **TaskExec**: Uses the modern Task Scheduler 2.0 COM API. This is often less monitored than WMI or SCM. It creates a one-time task that runs as the target user.
- **ADEnum**: Utilizes the `NetApi32` library to perform reconnaissance. This uses standard RPC calls that are common in domain environments, making the traffic harder to distinguish from normal AD traffic.

---

## 5. Persistence Redundancy

Persistence is designed to be durable.
1.  **Environment Variable**: The `UserInitMprLogonScript` is set in `HKCU\Environment`. This is a legitimate Windows feature that runs a script or executable during the logon process.
2.  **COM Hijacking**: If the logon script is removed, the implant can leverage COM hijacking. By redirecting a legitimate CLSID (like the one used by Work Folders) to its own binary, it ensures execution whenever a system component attempts to instantiate that COM object.
3.  **Maintenance**: Every 24 hours (with jitter), the Foothold process verifies and re-installs all persistence mechanisms to ensure it remains on the system.
