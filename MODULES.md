# Module Documentation

This document describes the primary modules within the Windows Modular Implant.

---

## Evasion & Stealth

### `evasion::SyscallResolver`
- **Purpose**: Dynamically resolves system call numbers and finds jump gadgets.
- **Key Functions**:
    - `ResolveAll()`: Scans `ntdll` export directory to map SSNs.
    - `GetSyscallGadget()`: Finds a `syscall; ret` instruction in `ntdll` memory.
- **Implementation**: Uses a HalosGate/HellsGate hybrid to find SSNs even if functions are hooked.

### `evasion::Injector`
- **Purpose**: Manually maps the implant into a target process.
- **Key Functions**:
    - `InjectIntoExplorer()`: High-level wrapper for targeting `explorer.exe`.
    - `MapAndInject()`: Performs section mapping, relocation patching, and IAT resolution.
- **Evasion**: Avoids standard `CreateRemoteThread` on suspicious APIs; uses indirect syscalls for memory operations.

---

## Credential Stealing

### `credential::ChromiumStealer`
- **Purpose**: Extracts data from Chrome, Edge, Brave, and Opera.
- **Key Features**:
    - **Safe Database Copy**: Clones SQLite databases and their WAL/SHM sidecar files to a temp directory to avoid file locks.
    - **v20 Support**: Interfaces with the browser's `IElevator` COM object to decrypt App-Bound encrypted fields.
    - **Profile Discovery**: Dynamically searches for `Default` and `Profile X` directories.

### `credential::FirefoxStealer`
- **Purpose**: Extracts credentials from Mozilla Firefox profiles.
- **Key Features**:
    - **Dynamic NSS**: Locates and loads `nss3.dll` from the Firefox install directory.
    - **Decryption**: Uses `PK11SDR_Decrypt` to unlock profile-protected secrets.

---

## Lateral Movement

### `lateral::SvcExec`
- **Purpose**: Remote execution via Service Control Manager.
- **Flow**:
    1. Establish an IPC$ session with provided credentials.
    2. Connect to the remote SCM.
    3. Create a service with a random/obfuscated name.
    4. Start and then immediately delete the service.

### `lateral::TaskExec`
- **Purpose**: Remote execution via Task Scheduler COM API.
- **Evasion**: Uses COM interfaces rather than the `schtasks.exe` command-line utility to reduce behavioral triggers.

---

## Beaconing & Tasking

### `beacon::Beacon`
- **Purpose**: Manages the main operational loop.
- **Responsibilities**:
    - Implant ID management.
    - C2 Redirector resolution.
    - Encryption/Decryption of heartbeat payloads.
    - Asynchronous task spawning.

### `beacon::TaskDispatcher`
- **Purpose**: The central routing logic for all C2 commands.
- **Handling**: Decodes the task IP/CMD and routes it to the appropriate module (e.g., `recon::getSysInfo()`, `capture::CaptureScreenshot()`).
- **Safety**: Each task is dispatched in a separate thread and handles its own COM initialization.

---

## System Discovery

### `recon::ADEnum`
- **Purpose**: Active Directory reconnaissance using `NetApi32`.
- **Features**:
    - Domain Controller discovery.
    - Computer enumeration (Server, Workstation).
    - User and Group membership retrieval.
    - Targeted Domain Admin discovery.
