# Libraries and Dependencies

This document lists all external and system-level dependencies used by the implant.

---

## External Libraries (Vendored)

| Library | Directory | Description |
| :--- | :--- | :--- |
| **nlohmann-json** | `external/nlohmann` | A header-only C++ JSON library used for C2 communication and parsing Local State files. |
| **SQLite3** | `external/sqlite3` | Used to parse Chromium and Firefox browser databases. |
| **ConcurrentQueue** | `external/concurrentqueue` | A lock-free, many-producer, many-consumer queue used for managing task results. |

---

## Windows System Libraries

These libraries are linked during the build process to provide access to native Windows functionality.

| Library | Purpose |
| :--- | :--- |
| `bcrypt.lib` | Cryptography (AES-GCM, PRNG). |
| `winhttp.lib` | Networking (HTTP/S communication). |
| `advapi32.lib` | Registry, Services, and Token management. |
| `ole32.lib` | COM/DCOM initialization and support. |
| `wbemuuid.lib` | WMI (Windows Management Instrumentation). |
| `crypt32.lib` | DPAPI and certificate handling. |
| `shlwapi.lib` | Shell-level path and string manipulation. |
| `gdiplus.lib` | Screenshot and media capture. |
| `user32.lib` | UI components and Message Boxes. |
| `iphlpapi.lib` | Network interface and ARP table discovery. |
| `ws2_32.lib` | SOCKS5 proxy and low-level socket operations. |
| `wlanapi.lib` | WiFi scanning and profile management. |
| `netapi32.lib` | Active Directory enumeration. |
| `taskschd.lib` | Task Scheduler COM interfaces. |
| `mpr.lib` | Network Provider (IPC$ sessions). |

---

## Development Dependencies
- **googletest**: Used for internal unit testing of crypto and utility functions (located in `tests/`).
