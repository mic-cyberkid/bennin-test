# Configuration Parameters

Global configuration is primarily handled in `src/core/Config.h`. This file contains hardcoded values that define the implant's behavior and infrastructure targets.

---

## 1. Infrastructure Targets

- **`REDIRECTOR_URL`**: The URL of the first-stage redirector. This is the only URL the implant is guaranteed to contact initially.
- **`API_KEY`**: A shared secret sent in the `X-Telemetry-Key` header to authenticate the implant with the redirector/C2.

---

## 2. Operational Behavior

- **`C2_FETCH_BACKOFF`**: The initial wait time (in seconds) between failed attempts to resolve the C2 URL. This value doubles on each failure (capped).
- **`SLEEP_BASE`**: The base heartbeat interval (in seconds).
- **`JITTER_PCT`**: The percentage of randomness applied to the heartbeat interval to prevent traffic pattern analysis.

---

## 3. Communication Profile

- **`USER_AGENTS`**: A list of common browser strings. The implant randomly selects one for each HTTP request to blend in with normal web traffic.
- **`BEACON_KEY`**: The 32-byte key used for AES-GCM encryption of beacon payloads.

---

## 4. Resource Limits

- **`MAX_PENDING_RESULTS`**: The maximum number of task results kept in memory before the queue is purged or capped.
- **`MAX_CHUNK_SIZE`**: The largest size for individual data exfiltration chunks (currently 1MB).
