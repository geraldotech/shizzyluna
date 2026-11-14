# Shizzy Luna v0.10.7-debug — Exclusive Blocking Engines and Native SoftAP MAC Enforcement

## 1. Mission

Implement a third, mutually exclusive blocking engine that uses the Android tethered SoftAP client blocklist to disconnect a selected Wi-Fi station and prevent that MAC address from reconnecting. This must be a functional enforcement attempt, not merely another BPF diagnostic report. Preserve rootless operation through Shizuku (ADB shell), require no client-side agent, and never claim success until actual association and traffic tests pass.

Target: Samsung Galaxy S23 Ultra / Android 14 (API 34), with OEM variations supported through capability detection. Bump the debug version to `0.10.7-debug`, serviceBuildId to 22 if 21 is still current, and report schema to 5. Preserve the existing debug application ID and stable branch. Inspect the actual repository before selecting implementation classes or changing build configuration.

### Evidence from v0.10.6

- Requested `PRE_NAT_FIREWALL`; effective `BPF_NAT_VPN`; exclusive invariant true.
- Pre-NAT probe never ran: Shizuku binder was not running, and reported CAP_NET_ADMIN was false. The report does not establish a fresh remote identity or an actual mutation denial.
- BPF/NAT still allows unknown owners; previous real-world tests showed messaging delivery despite blocked navigation.
- Native association denial could eliminate this particular leakage path without requiring per-packet NAT attribution. It is conditional on device support and authorized Wi-Fi service access.

## 2. Exclusive blocking mode

Use a single persisted enum and a serialized engine coordinator:

```kotlin
enum class BlockingMode {
    BPF_NAT_VPN,
    PRE_NAT_FIREWALL,
    SOFTAP_MAC_BLOCK
}
```

| Engine | Enforcement | Limitations |
|---|---|---|
| BPF_NAT_VPN | Existing verified-owner packet policy | Partial attribution; unknown traffic allowed |
| PRE_NAT_FIREWALL | Existing privileged forwarding-rule engine | Capability-gated; not proven rootless |
| SOFTAP_MAC_BLOCK | Native association blocklist and forced disconnection | Client loses Wi-Fi association; MAC changes can evade identity |

Only one engine may enforce Shizzy Luna policies at a time. During a transition there may be zero active engines. Native user/OEM rules are not owned by Shizzy Luna and must remain untouched. Keep read-only BPF collection and quota accounting separate from packet DROP/throttle decisions. VPN transport may remain running if needed for tethering/accounting, but its policy enforcement must be disabled in SoftAP mode. Do not promise VPN-free accounting.

Maintain requestedMode, effectiveMode (nullable if no engine is safe), transitionId, policyGeneration, engineHealth, owned native entries, and an enforcement-state reason. Serialize mode switching, policy updates, quota events and recovery. Reject stale asynchronous results using generation tokens.

## 3. Native SoftAP strategy

Use the tethered hotspot configuration, not a local-only hotspot or a replacement AP. Investigate the existing Shizuku service and Wi-Fi binder implementation. Prefer an authorized API path equivalent to `WifiManager.getSoftApConfiguration()` and `setSoftApConfiguration(config)`; use the actual platform signatures and remote execution identity. Build a copy of the current `SoftApConfiguration`, changing only the blocked-client list via `SoftApConfiguration.Builder.setBlockedClientList(...)`. Read `SoftApCapability` via supported callbacks and check `SOFTAP_FEATURE_CLIENT_FORCE_DISCONNECT`.

These are system/hidden APIs on relevant Android releases; reflection or Shizuku alone does not grant service permissions. Inspect the matching Android/OEM implementation for permission requirements and supported shell commands. Do not invent shell commands, hard-code binder transaction numbers, impersonate system packages, bypass SELinux, use root, or automate privileged Settings UI as a hidden substitute. Report actual errors. A supported OEM interface may be considered only if demonstrably callable and non-disruptive under the authorized identity.

AOSP supports blocklists and forced disconnect, including live configuration updates in its implementation. Samsung firmware may differ. Never assume a successful setter or readback implies runtime enforcement.

## 4. Capability checks: separate evidence from assumptions

Run a read-only preflight when the user selects SoftAP mode:

1. Verify Shizuku binder is alive, permission granted, and remote service reachable. If not, return `SHIZUKU_NOT_RUNNING` or `SHIZUKU_PERMISSION_REQUIRED`, not a definitive permission denial.
2. Collect fresh UID/GID, SELinux context and capabilities from the actual remote execution context. Record provenance and timestamp; missing values are UNKNOWN, never fabricated defaults. CAP_NET_ADMIN is not a prerequisite for calling an authorized Wi-Fi service API.
3. Check API availability, tethered AP state, actual connected-client callback, and force-disconnect HAL feature. Distinguish unsupported from unreadable.
4. Read the current AP configuration and blocklist; verify preservation of all other fields without exporting credentials.
5. Determine supported write path. A read-only check cannot prove write permission. Distinguish `PROBE_REQUIRED`, `PERMISSION_DENIED`, `API_UNAVAILABLE`, `HAL_UNSUPPORTED`, and `OEM_UNSUPPORTED`.
6. Require explicit user approval for the controlled two-client mutation test. Never toggle or restart the hotspot just to test capability. If only restart-based changes work, report `LIVE_UPDATE_UNSUPPORTED`; do not activate this engine.

Fix the v0.10.6 Pre-NAT verdict too: a dead Shizuku binder means `NOT_TESTED_SHIZUKU_UNAVAILABLE`; keep a genuine permission-denied result only when backed by fresh evidence. Preserve the engine and existing safeguards; do not run new netfilter mutations automatically.

## 5. Controlled live probe and activation

Prerequisites: test client A explicitly selected by its current associated station MAC, client B connected and running a continuous connectivity test, hotspot active, user approval, recoverable configuration readback, and no unresolved app-owned rules. Reject invalid, multicast, broadcast, ambiguous, or placeholder MACs. Randomized locally administered unicast station MACs are valid.

- Record the current configuration and ownership baseline. Do not use an invented MAC as proof of disconnection.
- Suspend the previous Shizzy enforcement engine after confirming its owned rules are removed or inactive. Do not suspend user/OEM policies. Warn that a test transition may briefly leave traffic unfiltered.
- Merge A into the current blocklist, preserving existing entries and client-control mode. If A is on the user allowlist, handle the conflict explicitly; never silently edit it. If the platform rejects the combination, report conflict and stop.
- Apply through the approved service, check return/exception, read back the list, and await a fresh callback confirming A disconnected.
- Verify A cannot reassociate with the same MAC; B stays associated and successfully completes network requests; AP remains running with no restart; host network remains functional.
- Remove only the test entry owned by Shizzy Luna; verify readback, A can reconnect, B remains connected. Persist probe evidence bound to firmware, API path and execution identity. Activation requires this successful test and revalidation when those conditions change.
- Activate SoftAP engine, then reconcile existing Shizzy policies. If any activation step fails, clean up app-owned mutations and restore the previous engine only after cleanup is proven. If cleanup is uncertain, enter `ROLLBACK_REQUIRED`, with no conflicting engine activated.

Suggested configurable observation timeout: 10 seconds for disconnect, 30 seconds for reassociation test. Timeouts are experimental acceptance targets, not Android API guarantees.

## 6. Real policy enforcement

Manual block, quota exhausted, pause and blocked schedule windows map to the same native MAC deny action. Multiple reasons combine with OR semantics; unblocking one reason must not remove another. Quota reset and schedule expiry remove the app-owned MAC entry only when no remaining reason requires it. Never enable a global allowlist, change SSID/password/security/band, or stop the hotspot to block one client.

```text
Policy event -> validate current client identity -> compute desired native deny set
-> serialize read/merge/write -> verify configuration -> observe disconnection
-> confirm applied state or report failure and recover
```

Maintain desired policy separately from confirmed applied state. A client being disconnected is not equivalent to a successful blocklist installation. Keep blocked clients in the UI even when disconnected, and offer unblock without requiring reconnection. Do not remove quota or policy records on disassociation. Reconcile after AP recreation, app restart, permission changes and external edits, using fresh configuration and client generation. Never automatically block a new MAC merely because it uses the old IP or device name.

### Quota and bandwidth behavior

BPF may remain read-only for quota attribution. Charge verified forwarded data only, avoid double-counting and exclude unknown-owner packets from per-client usage. The quota threshold may be reached late due to incomplete attribution; once detected, native disconnection should not depend on future packet attribution. Do not claim exact quota accounting. Keep usage across reconnects according to current quota semantics. Bandwidth throttling is unsupported in this mode; disable its controls and warn before switching if active throttling policies exist. Do not silently run the BPF limiter as a second engine.

## 7. Ownership, rollback and lifecycle safety

Persist a crash-safe journal before any configuration mutation: operation ID, target MAC (local private storage), prior membership, desired membership, config version/fingerprint, engine generation and commit phase. Never log passwords or export full configuration. Store only entries added by the app as app-owned; never remove pre-existing user entries. Read latest config before every write, merge only the required delta and verify afterward. If competing changes or ambiguous ownership are detected, stop and surface a conflict rather than overwriting user changes. Android may not provide atomic compare-and-swap; serialize local operations and disclose residual external race risk.

On engine switch or explicit disable, remove owned native blocks and verify before enabling another engine. On crash, journal recovery must reconcile pending writes before enabling enforcement. On permission loss, retain journal and state `ROLLBACK_REQUIRED` if cleanup cannot be verified. Do not claim rollback successful merely because a command was issued. Provide instructions to remove the affected MAC manually in hotspot settings if supported. Keep the rest of the hotspot configuration unchanged. Never promise automatic cleanup while Shizuku is unavailable.

## 8. UI and report schema

Add a single-choice **Blocking Mode** setting with all three engines. Show requested versus effective engine, capability status, and a clear warning: SoftAP blocking disconnects Wi-Fi; it does not keep the client associated without internet. Show a dedicated capability-check action and an explicitly approved live probe action. No automatic disruptive tests on opening settings.

UI/runtime states: `CHECKING`, `SHIZUKU_NOT_RUNNING`, `SHIZUKU_PERMISSION_REQUIRED`, `PROBE_REQUIRED`, `HAL_UNSUPPORTED`, `API_UNAVAILABLE`, `PERMISSION_DENIED`, `LIVE_UPDATE_UNSUPPORTED`, `PROBE_RUNNING`, `READY`, `ACTIVATING`, `ACTIVE`, `BLOCK_PENDING`, `BLOCK_CONFIRMED`, `BLOCK_FAILED`, `ROLLING_BACK`, `ROLLBACK_REQUIRED`, `UNAVAILABLE`. Separate engine-level states from individual client states. Provide retry and safe fallback only when cleanup is confirmed.

Export schema v5 with:
- Requested/effective mode, all three enforcement flags, exclusive invariant, transition generation and phase.
- Fresh Shizuku identity and capability provenance, SDK/build, Wi-Fi service API path and permission results, HAL support, live probe approval/result, sanitized exception class and reason.
- Per-client desired/applied state, policy reasons, ephemeral MAC hash, blocklist ownership, config readback, disconnect latency, reassociation attempts/results, quota accounting confidence.
- AP restart count, B connectivity checks, interface/session generations, rollback journal status and verified cleanup counts.
- Delivery test markers and independent receiver confirmation; classify untested as NOT_TESTED, not PASS. Separate test evidence from inferred capability. Ensure all counters have clear reset/window semantics and report snapshots are internally consistent.

## 9. Reproducible test matrix

Run on a dedicated hotspot with clients A and B. Disable mobile data, alternative Wi-Fi and automatic network fallback on A. Use a receiver on independent internet for unique WhatsApp/Telegram messages, recording timestamps. Test Wi-Fi and mobile upstream separately. Use a fresh test window for each scenario. Mark unavailable tests BLOCKED_BY_CAPABILITY rather than PASS.

| ID | Test | Expected evidence |
|---|---|---|
| SA01 | Shizuku stopped | Correct unavailable state; no mutation; no fabricated identity |
| SA02 | Shizuku started, permission denied | Accurate remote permission failure |
| SA03 | HAL/API unsupported | No configuration mutation |
| SA04 | Approved live probe with A/B | A disconnected, B stable, A cannot reassociate, cleanup verified |
| SA05 | Manual block A | Same-MAC reassociation fails; B stays connected |
| SA06 | Quota exhaustion A | Native block triggered after verified usage threshold |
| SA07 | WhatsApp and Telegram | Unique post-confirmation messages not delivered while A only has hotspot access |
| SA08 | TCP/UDP/IPv4/IPv6 | No useful internet communication through hotspot after confirmed block |
| SA09 | Unblock A | Owned entry removed; A can reconnect |
| SA10 | Multiple policy reasons | Removing one reason does not unblock remaining reasons |
| SA11 | Existing OEM blocklist/allowlist | Existing settings preserved; conflicts surfaced |
| SA12 | Reconnect with changed MAC | No false attribution; limitation visible |
| SA13 | Switch all three modes | Never more than one Shizzy engine enforcing; cleanup verified |
| SA14 | Kill app during write | Journal reconciled; no unverified fallback |
| SA15 | Revoke Shizuku after block | Honest rollback-required state; recover when authorized |
| SA16 | Hotspot/ VPN recreation | Reconcile fresh generation; no stale identities |
| SA17 | Concurrent external blocklist edit | Preserve foreign entries or stop on conflict |
| SA18 | Bandwidth policy configured | Warn/disable unsupported throttle; no hidden second engine |
| SA19 | Repeat Wi-Fi/mobile upstream | Same association behavior; B remains online |
| SA20 | Report consistency | Actual observations distinguished from inferred/untested outcomes |

For SA04–SA08, test repeated reconnect attempts and messages for at least 60 seconds after confirmed disconnection, with B issuing periodic network requests. Record A association status, AP lifecycle events and B request success. Ensure messages were created after confirmation, not queued before it. Re-run at least three times for each upstream. No claim of protection against MAC spoofing or alternate networks.

## 10. Acceptance criteria and engineering verdict

- AC01: Debug build installs; stable branch and existing BPF behavior preserved.
- AC02: Exactly one selectable enum; no simultaneous Shizzy enforcement, including transition and crash recovery.
- AC03: Fresh remote evidence and explicit permission failures; no fabricated capability claims.
- AC04: Native mutation only after consent and supported API/HAL checks.
- AC05: Actual live probe proves A disconnects and cannot reconnect with same MAC, without AP restart or B disassociation.
- AC06: Manual block and quota events apply native deny state and verify it.
- AC07: Zero independently confirmed new WhatsApp/Telegram deliveries during the controlled blocked test window; A has no alternative connection.
- AC08: B remains associated and its controlled connectivity checks pass throughout the test.
- AC09: Unblock restores A eligibility; external entries and other hotspot settings preserved.
- AC10: Rollback verified on supported failures; unresolved cleanup explicitly reported and conflicting activation forbidden.
- AC11: No per-client attribution of unknown traffic, no claim of exact quotas or supported throttling.
- AC12: Debug report includes actual test evidence and correct NOT_TESTED/BLOCKED states.
- AC13: Native mode can be enabled only after live probe passes; otherwise safe fallback after cleanup.

**GO**: authorized rootless live update, actual selective disconnect, same-MAC reassociation denial, independent delivery test, B unaffected, and verified cleanup all pass. **NO-GO**: confirmed unsupported HAL/API, denied authorized write, or disruptive/nonselective behavior. **INCONCLUSIVE**: Shizuku offline, no approval, missing client B or missing evidence. No new BPF tuning is required to declare the SoftAP feasibility result.

## 11. Deliverables

Implement code, UI, unit tests for coordinator/ownership/policy reducer, integration tests where available, debug APK, updated README and schema v5 report. Document actual API signatures, permissions, tested firmware, remaining limitations and commands used. Do not mark physical-device tests as passed from mocks. If rootless SoftAP access is denied, retain the previous engine and report the precise blocker; do not implement another speculative firewall workaround.

## References

- Android Open Source Project, Wi-Fi hotspot: https://source.android.com/docs/core/connect/wifi-softap
- Android 14 SoftApConfiguration source: https://android.googlesource.com/platform/prebuilts/fullsdk/sources/+/refs/heads/main/android-34/android/net/wifi/SoftApConfiguration.java
- AOSP SoftApManager implementation (reference only; verify target firmware): https://android.googlesource.com/platform/packages/modules/Wifi/+/refs/heads/main/service/java/com/android/server/wifi/SoftApManager.java
