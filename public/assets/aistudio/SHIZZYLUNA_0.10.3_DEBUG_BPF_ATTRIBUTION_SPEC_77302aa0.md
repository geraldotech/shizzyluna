# Shizzy Luna — v0.10.3-debug: BPF/NAT Attribution & Leak Diagnostics

## Objective

Create an **experimental, separately installable Android APK** from the current working `main` baseline (Shizzy Luna `0.10.2`) to investigate **unattributed packets that may be forwarded even when a hotspot client is blocked or has exhausted its data quota**.

This phase is **diagnostics only**. Do not claim that unknown-packet leakage has been fixed. Do not change policy decisions, introduce global fail-closed behavior, or weaken the existing BPF/NAT safety guards.

**Repository:** `https://github.com/geraldotech/shizzyluna`
**Target branch:** `debug` (create from the latest validated `main`; never commit debug changes directly to `main`)
**Stable baseline:** `0.10.2`, `applicationId = dev.shizzyluna.proxy`, versionCode `17`.

## 1. Build identity and isolation

- Debug APK application ID: **`dev.shizzyluna.proxy.debug`**.
- Android launcher label: **`shizzy lua (Debug)`**, visibly distinct from stable.
- Suggested `versionName`: **`0.10.3-debug`** and `versionCode`: **`18`** (adjust upward only if required by the target branch's existing build).
- Keep Kotlin/AIDL source **namespace `dev.shizzi`** unless a compelling technical requirement exists. The Android application ID and Kotlin namespace are separate concerns.
- Prefer a Gradle **product flavor** (e.g., `debuglab`) or an equivalent variant-scoped `applicationIdSuffix = ".debug"` so stable-release identity is not accidentally changed. **Careful:** Gradle already has a standard `debug` build type; using `applicationIdSuffix` there affects all debug builds. Document precisely which build variant produces the experimental APK and ensure the resulting ID is **exactly** `dev.shizzyluna.proxy.debug`, not `.debug.debug`.
- Distinct icon/label if practical; logcat tag prefix identifying the experimental build.
- Expected output filename: **`shizzyluna-v0.10.3-debug.apk`**.
- Stable and experimental apps must be installable side by side with different app data, preferences, and permissions. **Never assume stable settings are automatically migrated**.
- Two Android VPN services cannot be active simultaneously under the same Android user/profile; stop the stable VPN before running the experimental one.
- Check all component/permission/provider authorities, `FileProvider` authorities, exported components, intent actions, and hard-coded `dev.shizzi`/old application ID references for runtime collisions. Keep correct namespace-qualified class references in AndroidManifest and AIDL.

## 2. Preserve the proven datapath

Unless essential to diagnostic instrumentation, do **not** change:

- `BpfFlowAttribution.kt` tuple matching, reverse-map confirmation, conflict quarantine, snapshot freshness, and TCP SYN tuple-reuse guard.
- `TunTrafficEngine.kt` packet forwarding, `ALLOW`/`DROP`/rate-limit decisions, queueing, and quota accounting.
- `HostFirewall.kt` block precedence and bandwidth policies.
- `DataQuota.kt` quotas, calendar reset behavior, checkpointing, and per-client persistence.
- Shizuku, TUN/VPN setup, SoftAP client discovery, Wi-Fi/mobile-upstream routing, and BPF default settings.

**Important:** The present behavior `matchedMac == null => PacketDecision.ALLOW` remains **unchanged in this diagnostic phase**. The goal is to accurately quantify and categorize these cases before selecting a fix.

## 3. Expose useful attribution telemetry

Add a **Developer Settings → BPF Attribution Diagnostics (Debug)** panel, only in the experimental variant or behind a compile-time debug feature flag.

Display current session's counters and meaningful denominators:

1. Total inspected eligible internet packets and bytes.
2. Successfully attributed packets/bytes, separated into `DIRECT_IP`, `BPF_NAT`, and `CONNTRACK_PROCFS`.
3. Unattributed **forwarded** packets and bytes; distinguish from unrelated local control traffic.
4. Unknown / no tuple in BPF snapshot.
5. Snapshot unavailable/invalid/expired; age in milliseconds; last successful collection timestamp.
6. Ambiguous/conflicting ownership and TCP SYN tuple-reuse guard outcomes.
7. Unsupported protocols, non-initial fragments, invalid transport ports, IPv4/IPv6 breakdown.
8. BPF collection attempts, successes, parse failures/rejected lines, last error, actual collection duration, and last published mapped-flow count.
9. Current interface names/ifindices, session/binding generation, snapshot generation and age.
10. Current connected-client count, clients with manual block, clients with exhausted quotas (aggregate counts only by default).
11. Per-client quota-drop and firewall-drop counters (aggregate summary; avoid exposing personal data by default).

**Coverage metrics:** Define the denominator explicitly. Show e.g. `attributed eligible packets / all eligible inspected packets`, NOT a misleading ratio mixing multicast/link-local control frames. Count bytes as well as packets. Report unknown-forwarded numbers separately from unsupported traffic and denied packets. If a metric is unavailable, say `N/A` rather than `0`.

## 4. Diagnose why each flow cannot be attributed

Define an internal structured reason enum rather than treating all unmatched packets as one category. Suggested reasons:

- `NO_ACTIVE_SNAPSHOT`
- `SNAPSHOT_STALE`
- `SNAPSHOT_INVALID_OR_COLLECTION_FAILED`
- `TUPLE_NOT_PRESENT`
- `TUPLE_AMBIGUOUS`
- `TCP_TUPLE_REUSE_AWAITING_REFRESH`
- `CLIENT_DISCONNECTED`
- `CLIENT_IP_REASSIGNED`
- `IP_BINDING_MISSING_OR_CHANGED`
- `NON_INITIAL_FRAGMENT`
- `UNSUPPORTED_PROTOCOL`
- `INVALID_OR_MISSING_PORTS`
- `IPV6_NOT_SUPPORTED_BY_BPF_MAP`
- `OTHER_UNKNOWN`

Map existing `AttributionOutcome` values to precise reasons without weakening matching. When the existing API lacks enough detail, introduce **diagnostic-only reason propagation** that does not affect `PacketDecision` or traffic forwarding. Ensure reporting reflects both the primary reason and any fallback attempted; avoid counting one packet multiple times in mutually exclusive totals.

## 5. Passive collection first; controlled refresh experiment second

**Phase A (required):** passive telemetry only, using the existing polling and BPF collection logic.

**Phase B (optional, gated by explicit developer switch, OFF by default):** test whether a **rate-limited, asynchronous BPF refresh request** triggered by `TUPLE_NOT_PRESENT` or stale snapshot reduces unknown-forwarded packets.

Safeguards for Phase B:

- Never execute `dumpsys`, subprocesses, or blocking collection on the packet-processing thread.
- Use a single-flight collector, cooldown and bounded refresh frequency; retain normal periodic polling.
- Do not introduce packet delays, new drops, or changes in `ALLOW`/`DROP` outcomes.
- Record refresh triggers, suppressed duplicate requests, collection latency and attribution outcomes **on subsequent packets**, not an invented claim that the first packet was recovered.
- Automatically disable the option when collection health degrades, and report that change.
- Do **not** add a hold-and-retry packet queue in this release: that is a separate risky traffic-behavior experiment.

## 6. Diagnostics UI and report export

Include compact fields for:

- `BPF collection: OK / STALE / UNAVAILABLE / PARSE_FAILURE`
- `Snapshot age`, `Last successful refresh`, `Mapped flows`, `Ambiguous flows`
- `Packets attributed`, `Unknown forwarded`, `Unknown bytes`, `Coverage %`
- Breakdown by attribution source, failure reason, protocol and direction.

Working actions:

- **Reset counters** (confirm first; reset only diagnostics, never policies, quotas or saved client data).
- **Capture snapshot** (existing supported mechanism; asynchronous; report errors).
- **Export diagnostics** (Android share sheet / FileProvider, where appropriate).

Export a timestamped **Markdown** report (optional JSON alongside) containing:

- APK version, app ID, build/commit identifier if available.
- Android version, device manufacturer/model, VPN/TUN mode, SoftAP/upstream interface names.
- Session ID/generation, data-collection interval, monotonic snapshot age, collection result/health.
- Total eligible packet/byte counters, detailed source and failure breakdown, IPv4/IPv6, up/down.
- Enabled experimental switches and aggregate policy status.
- Specific test conditions: number of clients, blocked vs allowed vs quota-exhausted clients; optional manual note.
- A plain-English limitations section: unattributed traffic may still be forwarded; no guarantee of zero leakage.

**Privacy:** default export must not include client MACs, client IPs, public remote addresses, domains, complete BPF dumps, or packet payloads. Add an explicit opt-in to include redacted/hashed endpoint and client identifiers if essential for troubleshooting. Never include credentials, tokens, SSIDs, or private user data. Use scoped storage and clean temporary exports.

## 7. Automated tests

Add/update unit and (where practical) Compose/UI tests for:

- Reason classification for every known `AttributionOutcome` and unsupported/fragment/IPv6 cases.
- Counters: each eligible packet counted once; bytes match packet lengths; separate forwarded unknown vs dropped and local multicast; deterministic reset.
- Source-specific attribution, stale snapshots, tuple reuse, ambiguous ownership, missing IP-to-MAC and client disconnect.
- Report format, denominators, privacy redaction, null/N/A values, overflow/race safety.
- Optional refresh switch default OFF; request coalescing, cooldown, nonblocking behavior and no forwarding-policy changes.
- Stable and experimental APK identity isolation, build version/label, and provider authority collision checks.
- Regression of client block, bandwidth shaping, data quota, calendar rollover, and manual quota reset.

Build the APK and run test suite. Report the actual commands, exact success/failure outcomes, and any limitations. Do not present unrun device tests as passed.

## 8. On-device test protocol (Samsung hotspot)

1. Install the debug APK alongside stable, verify label and `dev.shizzyluna.proxy.debug` using `adb shell pm list packages`.
2. Stop the stable VPN, start only the debug VPN; verify BPF NAT enabled and correct TUN/upstream bindings.
3. Connect **three** clients: **A manually blocked**, **B with exhausted quota**, **C unrestricted**.
4. On A and B, attempt multiple new HTTPS/HTTP connections, DNS requests and sustained transfers; confirm current behavioral limits without assuming they are fixed.
5. On C, browse/download normally to catch false blocks; include mobile-data upstream and Wi-Fi upstream separately.
6. Measure snapshots with Phase A. If enabled, repeat with Phase B refresh; compare unknown-forwarded packets **and bytes**, attribution coverage and latency with similar traffic.
7. Test reconnect, IPv4/IPv6, airplane-mode/upstream changes, VPN restart, hotspot restart, Android idle/background scenarios.
8. Export one diagnostics report per test run; compare snapshots, failures and actual observed behavior.

Note: A VPN/TUN packet counter does not prove interception of every packet on every Android tethering/offload path. Explicitly record any signs of bypass.

## 9. Acceptance criteria

- Debug APK installs alongside stable with app ID `dev.shizzyluna.proxy.debug`, label `shizzy lua (Debug)` and version `0.10.3-debug`.
- Stable `main` APK package, data, behavior and version remain unchanged.
- Diagnostics accurately identify why packets are unattributed; unknown-forwarded counts and bytes are visible.
- The existing policy outcomes, data quotas, BPF mapping safety checks and traffic shaping are behaviorally unchanged.
- Export produces a **redacted** report that can be shared for engineering analysis.
- No new hot-path blocking, significant packet latency, runaway polling, or high memory growth.
- Test results are explicit and evidence-based; any failure or unavailable device evidence is stated clearly.

## 10. Deliverables

1. Source changes committed **only on branch `debug`**.
2. `shizzyluna-v0.10.3-debug.apk` and SHA-256 digest.
3. `DEBUG_BPF_ATTRIBUTION_REPORT.md` template/sample (labeled sample), plus test results actually performed.
4. `DEBUG_CHANGELOG.md` listing touched modules, build commands, checks and known limitations.
5. A short engineering recommendation based on observed breakdown: whether to attempt refresh-on-miss, a bounded hold-and-retry queue, stronger IPv6 attribution, or a configurable safety policy next.

**Non-goal:** This build is not a fix for zero packet leaks. It is a safe measurement instrument to identify the largest source of unknown traffic without risking the proven multi-client behavior.
