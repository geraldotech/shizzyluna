# Shizzy Luna v0.10.2 — Implementation Specification

**Repository:** https://github.com/geraldotech/shizzyluna  
**Baseline:** latest committed `0.4.0-rs-lua.10.1` (`versionCode=16` when this specification was prepared)  
**Target:** `versionName=0.10.2`, `versionCode=17` (increase further if the current repository has already advanced).  
**Scope:** new Android application identity, streamlined About modal, persistent per-client data quotas.  
**Language:** implement in English, consistent with the current app.  
**Priority:** preserve the functional multi-client firewall and BPF/NAT attribution from lua.10/10.1.

## 0. Working instructions for the implementing LLM

1. Inspect the CURRENT local repository and `git status` before edits; do not overwrite newer changes. Inspect existing data types, services, Compose UI, policy pipeline, tests, and Gradle settings. Create a dedicated branch if appropriate.
2. Implement changes, not merely a proposal. Keep the diff focused, explain any unavoidable change outside the files listed below.
3. Run the existing unit tests and Android build. If tooling is unavailable, explicitly say which checks could not be executed; **never claim an APK was produced if it was not**.
4. Never disable or mock BPF to make tests pass. Never treat a stored quota as proof of live enforcement.
5. Preserve existing application data where technically possible. Changing application ID creates a distinct app (see migration caveat below).
6. Report changed files, commands, test results, limitations, APK location and SHA-256 checksum.

## 1. Version and app identity

In `app/build.gradle.kts`:

```kotlin
android {
    namespace = "dev.shizzi" // KEEP existing Kotlin/Compose namespace
    defaultConfig {
        applicationId = "dev.shizzyluna.proxy" // NEW installed package identity
        versionCode = 17
        versionName = "0.10.2"
    }
}
```

- Keep `namespace = "dev.shizzi"` and existing `package dev.shizzi` statements; **do not** bulk rename source packages, AIDL, Kotlin classes, or imported symbols.
- Set the **launcher-visible app label** to exactly `shizzy lua` (adjust `AndroidManifest.xml` / string resources as appropriate). Preserve existing application icon and functionality.
- Audit manifest authorities, `FileProvider` authorities, permission names, deep links, pending intents, service component names, shortcuts and package-scoped identifiers for references to the former application ID. Use `${applicationId}` for authorities where appropriate; avoid renaming internal class packages.
- Verify application installs and launches under `dev.shizzyluna.proxy` without crashing. Validate Shizuku service binding and VPN consent on the new package, including any hardcoded package identifiers.
- **Migration caveat:** Android treats `dev.shizzyluna.proxy` as a new app, not an upgrade to `dev.shizzi`. Existing DataStore settings, MAC rules and app VPN permission will **not automatically transfer**. Do not promise migration. Do not silently delete the old app. Clearly inform the user in release notes; offer only a separate explicit migration feature if deemed necessary later.
- Because the user has tested that per-client enforcement depends on experimental BPF NAT attribution, its default must remain **enabled** for new installs. The Developer setting and diagnostic screen must remain available.
- If `versionCode=17` has already been used on the target branch, choose a strictly higher integer and document why.

## 2. About: one settings entry opening a modal

**Existing file:** `app/src/main/java/dev/shizzi/ui/SettingsPage.kt` currently contains separate `GitHub`, `Report a bug`, and `Author` actions in `AboutSection()`. Replace these three rows with **one `About` settings action** that opens a Compose `AlertDialog` or an existing styled modal/sheet.

Desired display:

```text
About
  ┌──────────────────────────┐
  │        shizzy lua        │
  │      Version 0.10.2      │
  │    Author: GeraldoDev    │
  │                          │
  │  GitHub ↗                │
  │            Close         │
  └──────────────────────────┘
```

Requirements:
- Display current version **dynamically** from installed package metadata or generated `BuildConfig.VERSION_NAME`, not a hardcoded `0.10.2` label (enable `BuildConfig` generation if necessary, or use `PackageManager`).
- Display author exactly **`GeraldoDev`**.
- Clicking GitHub opens **https://github.com/geraldotech/** via the existing safe external URL helper / `ACTION_VIEW`.
- Close by tapping Close, the Back button or outside the dialog, following the app's established UI pattern.
- Remove outdated links to the original author's GitHub / website / bug report **from this About section**. Do not make unrelated license or attribution changes; retain third-party license notices wherever legally required.
- Reuse the app's Material theme, labels, spacing, accessibility semantics and dark-mode styling. Avoid adding unnecessary dependencies.
- Test modal open/close, correct version, link target, screen rotation / recomposition if feasible.

## 3. New feature: persistent per-client Data Limit

### 3.1 Product behavior

Add **Data Usage Limit** to the existing `Configure Host Rules` dialog for both connected and saved offline MAC rules.

- `0` means unlimited quota.
- Specify a positive integer limit **in MB** (unit for data quantity, not Mbps). `1 MB = 1,048,576 bytes`, `1 GB = 1024 MB` in this UI; avoid confusing this with the existing speed limit measured in Mbps.
- Allow renewal policy: **Daily**, **Weekly**, **Monthly**, or **Manual reset**. Default to Manual reset or the least surprising existing convention; specify it in the UI, tests and release notes. Prefer a local calendar boundary using device timezone for daily/weekly/monthly. Define weekly start as Monday, monthly as first day of month, daily at local 00:00.
- When confirmed attributable usage reaches the allowance: **block internet traffic for that client** until quota reset, while preserving the MAC's connection to the hotspot. The quota block must be integrated into the existing client policy result; it must not change the administrator's persistent `isBlocked` field.
- A manual block always wins. A disabled quota must not block. Scheduled-access restrictions, duration limits and bandwidth limits must keep their previous behavior.
- Add a **Reset Usage** button with confirmation for the selected client (without removing its quota or other rules).
- Show usage, remaining allowance, percent and enforcement reason on the client card. Example: `1.4 GB / 2 GB`, `70%`, `Data limit reached` vs `Blocked by admin`. Offline rules must retain quota state.
- Show download + upload consumption separately and total combined usage, when those counters can be measured accurately. State plainly that this is *attributed traffic*, not carrier-grade metering.
- Do not automatically reset cumulative usage when the screen, VPN session, app process or hotspot restarts.

### 3.2 Inspect actual traffic/policy code first

Likely files (verify current code and change only what is required):

- `app/src/main/java/dev/shizzi/TetherClient.kt` — `ClientRule`, `ConnectedClient`, serialization/parse and display models (inspect declarations; they may be elsewhere).
- `app/src/main/java/dev/shizzi/ClientManager.kt` — saved rule policy and current clients.
- `app/src/main/java/dev/shizzi/SettingsStore.kt` — DataStore preferences and rule persistence.
- `app/src/main/java/dev/shizzi/TunTrafficEngine.kt` — per-packet decisions and already-attributed traffic metrics.
- `app/src/main/java/dev/shizzi/SessionViewModel.kt` and `SessionService.kt` — expose updates to UI safely.
- `app/src/main/java/dev/shizzi/ui/ClientsPage.kt` — rule editor and client badges.
- `app/src/test/java/dev/shizzi/ClientManagerTest.kt` — extend regression tests.

The original `ClientsPage.kt` contains `ConfigureClientDialog`, `bandwidthLimitKbps`, `connectionTimeLimitMinutes`, `scheduleEnabled`, `scheduleStartHour` and `scheduleEndHour`. **Preserve them all.** Keep the lua.10.1 Mbps text input and hour picker exactly as finalized.

### 3.3 Persistence/data-model design

- Introduce new fields conservatively, e.g. `dataLimitBytes: Long` (or `dataLimitMb: Long` if all conversions are centralized) and a stable `QuotaResetPeriod` enum; choose one canonical unit **bytes** for enforcement.
- Store period metadata and the start of the active quota window. Use a durable keyed record per normalized MAC, with uploaded/downloaded counted bytes, last durable update and current accounting epoch/window. It must survive process death and reboot.
- Maintain **backward compatibility with existing saved ClientRule JSON**: absent quota fields => unlimited and no quota block. Existing rules must retain aliases, MAC, blocked state, speed limits, duration and schedules when edited/saved.
- Avoid writing DataStore on every packet. Use a thread-safe in-memory accumulator with throttled/checkpointed persistence, plus flush on orderly shutdown and at policy/period changes. Clearly document the worst-case data loss after abrupt process death; consider durable periodic snapshots.
- Do not count a packet multiple times because it is queued, shaped, retransmitted, or evaluated again. Pick and document an explicit accounting boundary (ideally attributed forwarded IP bytes, counting each direction only once). If upload/download direction cannot be distinguished reliably, do not invent direction totals.
- Maintain a stable association between the already validated BPF/flow MAC and quota counters. Do not charge unknown/unattributed packets to a random MAC and do not assign shared `192.0.2.2` traffic to an arbitrary hotspot device.
- Quota use and decision must be **atomic enough to avoid exceeding a limit through concurrent flows** (check and account in an appropriate synchronized policy/engine path). Define threshold behavior at the boundary; a small in-flight overshoot may be documented if it cannot be eliminated safely.
- A quota block should appear in the same enforcement/diagnostic pipeline as existing manual/time blocking, without claiming that unknown/unattributed packets are filtered. Preserve existing fail-open behavior for unknown attribution rather than secretly changing its policy.
- Use overflow-safe arithmetic and sanitize untrusted persisted values. Reject negative, malformed, fractional quota MB and values that overflow `Long` when multiplied into bytes.
- For weekly/monthly resets, account for DST/timezone changes and wall-clock adjustments. Store a stable window identifier; never reset repeatedly for a clock moving backward. The UI should state exactly when the next reset occurs.
- No new background service or wake lock is needed solely to reset counters: update the current window lazily when reading/applying quota and on app/service foreground startup; ensure active clients transition at boundaries without waiting indefinitely for UI navigation.

### 3.4 Preserve successful enforcement architecture

**Do not rewrite** `BpfFlowAttribution.kt`, parser, BPF map snapshots, flow ownership matching, NAT reverse validation, `ifindex` mapping, VPN/`testtun` setup, `HostFirewall` rootless probes or token bucket implementation merely to add quota.

The demonstrated functional approach in lua.10 is:
1. Android tethering NAT maps client flows into shared TUN-facing traffic.
2. BPF diagnostics map translated flow tuple back to an identified hotspot client MAC.
3. `TunTrafficEngine` applies client-specific drop/shaping based on attributed owner.

Observed A/B result on the test Samsung: disabling experimental BPF stopped effective blocking; enabling it restored client isolation. **Keep BPF enabled by default** and retain Developer's BPF toggle and diagnostics. The current engine still forwards some unknown/unattributed packets; neither quota nor firewall should be presented as 100% complete enforcement.

### 3.5 UI specifics

In `Configure Host Rules` under existing speed/connection/schedule controls:

```text
Data Usage Limit
[ 2048                   ] MB     (0 = Unlimited)
Reset period:  [ Daily | Weekly | Monthly | Manual ]
Usage this period: 1.4 GB / 2 GB
[ Reset Usage ]
```

- Keep input keyboard numeric; validate before enabling Save; preserve draft text while editing (do not turn empty input into zero on each keystroke).
- Use consistent label `Data Usage Limit` and keep `Bandwidth Limit (Mbps)` separate. Show MB/GB values with clear conversion and no floating-point boundary errors.
- For manual reset, show `Until manually reset`; for others show the next period reset at the user's local time. UI must fit small screens, work in dark mode, and support accessibility.
- If metering unavailable/attribution partial, display `Usage may be incomplete` and distinguish **configured** quota from **actively enforced** quota. Do not show a green success status without verification.
- Preserve existing add-by-MAC, search, saved offline rules, rule deletion, admin block switch and client stats.

## 4. Regression test matrix (mandatory)

### Automated tests

1. Existing BPF parser tests and ClientManager tests continue to pass unchanged unless assertions legitimately need updating for an additive field.
2. Existing saved rule JSON without quota deserializes identically; reserialization retains old fields and adds safe quota defaults.
3. `0 MB` => unlimited; `1 MB` => 1,048,576 bytes; invalid/negative/overflow values rejected.
4. Quota boundary: below threshold allow; at/above threshold block attributed traffic for that MAC only; another client remains unaffected.
5. Manual block independent from quota exhaustion; a quota reset never clears an admin block.
6. Download/upload attribution once per packet; no double count on shaping queue or retry; unidentified packets not charged to an unrelated client.
7. Persistence after service restart, process death/relaunch, and reconnect; quota remains until period reset.
8. Daily midnight, Monday weekly boundary, first-of-month boundary, clock anomalies and timezone cases.
9. Reset Usage clears only usage state for the selected MAC, not speed, schedule, block or quota configuration.
10. UI tests/manual verification: About modal, version reading, correct GitHub URL, edited rules and quota field, no regression to lua.10.1 Mbps and hour controls.

### On-device acceptance (Samsung S23 Ultra / Android 14 / Shizuku ADB shell, rootless)

Test with three hotspot clients simultaneously, with VPN and BPF NAT attribution **ON**:

- Client A: manual block enabled; no internet for attributable flows.
- Client B: speed limited to 1 Mbps **and** a very small test data quota. Speed limit works prior to exhaustion; quota then blocks attributed traffic without affecting other clients.
- Client C: unlimited speed/data; remains able to browse.
- Restart the app or local VPN session; ensure B's consumed amount persists and B remains quota-blocked.
- Manually reset B's usage; verify B resumes access without losing speed limit.
- Check diagnostics: BPF snapshot publication and flow mappings healthy, counters attributable; report `unknownForwardedPackets`, `unknownForwardedBytes` and any enforcement limitations, not just UI badges.
- Verify mobile-data upstream and Wi-Fi upstream if both are available. Ensure app's local VPN and hotspot recovery behavior remains unchanged.
- Verify both old and new app can coexist under different IDs, but don't run competing VPN sessions. New app must request its own VPN/Shizuku permissions.

**Important:** build/tests on a development machine do not prove on-device network blocking. If no device is connected to the implementing LLM, mark those hardware tests `NOT RUN`, supply exact manual steps, and never report them as passed.

## 5. Build and delivery

Check existing Gradle/SDK setup and run commands appropriate for the repository (examples):

```bash
./gradlew :app:testDebugUnitTest
./gradlew :app:assembleDebug
```

- Resolve compiler errors and failing tests introduced by this feature.
- Package the actual built APK under a clear name **`shizzyluna-v0.10.2.apk`**, preferably in a release artifacts folder, without overwriting the working lua.10.1 APK. Keep debug/release signing status explicit.
- If release signing is required, use the approved signing configuration; do not invent credentials, upload keystores, expose passwords or commit new secrets. Do not silently replace a verified signature.
- Report actual `applicationId`, `namespace`, `versionName`, `versionCode`, APK path, size, SHA-256, signed/debug status, build/test commands and results.
- Provide a short `V0.10.2_CHANGELOG.md` plus a test report listing PASS / FAIL / NOT RUN for automated and on-device checks.
- Include `git diff --stat` and a brief explanation of each modified core file. Do not call release complete if quota blocking is UI-only or if critical regression tests fail.

## 6. Definition of done

- [ ] Application ID `dev.shizzyluna.proxy`; namespace still `dev.shizzi` unless demonstrably necessary otherwise.
- [ ] Launcher label `shizzy lua`.
- [ ] Installed version name `0.10.2`; version code increased.
- [ ] Single About action opens themed modal with dynamic version, `GeraldoDev`, GitHub profile URL.
- [ ] Per-client configurable quota in MB, 0 unlimited, selected reset interval, manual reset.
- [ ] Reliable owner-attributed upload/download accounting and persistent counters; no double charging.
- [ ] Exhaustion integrates with actual packet enforcement; admin/manual controls remain independent.
- [ ] Saved rules from lua.10.1 remain backward compatible within the new install's data model; cross-package data migration explicitly not automatic.
- [ ] All existing BPF/firewall/shaping capabilities preserved; BPF defaults ON.
- [ ] Automated tests/build pass or gaps explicitly documented.
- [ ] Real APK generated and checksum reported; 3-client physical test marked honestly PASS/FAIL/NOT RUN.

**Out of scope:** global ad blocking, domain/URL filtering, captive portal, per-URL client selection, changes to BPF parser, unrelated redesigns, and root-dependent kernel firewall approaches.
