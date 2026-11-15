# Shizzy Luna v0.10.9-debug — Per-Host Domain Enforcement & VPN Loss Recovery

## 1. Context and objective

Implement on the `debug` branch, preserving the current package and debug build conventions. Reviewed baseline: `7fb3b1b94b9ae35c447fc617e63483f5ed0cb810` (verify HEAD before editing). Set version to `0.10.9-debug`; increment the service build ID according to the existing convention. Do not change the stable branch.

User observations: global domain rules work with the default DNS, per-host rules do not reliably work, and customized/encrypted DNS can bypass plaintext inspection. When an external VPN disconnects, Shizzy stops the session/hotspot for protection, even if the VPN reconnects automatically later. The user wants this shutdown to be optional.

Deliver actual behavior changes, not a diagnostics-only release. Keep both existing blocking modes, VPN/TUN architecture, and global domain filtering. Do not reintroduce Pre-NAT or add a new blocking engine.

## 2. Findings from the current code

- `TunTrafficEngine.kt:2902+`: `resolveClientMacWithSource()` already tries `DIRECT_IP`, then verified `BPF_NAT` for eligible post-NAT IPv4 traffic, and other existing fallbacks. Do not duplicate the resolver.
- `TunTrafficEngine.kt:3434+` and `3645+`: domain filtering already runs on unknown-owner and verified-owner outbound paths. The unknown path supplies `matchedMac=null, ownerVerified=false`; the verified path supplies a MAC.
- `DomainBlockingEngine.kt:1420+`: `evaluateParsedDnsQuery()` matches client rules by normalized MAC and hostname. A matching client rule with no owner increments `unknownOwnerClientRuleSkips` and permits the query unless a global rule blocks it. Hostname evaluation has a similar ownership gate; verify it during implementation.
- `VpnWatchdog.kt`: checks every 5 seconds, emits `Lost` after two consecutive misses, and terminates its monitor on loss.
- `VpnUpstream.kt`: on `Lost`, clears the handle and calls `onLost`; on `Adopted`, binds the datapath to the new VPN handle.
- `TetherSession.kt:25,314–345`: VPN loss calls `tearDownAfter()`, which calls `stop()` and sets `ERROR`. A separate `SessionWatchdog` protects against unexpected tethering upstream drift.
- `SessionService.kt:91`: settings are loaded when starting the session; the VPN loss policy must be propagated through the actual controller/service boundary.

Line numbers are baseline references, not a substitute for inspecting the latest source.

## 3. Feature A — Improve Per-Host Domain Blocking

### A1. Preserve correct matching and integrate verified attribution

1. Trace actual runtime rule publication from UI/settings to `TunTrafficEngine.updateDomainRules()` and `DomainFilterEngine.replaceAllRules()`. Verify client MAC normalization on both sides, active rule generation, and that updates reach the running service without restart.
2. Use existing verified attribution results for DNS, HTTP Host, and TLS SNI. Confirm raw packet bytes and lengths reach both evaluation branches. Do not label a MAC verified merely because it is non-null; preserve the existing owner confidence checks and session/binding generation constraints.
3. If `Experimental BPF` is off, clearly indicate that post-NAT per-host matching may be unavailable. Do not silently enable a global experimental feature or bypass its validation. Provide a UI hint to enable it where supported.
4. Make global rules independent of individual MAC attribution, but retain verified hotspot provenance. Audit the hard-coded `fromDedicatedHotspotTun=true` / `isHostOriginated=false` assumptions against the actual datapath; never broaden global rules to host-phone traffic.
5. Normalize case, trailing DNS dot, IDNA and label boundaries consistently. Use exact MAC equality, never IP-only or substring MAC matching. Retain exact-host and root-plus-subdomains semantics.
6. Replace rule snapshots atomically (immutable snapshot or equivalent) if the current clear/repopulate operation permits a transient empty ruleset. Readers must see one consistent generation per evaluation.

### A2. Targeted DNS attribution improvement

For a plaintext DNS query matching an active per-host rule, if ownership is unknown and a refreshable BPF miss occurred, request the existing asynchronous refresh-on-miss mechanism subject to its cooldown, single-flight and breaker. Avoid duplicate refresh requests and avoid full snapshots on every query. If the existing refresh feature is disabled, respect that setting and expose the limitation.

Implement an optional, bounded DNS-only retry queue **only if the current forwarding architecture supports safe asynchronous packet ownership and reinjection**. Prefer this as a debug toggle, default off. Suggested initial budget: 150–300 ms maximum per query, at most 128 pending packets and 256 KiB aggregate, copied packet bytes, monotonic deadlines, no blocking the TUN reader. Reuse the exact original full tuple and re-run verified attribution against a fresh snapshot. A rule matching a hostname is not proof of ownership. Do not use guessed MACs, client order, remote IP alone, DNS transaction ID alone, or assume the sole connected client owns all TUN traffic.

- Verified owner found: evaluate current domain rules and forward or block exactly once.
- Still unknown, ambiguous, expired, or queue full: preserve existing fail-open behavior for per-host-only rules; apply a matching global rule if independently eligible. Count the reason.
- Rule/session/binding changes: revalidate or cancel safely; never reuse an old owner across sessions or IP/MAC changes. On shutdown cancel pending work and do not inject stale replies.
- If holding the query prevents the kernel from creating an observable NAT entry, document this and disable the retry experiment; do not claim that waiting guarantees recovery.

Do not make a full DNS proxy, DHCP replacement, TLS MITM or encrypted-DNS interception mandatory for this release. A local DNS proxy may be a separate PoC later if source IP visibility is proven.

### A3. Protocol correctness and telemetry

Preserve existing UDP DNS REFUSED synthesis, checksum handling and reinjection. TCP DNS is currently single-segment inspection; do not claim complete TCP stream support or a synthesized TCP REFUSED unless implemented and tested with sequence handling. Preserve TLS/HTTP bounded inspection; do not claim QUIC, ECH, DoH or DoT decryption. Do not globally block UDP/443 or public resolver IPs as a workaround.

Expose counters by scope and attribution source: `dnsInspected`, `dnsDirectIp`, `dnsBpfNat`, `dnsUnknownOwner`, `clientRuleMatched`, `clientRuleOwnerMismatch`, `clientRuleSkippedUnknownOwner`, `clientDnsBlocked`, `clientHostnameBlocked`, `dnsRetryQueued`, `dnsRetryResolved`, `dnsRetryTimeout`, `dnsRetryOverflow`, `dnsRetryCancelled`, `globalDnsBlocked`. Count unique evaluation outcomes separately from retries. Include recent redacted diagnostic records with rule generation, protocol, direction, ownership source and skip reason; avoid raw DNS payloads or full MACs in exported logs. Do not mark a feature PASS merely because counters are zero.

## 4. Feature B — Optional hotspot shutdown on VPN disconnect

### B1. Settings and user interface

Add a persisted boolean `stopHotspotOnVpnDisconnect` (suggested DataStore key `stop_hotspot_on_vpn_disconnect`), default `true` for new and migrated installations, preserving existing protection. Add a checkbox/switch under VPN settings:

- Label: **Stop hotspot when VPN disconnects**
- ON: Existing protection; stop the session if the bound VPN disappears.
- OFF: Keep the hotspot and Shizzy session running, wait for VPN recovery, and automatically rebind when it returns.
- Supporting warning: **While the VPN is disconnected, internet access may be interrupted. Traffic must not silently bypass the VPN.**

For this release, keep OFF behavior fail-closed for forwarding while the previously bound VPN is unavailable; do not automatically route through mobile data or Wi-Fi outside the VPN. A future explicit direct-internet fallback would be a separate security-sensitive feature. This is a deliberate safe default; the user requested keeping the hotspot on, not bypassing the VPN.

With `VpnMode.NEVER`, the setting is irrelevant; disable or hide it. Preserve `AUTO` and `ALWAYS` startup semantics. In AUTO, distinguish a session that has never adopted a VPN from a session whose adopted VPN was lost. ALWAYS still requires a VPN at startup. The new option controls loss after adoption, not startup requirements.

Wire through `SettingsStore`, `SessionViewModel`, `ui/VpnSection.kt` and the relevant controller, service and Shizuku IPC/session configuration. Inspect actual interfaces and version contract before editing; keep backward compatibility or explicitly bump the contract. Prefer applying changes live to the active session using its serialized state owner. If live updates cannot be safely supported, label the setting as effective on next start rather than silently ignoring it.

### B2. Watchdog and recovery state machine

Current loss terminates both monitoring and the session. Merely skipping `stop()` is insufficient: the watchdog would remain dead and never detect recovery.

Introduce explicit states (names may map to existing enums): `VPN_BOUND`, `VPN_WAITING_FOR_RECOVERY`, `VPN_REBINDING`, `VPN_RECOVERY_FAILED`, `SESSION_STOPPED`. Maintain the foreground service, hotspot, TUN resources, client configuration, quotas, rules, and monitoring when the option is OFF. Do not restart the hotspot simply because the external VPN disappeared.

On loss detection, ensure new and in-flight forwarding cannot escape the VPN. Inspect `SessionResources.bindDatapathTo`, the native datapath, socket creation and existing connections. Gate forwarding on the current validated bound network; suspend/close affected sockets and cancel queued work as necessary. Do not treat `bindDatapathTo(0)` or clearing the handle as a safe pause; those may allow default-network fallback. Verify behavior with packet capture or controlled endpoints. The current two-miss debounce is appropriate for teardown/UI, but is not a leak-prevention guarantee: enforce network binding continuously and handle network loss/socket errors promptly, including the debounce period.

When OFF, emit loss once per outage, keep watchdog running, reset its observed/bound state so the same handle or a new handle can be adopted after recovery. Avoid repeated notifications, thread leaks and busy loops. On recovery validate the VPN network and binding, reopen affected transport sockets as required, invalidate stale attribution/flow caches when necessary, then resume forwarding. Retain client policy and quota records. Do not resume if rebind fails; retry with bounded backoff while showing waiting/error state. Serialize rebind, manual stop, mode switch and teardown; stale callbacks must not revive a stopped session.

Keep the separate `SessionWatchdog` protection against actual upstream drift. If it currently treats the expected waiting condition as fatal, distinguish verified retained TUN/upstream from genuine unsafe drift; do not disable all safeguards. If maintaining the hotspot safely is impossible due to platform behavior, report the limitation instead of silently routing traffic directly. Never override a manual stop.

When ON, preserve existing teardown behavior after confirmed loss. If switched ON during an outage, apply the documented stop behavior (if live updates are supported). When OFF and VPN does not return, stay in the waiting state until manual stop or an independent fatal safety condition. No arbitrary timeout that shuts down the hotspot.

### B3. UI and logging

Expose `VPN connected`, `VPN disconnected — waiting for reconnection`, `VPN reconnecting`, and `VPN recovered` in status/notification as appropriate. Do not display the existing "Session stopped to keep devices protected" message when the session remains active. Distinguish hotspot association from internet availability. Log policy value, previous/new network handle (redacted if exported), outage/recovery count, waiting duration, rebind success/failure, forwarding gate state, and whether hotspot teardown occurred. Preserve explicit user stop and other fatal error messaging.

## 5. Reproducible tests

Use two hotspot clients A (Dell) and B (A55); disable alternate internet paths on clients. For DNS tests, disable browser secure DNS and flush caches; use explicit plaintext queries (`nslookup example.com 8.8.8.8`) and compare with default DNS. Record baseline and repeat under the same upstream and mode. Use a domain known to resolve successfully before applying rules.

| ID | Scenario | Expected |
|---|---|---|
| D01 | Global rule, A and B | Both matching plaintext queries blocked; unrelated domains work |
| D02 | Per-host rule A only, verified DIRECT_IP | A blocked; B resolves same domain |
| D03 | Per-host rule A only, verified BPF_NAT | A blocked; B resolves same domain |
| D04 | Unknown owner, matching per-host rule | No collateral block; skip reason recorded |
| D05 | Unknown owner, matching global rule with proven hotspot provenance | Global rule still blocks |
| D06 | BPF disabled, then enabled | Accurate attribution source and UI status; no fake ownership |
| D07 | Targeted refresh resolves DNS owner | Current per-host rule applied to held packet if retry enabled |
| D08 | Retry timeout/overflow/session change | Bounded queue; no stale replay; documented fail-open policy |
| D09 | Exact/subdomain, IDNA/case, MAC normalization | Correct matching, no substring matches |
| D10 | Rule edit/remove during active traffic | New generation applied without transient empty rule table |
| D11 | DoH/DoT/QUIC and cached DNS | Limitations recorded; no false coverage claims |
| D12 | Host phone accesses blocked domain | Host unaffected; confirm actual provenance |
| V01 | Default setting ON, VPN loss | Existing protected teardown occurs |
| V02 | OFF, VPN loss longer than 10 seconds | Hotspot remains active, clients associated, session waiting |
| V03 | OFF, VPN returns with new handle | Automatic rebind, internet resumes, no hotspot restart |
| V04 | OFF, VPN returns with same handle | Recovery event and rebind still occur |
| V05 | OFF, VPN absent for 5 minutes | No teardown solely due to VPN loss; no direct leakage |
| V06 | Rapid VPN flapping | No duplicate watchers, stale sockets, teardown/rebind races |
| V07 | Manual stop while waiting | Resources cleaned; subsequent VPN recovery does not restart session |
| V08 | AUTO without initial VPN / ALWAYS without VPN / NEVER | Existing startup contracts preserved |
| V09 | Setting persistence and migration | Default ON; OFF survives restart; live behavior matches UI |
| V10 | Rebind failure or actual upstream drift | Safe waiting or existing fatal protection; no false READY |
| V11 | Quota and domain rules across recovery | Rules and usage retained; no cross-client policy reassignment |
| V12 | Leak verification during debounce/outage/rebind | No successful non-VPN forwarding from either client |

Use fake locator/clock and fake binding interfaces for watchdog tests. Test real device behavior with VPN reconnecting automatically, including both mobile and Wi-Fi underlay where available. Separate unit-tested, device-tested, failed and not-run cases in the report.

## 6. Acceptance criteria

- AC01: Both existing modes remain selectable; no Pre-NAT option restored.
- AC02: Existing global blocking works; no host-phone collateral blocking.
- AC03: Verified DIRECT_IP and BPF_NAT ownership can each drive per-host DNS rules in tests; A-only rule does not affect B.
- AC04: Unknown-owner rules remain fail-open and observable; no inferred identity or 100% enforcement claim.
- AC05: DNS retry, if implemented, is bounded, optional and race-safe; report real recovery counts and limitations. If unsafe, omit it and explain why.
- AC06: New setting persisted, default ON; OFF keeps hotspot/session active across tested VPN loss and recovery.
- AC07: Watchdog continues monitoring while waiting and automatically rebinds on recovery, including same/new handles.
- AC08: No silent fallback outside VPN during waiting, debounce or failed rebind; verify on-device. If unverified, explicitly mark not verified.
- AC09: Client policies, quotas and domain rules survive recovery; no forced hotspot restart on routine VPN recovery.
- AC10: Manual stop, genuine upstream drift protection and exclusive engine invariant remain intact.
- AC11: Accurate status and telemetry distinguish desired policy, applied result, and actual runtime state.
- AC12: Debug APK builds, existing tests pass, new unit/integration tests added; report exact files changed and actual test results.

## 7. Delivery

Implement changes in `debug`; produce debug APK and concise implementation summary. Include reproducible commands, test results, limitations and any behavior not verified on hardware. Do not claim device-level success from compilation or synthetic counters alone. Do not remove VPN or change its intended upstream routing. Focus on functional Per-Host improvement and reliable optional VPN recovery, not more broad BPF experiments.
