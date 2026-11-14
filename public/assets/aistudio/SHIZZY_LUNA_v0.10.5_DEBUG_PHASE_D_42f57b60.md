# Shizzy Luna v0.10.5-debug — Phase D: Persistent Connection Leak Investigation and Experimental Enforcement

## 0. Implementation brief for coding LLM

**Repository:** `https://github.com/geraldotech/shizzyluna`  
**Target:** existing debug branch; do not merge into `main` without test evidence.  
**Version:** `0.10.5-debug`; increment build ID/schema only as needed and keep backward compatibility.  
**Objective:** investigate and reduce post-block leakage from hotspot clients (notably WhatsApp and Telegram) while preserving connectivity for unrelated allowed clients. **This is an implementation task, not report-only.**

Inspect the *actual repository* before making modifications. Identify current packet-decision path, policy and quota state machine, flow/owner caches, BPF snapshot manager, Phase B refresh-on-miss, Phase C tuple diagnostics, VPN service lifecycle, UI settings, and report exporter. Do not assume these caches or APIs exist; document actual findings and adjust implementation accordingly. Keep existing Phase B/C working.

## 1. Evidence and problem statement

In `0.10.4-debug`, with two hotspot clients and one `QUOTA_EXHAUSTED`, the second client continues using the internet. Browser pages fail to load on the quota-exhausted client, but WhatsApp and Telegram messages can eventually be delivered after delays. This is **observed behavior**, not yet proof of which packet path leaks.

Relevant Phase B+C ON report:

| Metric | Observed |
|---|---:|
| Eligible packets | 285,355 |
| Attributed | 255,092 (89.39%) |
| Unknown-owner packets forwarded | 30,263 (23,507,087 bytes) |
| Verified-owner policy drops | 2,803 (1,742,590 bytes) |
| Phase B refreshes | 103/103 completed; 0 failed |
| Flow keys resolved after refresh | 106 |
| Persistent-after-refresh diagnostic state count | 112 |
| Phase C not-offloaded/not-observable state count | 83 |
| Clients | 2; quota exhausted=1; allowed=1 |

**Interpretation constraints:** Global unknown-owner packets are not attributable to the blocked client. Post-refresh window packets are not necessarily packets that would otherwise leak. Global attribution coverage is not enforcement effectiveness. Phase C state counts may count transitions rather than distinct active flows. Do not claim a resolved leak without independent delivery evidence.

## 2. Scope: two switchable modes

Implement a debug-only mode selection in UI with clear descriptions, accessible without rebuilding the APK:

1. **DIAGNOSTIC (default)** — Preserve current `0.10.4-debug` packet decisions and existing blocking behavior. Add Phase D instrumentation, correlation, and export. *This is not an unrestricted mode*: normal verified-owner policy enforcement remains active.
2. **EXPERIMENTAL_ENFORCEMENT (opt-in)** — Same diagnostics, plus safe changes to policy transition handling: invalidate stale `ALLOW` decisions if such caches exist; re-evaluate verified-owner flows immediately on `BLOCK` or `QUOTA_EXHAUSTED`; ensure policy generation and verified identity are checked in the packet decision path; investigate and fix confirmed fail-open bugs for verified flows. **Never globally drop `UNKNOWN_OWNER`** merely because any client is blocked.

Support switching modes without service restart where feasible, otherwise explicitly signal and perform a safe rebind. Ensure mode and configuration are reported. Default back to DIAGNOSTIC after app upgrade if persistence is uncertain; never silently enable experimental behavior.

## 3. Phase D workstreams

### D1 — Policy transition and generation audit

- Emit monotonic event sequence for `ALLOW -> BLOCK`, quota exhaustion, unblock, quota reset, disconnect, reconnect, IP/MAC binding changes, VPN/hotspot interface rebinding, and mode changes.
- Capture monotonic timestamps (and wall-clock for correlation), session ID, binding generation, policy generation, anonymized client token, cause, old/new states.
- On policy transition, increment client-specific policy generation atomically; packet decisions must not reuse stale `ALLOW` results if they exist.
- Define ordering: when quota exhaustion is committed, new decisions for **verified** client traffic see `DROP`; avoid time-of-check/time-of-use races. Document any unavoidable boundary packet.
- On reconnect or binding changes, invalidate stale owner and policy cache entries. Do not link a newly randomized MAC to the previous client without verified evidence.

### D2 — Existing-flow and cache audit

- Locate flow tables, NAT mappings, decision caches, tracked sockets and any memoized `ALLOW`. Record whether they exist; do not add redundant mechanisms.
- On verified client block/quota transition, re-evaluate all currently verified flows belonging to that client. Use generation-guarded lazy invalidation if safer than modifying a concurrent table directly.
- Count active verified flows at transition, stale-allow cache hits prevented, decisions recomputed, verified-owner drops, and any packet allowed after policy transition with verified owner (this last metric must be zero except explicitly documented permitted control exceptions).
- Ensure no stale policy is reused across sessions/binding generations.

### D3 — Unknown packet / persistent tuple audit

- Retain `UNKNOWN_OWNER => ALLOW` to prevent collateral impact. Instrument unknown traffic **after a block transition** without attributing it to a particular client.
- Extend Phase C with bounded, ephemeral per-flow tracking of repeated/persistent misses and sampling of packet direction, IPv4/IPv6, TCP/UDP, tuple lookup path, reverse lookup, packet age, snapshot age, interface generation, policy epoch, and reason.
- Compare observed post-NAT tuple schema against actual parsed upstream/downstream BPF entries, including swapped endpoints, directions, and NAT rewrites, but only accept owner assignment after reverse-confirmed, non-ambiguous evidence.
- Track `NEW_MISS`, `REPEATED_MISS`, `PERSISTENT_AFTER_REFRESH`, `RESOLVED_AFTER_REFRESH`, `KEY_MISMATCH_SUSPECTED`, and `NOT_OFFLOADED_OR_NOT_OBSERVABLE` with explicit classification thresholds. Distinguish event totals from current-state gauges.
- If ownership cannot be established, report `UNPROVEN_OWNER`, not `LEAK_FROM_BLOCKED_CLIENT`.

### D4 — Path diversity and protocol audit

- Separate TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6 and direction; highlight UDP/443 (QUIC-capable), UDP/53 (DNS), and long-lived TCP connections. Do not infer specific app identity from port alone.
- Correlate VPN state, `swlan0`/downstream ifindex, upstream ifindex, routing or fallback transitions, offload visibility, and snapshots; detect periods of `WAITING_FOR_INTERFACES`, `BINDING_INTERFACES`, and `ATTRIBUTION_READY` if warranted by actual implementation.
- If a route bypasses the observable TUN and cannot be captured with available non-root permissions, explicitly report `PATH_NOT_OBSERVABLE` and implementation limits. Do not fabricate access to kernel hooks or client-specific pre-NAT identifiers.

### D5 — Delivery verification and multi-client safety

- Add a test-session start/stop marker and `policyActivatedAt` timestamp to match host logs with **independent observations on the client device**.
- The app must not assert WhatsApp/Telegram delivery based solely on packet counters. User must record: message initiated after quota exhaustion, delivery acknowledged on receiver, time of receipt, and network route (hotspot exclusively; disable client cellular/secondary Wi-Fi or alternative transport).
- Report client-specific drops only when owner is verified. Unknown traffic stays separate from client rows. Keep `ALLOW` client internet working; zero verified-owner drops on allowed client unless another documented policy applies.
- Verify both **explicit BLOCK** and **QUOTA_EXHAUSTED** semantics. Verify upload and download, existing connections and newly opened connections.

## 4. Packet decision invariants

Proposed logical ordering (adapt to existing architecture; do not copy blindly):

```text
packet -> parse metadata / classify control traffic
       -> resolve verified client identity (DIRECT_IP / verified BPF/NAT / validated fallback)
       -> if VERIFIED:
            read current client policy generation and state atomically
            if BLOCK or QUOTA_EXHAUSTED: DROP; count with verified owner
            else: apply allowed/quota/throttle rules
       -> else:
            record unknown reason and Phase C trace (bounded)
            schedule Phase B async refresh if eligible
            ALLOW under existing unknown-owner policy
```

Critical requirements:
- Never infer identity from an unverified tuple, port, likely app, destination IP, or the fact that only one client is blocked.
- No global `DROP` for unknown packets; no blanket UDP/TCP/IPv6 block.
- Snapshot refresh is asynchronous and must not block packet processing; it cannot retroactively undo a transmitted packet.
- Thread-safe policy publication, no stale verified-owner association across interface rebinding.
- Existing connection revalidation must not affect an unrelated `ALLOW` client.
- Leave packets for necessary local control traffic under their established safe path; document exceptions.

## 5. Telemetry and report schema (v3 proposed)

Add a **Phase D** section to the existing Markdown report; retain all current Phase B/C fields for side-by-side comparison.

Required fields:

```text
phaseD.mode: DIAGNOSTIC | EXPERIMENTAL_ENFORCEMENT
phaseD.sessionId, bindingGeneration, policyGeneration
phaseD.policyTransitions: counts per cause and timestamps
phaseD.verifiedFlowsAtTransition
phaseD.staleAllowCacheHitsPrevented
phaseD.verifiedAllowedAfterBlockPackets (target 0)
phaseD.verifiedDroppedAfterBlockPackets / Bytes
phaseD.unknownForwardedAfterBlockPackets / Bytes (GLOBAL, not client-specific)
phaseD.unknownPostBlockByProtocolAndDirection
phaseD.persistentMissAgeAndSnapshotSurvival
phaseD.udp443 / udp53 / tcpLongLivedDiagnostics
phaseD.interfaceLifecycleEvents
phaseD.deliveryTestMarkers (manual evidence; do not infer success)
phaseD.evidenceConfidence: VERIFIED_OWNER | UNKNOWN_OWNER | PATH_NOT_OBSERVABLE
phaseD.performance: lookup latency, refresh p50/p95/p99, memory and ring-buffer drops
```

For each verified client, include policy transition generation, verified traffic/drop counts **after transition**, along with redacted client token. Label counters as cumulative versus per-window. Avoid storing plaintext payloads, contact info, destination hostnames, raw IP/MAC, or message contents in export. Hash flow identifiers with per-session salt; use bounded ring buffers with explicit eviction counts and TTL. Allow user to reset telemetry between test cases.

Include a result summary with three distinct judgments: (a) verified-flow policy correctness, (b) multi-client isolation, and (c) *independently confirmed* post-block application delivery. Do not use a single misleading “blocking percentage” calculated from global attribution.

## 6. Reproducible test matrix

**Common setup:** Two hotspot clients A/B; A has hotspot as its *only* internet path (disable cellular data, secondary Wi-Fi, and other routing); B is unrestricted. Record build, mode, OS/device, VPN state, interface names/ifindices, session/binding generations, snapshot status, policy transition timestamp, test timestamps, and client-reported delivery. Run each test in DIAGNOSTIC and EXPERIMENTAL_ENFORCEMENT modes under as similar conditions as possible.

| ID | Test | Procedure | Expected / measured outcome |
|---|---|---|---|
| D01 | Baseline | A/B both ALLOW; browse and send messages | Both operate; counters baseline |
| D02 | Quota exhaustion / browser | Exhaust A quota; start new HTTPS requests | A verified flows DROP; B remains normal; record any delivery |
| D03 | Quota exhaustion / WhatsApp | Maintain existing chat connection, exhaust quota, send NEW numbered message | Log request/ack timestamps; any receiver-confirmed delivery means leak remains |
| D04 | Quota exhaustion / Telegram | Same as D03 for Telegram | Same evidence requirements |
| D05 | Fresh app connections | Force-close/reopen messaging apps **after** A blocked | Compare new vs pre-existing connection paths |
| D06 | Explicit BLOCK | Set A BLOCK (not quota); repeat D02-D05 | Match expected policy semantics; note differences |
| D07 | UDP/443 | Generate QUIC-capable traffic if supported | Track tuple resolution, persistent unknown and delivery |
| D08 | UDP/53 | Generate DNS requests and record method | Track DNS UDP/53; do not assume encrypted DNS uses this port |
| D09 | IPv4/IPv6 | Test each supported family; note if family unavailable | No silent bypass claims without observed route |
| D10 | Multi-client safety | Block A, transfer on B continuously, reconnect B | B remains functional; no wrongful verified-owner drops |
| D11 | Lifecycle | Toggle VPN/hotspot; reconnect A/B | Invalidate stale bindings; no incorrect cross-client decisions |
| D12 | Stress / races | Rapid quota reset, block/unblock, mode flips; traffic in flight | No stale ALLOW for VERIFIED blocked owner; no crashes/deadlocks |
| D13 | Diagnostics overhead | Compare B/C/D OFF vs ON under similar load | Quantify overhead and missed samples; bounded resources |
| D14 | Persistent tuple proof | Reproduce 3+ snapshot misses and inspect key-mismatch hypotheses | Report verifiable cause or UNKNOWN; no invented owner |

Use at least three repeat runs for D03/D04/D06/D10; include run-by-run results and timestamps. Receiver acknowledgments are the pass/fail evidence for messaging deliveries, not app-local “sent” status alone.

## 7. Acceptance criteria

- **AC01** UI exposes both modes and accurately reports the active mode; DIAGNOSTIC is default.
- **AC02** Existing verified-owner BLOCK/QUOTA logic remains active in both modes.
- **AC03** EXPERIMENTAL_ENFORCEMENT re-evaluates verified-owner policy on transitions and prevents any stale cached ALLOW decisions (if caches exist); code review and automated test demonstrate this.
- **AC04** No verified blocked-owner packets are intentionally ALLOWed after policy transition, excluding clearly defined protocol/control exceptions; log any violation.
- **AC05** No confirmed verified-owner drops for the unrestricted client during D02-D12.
- **AC06** Unattributed traffic is preserved as `UNKNOWN_OWNER`, not falsely attached to Client A; `UNKNOWN_OWNER => ALLOW` remains explicit.
- **AC07** Phase B/C continues functioning and has zero regressions in reverse-confirmed ownership or parser validity in the test environment.
- **AC08** Interface/session changes invalidate stale binding and policy information; no cross-client identity leakage.
- **AC09** Phase D report contains required timestamps, mode, counts and confidence labels, and supports telemetry reset.
- **AC10** Diagnostic buffers have a cap, TTL, safe redaction and measured overhead; no unbounded per-flow growth.
- **AC11** D03/D04 tests include independently verified receiver delivery evidence and document any successful message as **unresolved leakage**.
- **AC12** Any failure to reach zero confirmed deliveries must be reported without claiming complete enforcement; document whether rootless architecture prevents the remaining fix.

**Success target:** Zero independently receiver-confirmed *new* application messages after a verified block transition, in reproducible tests using hotspot as A's sole internet path, **without disrupting B**. This is an outcome to test, **not a promise** that existing post-NAT/BPF observation can guarantee it.

## 8. Implementation deliverables

1. Code changes for v0.10.5-debug, isolated from stable/main.
2. UI toggle for two modes with clear safety warning and active-state display.
3. Policy-generation and flow revalidation fixes, *only where supported by the actual current code*.
4. Instrumented and redacted Phase D report exporter; preserve B/C diagnostics.
5. Automated unit/integration tests for stale cache decisions, generation races, reconnects, multi-client isolation, and export integrity.
6. `PHASE_D_IMPLEMENTATION_NOTES.md` with inspected files, actual packet path, root causes confirmed versus speculative, changed modules, limitations, and instructions to reproduce D01-D14.
7. Before/after results in both modes, with explicit `NOT_TESTED` for scenarios not run. Never invent percentages, packet drops, delivery results or success claims.

## 9. Non-goals

- No root-only iptables/eBPF write permission assumptions, covert privilege escalation, or unsupported netfilter changes.
- No blind drop of unknown-owner forwarded packets.
- No application identification based only on destination ports.
- No claim that generic Android `VpnService` can enforce per-hotspot-client policies before NAT without verified evidence of such a path.
- No changes to production `main` during this experimental phase.

**Final instruction to coding LLM:** Start by reading the actual implementation and producing a concise code-path map. Implement the safe policy-generation fix and complete Phase D diagnostics as appropriate. Run available tests, report precise evidence and unresolved limits, and prioritize correctness and multi-client safety over inflated blocking percentages.
