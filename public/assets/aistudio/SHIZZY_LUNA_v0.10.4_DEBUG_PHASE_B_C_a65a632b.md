# Shizzy Luna v0.10.4-debug — Phase B + C
## Async Refresh-on-Miss, Deep Tuple Diagnostics & Multi-Client Safety

**Status:** Implementation specification (experimental, debug build only)  
**Target version:** `0.10.4-debug`  
**Package/application ID:** `dev.shizzyluna.proxy.debug` (verify existing debug flavor; do not change release application ID)  
**Baseline:** `0.10.3-debug`, serviceBuildId `18`, commit `ab2e16dcef1590fe09358fc462cf3a3561439602`  
**Scope:** Diagnostic accuracy and safe attribution improvements, **not** a claim of leak-free enforcement.

## 1. Baseline and problem statement

Baseline observations from the provided v0.10.3-debug report:

| Metric | Observed |
|---|---:|
| Eligible packets / bytes | 77,212 / 63,960,130 |
| Attributed packets / bytes | 12,924 (16.74%) / 5,847,530 (9.14%) |
| Unattributed forwarded packets / bytes | 64,288 / 58,112,600 |
| Unknown reason `TUPLE_NOT_PRESENT` | 64,082 packets |
| UDP attributed / eligible | 668 / 25,465 (2.62%) |
| BPF snapshots succeeded | 328 / 328 |
| Published active validated mappings | 322 |
| Dropped by client policy | 8,538 packets / 3,521,954 bytes |
| Conntrack procfs fallback | 0 successes / 64,116 failures |
| Refresh-on-miss | Disabled |
| Connected / blocked clients | 2 / 1 |

**Interpretation:** Parser and publication health look good, but BPF flow coverage is low. `TUPLE_NOT_PRESENT` alone does **not** establish that a missed packet was the first packet of its flow. Missing/late offload entries, mismatched tuple keys, direction or network-family handling, and bypassed or non-offloaded traffic remain separate hypotheses.

**Security limitation:** A post-NAT VPN/TUN packet without provable client ownership cannot safely be blocked merely because some hotspot client is blocked. A readable `dumpsys tethering bpf` map is an asynchronous observation source, not a synchronous pre-NAT enforcement hook. Treat attributed packets dropped under policy as *partial enforcement*; do not label the whole blocked client leak-proof.

## 2. Goals and non-goals

### Goals
1. Enable and evaluate **Phase B**: asynchronous, deduplicated BPF snapshot refresh when eligible tuples miss, with backpressure, cooldown, and circuit breaker.
2. Implement **Phase C**: bounded, privacy-preserving per-flow diagnostics to distinguish transient misses from persistent misses, tuple mismatch, missing ownership, IPv6 gaps, and unsupported protocols.
3. Quantify attributed traffic, persistent misses, policy drops, and possible leaks **per client** wherever client ownership is proven.
4. Preserve correct access for an unrestricted second hotspot client while another is blocked.
5. Maintain debug/release isolation and make the feature reversible without touching the stable production build.

### Non-goals
- No promise of 100% blocking or bandwidth control without a reliable pre-forwarding ownership/enforcement point.
- No root, privileged netfilter changes, hidden Android APIs, or assumed conntrack permission.
- No arbitrary attribution based on the currently blocked client, destination address, or last observed MAC.
- No synchronous shell/BPF collection on the packet processing thread.
- No indefinite packet buffering awaiting a snapshot.

## 3. Feature flags and defaults

| Flag | Debug default | Requirements |
|---|---|---|
| `experimentalBpfEnabled` | Existing user setting | Preserve current behavior |
| `refreshOnMissEnabled` | **false until explicitly enabled in debug UI** | Opt-in controlled test |
| `deepTupleDiagnosticsEnabled` | **false until explicitly enabled** | Opt-in; minimal metadata only |
| `refreshOnMissCooldownMs` | `500` | Configurable; enforce sane lower bound |
| `refreshOnMissMinGlobalIntervalMs` | `500` | Avoid collection storms |
| `refreshOnMissMaxInFlight` | `1` | Strict single-flight |
| `refreshOnMissMaxConsecutiveFailures` | `3` | Trip breaker |
| `refreshOnMissBreakerCooldownMs` | `30_000` | Then allow probe/recovery |
| `tupleDiagnosticsMaxTrackedFlows` | `2_048` | Bounded LRU with TTL |
| `tupleDiagnosticsMaxSampleRecords` | `256` | Ring buffer, redact by default |
| `tupleDiagnosticsFlowTtlMs` | `60_000` | Eviction must count |
| `conntrackUnavailableBackoffMs` | `300_000` | Avoid permission-denied call loops |
| `unknownOwnerPacketPolicy` | `ALLOW` | **Must remain ALLOW** for this experiment |

Do not tie a previously stable behavior to a new debug flag. Persist feature flags only in the debug build, scoped to this experimental version if needed. Reset/disable on unexpected exceptions without changing existing policies.

## 4. Phase B: asynchronous refresh-on-miss

### 4.1 Trigger eligibility
Trigger a refresh request only when all apply:
- BPF experimental mode and refresh-on-miss are enabled.
- The packet is eligible and parseable; exclude local control packets and known unsupported protocols.
- The current valid snapshot was consulted and attribution failed with `TUPLE_NOT_PRESENT` (optionally instrument other failure classes without triggering refresh).
- The snapshot is neither currently refreshing nor protected by circuit-breaker/backoff.
- The rate limit permits a refresh; otherwise increment a named suppression counter.

### 4.2 Execution behavior
1. Packet path performs an **O(1)/bounded** lookup against an immutable published snapshot.
2. On an eligible miss, enqueue a **nonblocking signal** for a worker; do not spawn a thread per packet.
3. Coalesce signals while a refresh is in flight, and throttle using a monotonic clock.
4. Refresh via the existing tested `dumpsys tethering bpf` collector/parser on a background worker.
5. Validate entire candidate snapshot: parsing, interface ifindices, ownership, reversed-confirmation, generation/session binding, age bounds, conflicts, and publication completeness. Publish atomically only if valid.
6. After publication, later packets automatically use the new snapshot; do **not** retroactively claim that an earlier forwarded packet was blocked.
7. Optionally compare still-tracked missed flow keys with the new snapshot **for diagnostics only**; record `resolvedAfterRefresh` and latency without double-counting previously forwarded packets as attributed.
8. On failure, retain the last valid snapshot subject to its existing freshness limits and set explicit health/breaker reasons. Never publish partial or mixed-generation maps.

### 4.3 Breaker states
`CLOSED` (normal) → `OPEN` (after threshold of collection/validation failures) → `HALF_OPEN` (one permitted probe after cooldown) → `CLOSED` on successful verified publication, or `OPEN` on failure. The circuit breaker is scoped to refresh-on-miss, not to the normal polling mechanism. A parser failure, permission denial, collector timeout, and generation mismatch require distinct diagnoses.

### 4.4 Mandatory counters
`missRefreshTriggered`, `missRefreshCompleted`, `missRefreshFailed`, `missRefreshCoalesced`, `missRefreshSuppressedCooldown`, `missRefreshSuppressedBreaker`, `missRefreshSuppressedIneligible`, `missRefreshQueueOverflow`, `missRefreshLatencyMs` (histogram), `postRefreshFlowKeysResolved`, `postRefreshFirstSubsequentAttributedPackets`, `postRefreshFirstSubsequentAttributedBytes`, `snapshotPublishRejectedByReason`.

## 5. Phase C: deep tuple and owner diagnostics

### 5.1 Canonical tuple definition
Create one canonical internal tuple representation, shared by BPF map parsing and packet matching, with documented byte order:

```
{ networkSessionGeneration, ipFamily, transportProtocol,
  direction, srcIp, srcPortOrIcmpId, dstIp, dstPortOrIcmpId,
  downstreamIfindex, upstreamIfindex, preNatOrPostNatRole }
```

**Important:** The two sides of a NAT mapping are **not** interchangeable. Build explicit upstream and downstream lookup keys corresponding to the exact kernel BPF map format observed on the test device; do not guess or swap endpoints opportunistically. Define each tuple field's origin (`TUN packet`, `BPF upstream`, `BPF downstream`, `SoftAP callback`) and network byte order in code comments and tests. Record whether direction is known or inferred.

### 5.2 State machine for missed flow keys
Track bounded per-flow state:

- `NEW_MISS`: first observed eligible miss for this canonical flow key.
- `REPEATED_MISS`: the same flow misses again before a new published snapshot.
- `PERSISTENT_AFTER_REFRESH`: missed after at least one newer valid snapshot while the flow is still active.
- `RESOLVED_AFTER_REFRESH`: a newer published snapshot can validate ownership for the previously missed tuple (diagnostic only for historical traffic).
- `KEY_MISMATCH_SUSPECTED`: equivalent flow found under a documented alternative direction/tuple representation; **do not enforce** until match is exact and reverse-confirmed.
- `NOT_OFFLOADED_OR_NOT_OBSERVABLE`: remains absent after multiple validated snapshots; label as hypothesis, not certainty.
- `EXPIRED`/`EVICTED`: tracking lifecycle bookkeeping.

Use `(sessionGeneration, bindingGeneration, tuple)` for lookup identity; on any generation change, clear all tracked state and disallow cross-session ownership reuse. Retain timestamps using a monotonic clock. Bound memory and retention; do not store packet payloads.

### 5.3 Per-reason and per-dimension breakdown
For **each** packet/byte counter, allow breakdown by `IPv4/IPv6`, `TCP/UDP/ICMP`, upload/download, attribution source (`DIRECT_IP`, `BPF_NAT`, `CONNTRACK_PROCFS`), and diagnostic reason (`TUPLE_NOT_PRESENT`, `IP_BINDING_MISSING_OR_CHANGED`, `UNSUPPORTED_PROTOCOL`, `IPV6_NOT_SUPPORTED_BY_BPF_MAP`, snapshot stale/missing, ambiguous ownership). Also track observed BPF map protocol counts, age and eviction by protocol. Specifically investigate UDP and QUIC-capable flows (e.g. UDP/443) without assuming every UDP/443 flow is QUIC.

### 5.4 Client attribution confidence
Emit per-client data **only** for `VERIFIED` ownership (stable SoftAP client binding + correctly directed validated tuple). For unverified traffic report `UNKNOWN_OWNER`, never attribute to the sole blocked client. Record binding changes and randomized MAC reconnects as distinct generations; invalidate cached association on disconnect, reconnect, address reassignment, interface changes, or VPN/tethering restart.

### 5.5 Privacy and safe export
Do not log payloads, DNS queries, hostnames, full external IPs, raw client MACs, or app identifiers by default. Export rotating pseudonymous client IDs and keyed/ephemeral flow hashes; truncate/aggregate remote destination and ports when possible. An explicit developer-only *sensitive trace* option, if ever added, must be consented to, time-limited, local-only, and excluded from normal issue reports. Add counters for redaction and sampling/eviction. All logs must be removable with a clear reset action.

## 6. Multi-client safety invariants (must pass)

1. **No speculative cross-client drop:** `UNKNOWN_OWNER` must never be treated as belonging to any blocked client.
2. For verified client A with `BLOCKED`, apply its drop policy; verified client B with `ALLOWED` must continue passing traffic regardless of A's state.
3. A's drop, throttle or quota state must not propagate to B by shared tuple-cache entries, NAT collisions, snapshot changes, or UI state.
4. Ownership must be reverse-confirmed, conflict-free, generation-matched and current; invalid/ambiguous owner means `UNKNOWN_OWNER` and is counted explicitly.
5. IPv4 and IPv6 must be evaluated independently. Lack of IPv6 coverage must be reported as exposure; never claim IPv6 isolation from IPv4 metrics.
6. VPN reconnect, hotspot restart, upstream interface switch, SoftAP ifindex change, DHCP reassignment, and client MAC randomization must invalidate affected attribution caches.
7. Release/non-debug behavior remains unchanged; toggling diagnostics on/off must not modify client policies.
8. Do not block or delay the packet processing thread on `dumpsys`, filesystem, parser, report export, or worker queue locks.

## 7. Telemetry model and report format

### 7.1 Report headings
1. Build, mode, flags, binding generation and interface identifiers.
2. Coverage overview (eligible, verified attributed, unknown forwarded, blocked, bytes and packets).
3. Miss reasons and breakdown by protocol/family/direction.
4. Phase B: triggers, coalescing, cooldown, breaker state, refresh latency, publication results.
5. Phase C: unique missed flow keys, repeated/persistent/resolved misses, histogram of snapshots survived, key mismatch evidence, LRU/TTL evictions.
6. Multi-client: connected count, policy per pseudonymous client, verified-attribution packet/byte coverage per client, blocked drops and allowed passes; unknown-owner bucket separate.
7. Conntrack fallback health and backoff state.
8. Safety warnings and conditions under which results **cannot** establish leak-free blocking.

### 7.2 Accounting invariants
Within the same window and traffic eligibility domain:

```
eligiblePkts == attributedPkts + unattributedPkts
eligibleBytes == attributedBytes + unattributedBytes
attributedPkts == directIpPkts + bpfNatPkts + conntrackPkts
unattributedPkts == sum(unknownReasonPkts)
```

`policyDropped` must be a subset of packets with *verified ownership* and an applicable policy; its relationship to forwarded/eligible counters must be explicitly documented (avoid double-counting). Counts reset or segment on session generation change; every report declares the window start/end and whether counters are cumulative, instantaneous, or sampled. Keep `snapshot flow counts` distinct from `packet counts`. Display percentage denominators and values rounded consistently.

### 7.3 Example diagnostic record (no identifying data)

```json
{
  "schemaVersion": 2,
  "featureVersion": "0.10.4-debug",
  "sessionGeneration": 4,
  "bindingGeneration": 13,
  "flowHash": "ephemeral:4fd2...",
  "family": "IPv4",
  "protocol": "UDP",
  "direction": "DOWNLOAD",
  "missReason": "TUPLE_NOT_PRESENT",
  "missState": "PERSISTENT_AFTER_REFRESH",
  "snapshotSequenceFirstMiss": 101,
  "snapshotSequenceNow": 104,
  "observedPacketCount": 19,
  "ownerConfidence": "UNKNOWN_OWNER",
  "decision": "ALLOW",
  "enforcementGuarantee": "NONE_FOR_UNKNOWN_OWNER"
}
```

## 8. Reproducible test protocol

### 8.1 Environment/preconditions
- Install `0.10.4-debug` alongside or separate from stable build using the intended debug application ID; verify VPN ownership constraints before running (only one VPN active at a time).
- Android test host with Shizuku permission; log Android/One UI version and security patch level.
- Two **physical** hotspot clients, A and B. Record only redacted client identities.
- Confirm SoftAP interface, upstream interface, their **OS-reported ifindices**, and VPN/TUN routing before each run.
- Start with both allowed; confirm both can access the internet via an independently controlled endpoint. Note whether upstream is Wi-Fi or mobile data.
- Collect a warm-up baseline with `refreshOnMissEnabled=false` and `deepTupleDiagnosticsEnabled=true`, then enable Phase B without restarting clients. Run each scenario a minimum of 3 times.
- Use the same endpoints, traffic duration, client configuration, and counters for A/B comparisons. Use an independent client-side packet/byte measurement and, where possible, a controlled test server for corroboration.

### 8.2 Workloads
- `W1 TCP`: HTTPS requests/downloads from both clients, with cold connections and connection reuse.
- `W2 UDP`: UDP echo/iperf3-style tests using a controlled server; include UDP/443 separately if environment supports it.
- `W3 DNS`: UDP DNS and, if supported, TCP DNS; record that private DNS/DoH/DoT may change behavior.
- `W4 IPv6`: test globally routable IPv6 (if provisioned); distinguish missing IPv6 from unsupported IPv6 attribution.
- `W5 churn`: 50 new short-lived connections per client with repeatable rates and seed, preserving target endpoints.
- `W6 continuity`: one long-lived TCP and UDP flow across several snapshot cycles.
- `W7 topology`: hotspot toggle, VPN toggle, upstream Wi-Fi↔mobile switch, client A disconnect/reconnect, DHCP renewal, and optional randomized MAC reconnect.

### 8.3 Required test matrix

| ID | Scenario | Steps | Expected result |
|---|---|---|---|
| T01 | Both allowed baseline | A+B online; run W1–W3; Phase B off | Both continue passing; counters internally consistent |
| T02 | A blocked, B allowed | Apply `BLOCKED` to A; run W1–W3 from both | Verified A packets dropped; verified B traffic unaffected; UNKNOWN remains counted and may pass |
| T03 | Swap blocked client | A allowed, B blocked; repeat | No stale A policy on B or vice versa |
| T04 | Phase B A/B | Run identical W1–W6 with Phase B off/on | Observe refresh events and compare coverage with equivalent denominators; do not assume improvement |
| T05 | Refresh storm | Trigger many new-flow misses rapidly | Max 1 in-flight; cooldown/coalescing effective; packet thread responsive |
| T06 | Broken collector/parser | Simulate timeout, malformed BPF line, ifindex mismatch | No partial publication; explicit error; breaker and recovery |
| T07 | Session change | Restart VPN/hotspot; reconnect A/B; change upstream | Old tuple ownership invalidated; generation counters advance; no cross-session drops |
| T08 | UDP focus | Run W2/W3/W5; group by ports & direction | UDP misses classified; no incorrect ownership from relaxed keys |
| T09 | IPv6 | Run W4 with A blocked/B allowed | IPv6 unverified exposure is reported; not silently counted as blocked |
| T10 | Conntrack denied | Force or observe procfs permission denial | Backoff occurs and prevents repeated expensive fallback attempts |
| T11 | Long run | 30-minute mixed W1–W6 | No unbounded queues, memory growth, worker starvation, or stale snapshot publication |
| T12 | Debug rollback | Disable B+C then restart service | Baseline behavior restored, with no release settings/policy migration |

### 8.4 Data capture for each run
Capture build/commit, device OS, Shizuku UID/capabilities, upstream type, connected client count, policy assignment, feature flags, warm-up, test start/end timestamps, snapshot sequence, counters before/after, flow miss state transitions, p50/p95/p99 refresh latency, breaker transitions, total CPU/memory overhead, and client-side observed network outcomes. Redact personal IP/MAC before sharing.

## 9. Acceptance criteria (pass/fail)

### Functional requirements
- **AC01:** Phase B can be enabled/disabled independently; off reproduces v0.10.3-debug behavior within equivalent workloads.
- **AC02:** At most one refresh-on-miss collector is running; packet processing never waits on collection.
- **AC03:** All refresh states and rejection reasons are recorded and breaker recovery works automatically after cooldown.
- **AC04:** An invalid candidate snapshot never replaces the latest valid published snapshot.
- **AC05:** Per-flow diagnostics track unique, repeat, persistent, and resolved misses without double-counting packets or leaking across sessions.
- **AC06:** All packet/byte accounting invariants hold per report window (allow no unexplained imbalance).
- **AC07:** Debug report makes `UNKNOWN_OWNER => ALLOW` and **partial enforcement** explicit; it never describes blocked client internet isolation as guaranteed.
- **AC08:** In 3 repeated A/B runs, both allowed client B and newly unblocked A retain connectivity; no evidence of cross-client policy contamination or wrong-owner drop.
- **AC09:** Conntrack permission denials trigger bounded retries/backoff; no per-packet permission-denied attempts.
- **AC10:** Captured diagnostic records are bounded, redacted, and can be cleared.
- **AC11:** VPN/hotspot/upstream transitions invalidate session-bound attribution and do not resurrect stale policy bindings.
- **AC12:** B+C can be disabled and the debug build rolled back without impacting release or persistent client policy data.

### Evaluation metrics (not guaranteed targets)
Measure change relative to controlled baseline; report median and variability over **at least 3 runs**:
- Packet and byte attribution coverage overall, by TCP/UDP, IPv4/IPv6, direction, and client where verified.
- `TUPLE_NOT_PRESENT` packets and **distinct flow keys**, plus fraction resolved after subsequent snapshots.
- Unknown forwarded packets/bytes while a client is blocked; treat as potential exposure, **not proven leak specifically from that client**.
- Correct verified-client policy drop/pass counts and external client-side reachability.
- Additional refresh count and collection overhead, p50/p95/p99 latency, timeout, rejection and breaker rates.

**Promotion rule:** Never promote to normal builds based only on improved aggregate attribution coverage. Require demonstrated per-client correctness, limited overhead, privacy compliance, and a documented residual leak/exposure model.

## 10. Implementation work breakdown

1. **Instrumentation groundwork** — immutable snapshot sequence IDs, generation-safe keys, monotonic timestamps, accounting tests.
2. **Phase B worker** — bounded signal queue, single-flight, cooldown, publication rules, circuit breaker, counters.
3. **Phase C flow tracker** — canonical tuples, keyed hashes, TTL/LRU, miss state machine, protocol/direction breakdown.
4. **Owner confidence boundary** — verified attribution only; multi-client isolation assertions and cache invalidation.
5. **Conntrack backoff** — detect permission error and avoid repeated procfs attempts.
6. **Debug UI/report** — flag controls, telemetry snapshots, privacy-preserving Markdown/JSON export, reset action.
7. **Tests and profiling** — unit tests with saved/redacted BPF fixture formats, deterministic concurrency tests, two-client device runs, overhead profiling.

## 11. Suggested unit / integration assertions

- Canonical TCP/UDP tuple serialization is stable across host/network byte order conversions.
- Reversed BPF entries with mismatched ownership never yield `VERIFIED`.
- Duplicate miss events produce one refresh request per cooldown and count coalesced/suppressed signals.
- Malformed BPF snapshot, stale generation, and mismatched interfaces do not publish.
- Disconnect/reconnect cannot reuse cached flow-to-MAC binding from an old generation.
- Client B remains unaffected when policy for A changes rapidly, including with overlapping remote destination/ports.
- Packet accounting exactly reconciles on packet-by-packet synthetic fixtures.
- Evicted, sampled, and expired flow-tracker entries are counted without accumulating memory indefinitely.
- Collector exception and permission denial never crash the VPN service or cause packet-thread blocking.

## 12. Deliverables

- Debug APK and source changes isolated to `0.10.4-debug`.
- Documented feature flags and rollback instructions.
- Redacted diagnostic report in Markdown plus machine-readable JSON schema/sample.
- Automated parser, concurrency, tuple normalization, policy isolation and accounting tests.
- Test evidence for T01–T12 including 3-run comparisons, release regression status, and outstanding limitations.

## 13. Final architectural warning

Phase B may help with *temporarily absent* map entries; Phase C is required to determine why persistent misses occur. Neither phase turns a post-NAT TUN into a trustworthy pre-NAT per-client firewall. If unknown traffic continues to be forwarded, the project must continue to describe the feature as **PARTIAL_ENFORCEMENT**. Do not hide, reclassify, or suppress unknown traffic to make coverage or blocking metrics look better.
