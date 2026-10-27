# Shizzi: Experimental BPF NAT Flow Attribution and Per-Client Enforcement

## Task for the implementation agent

Implement a focused, feature-gated integration in the existing Shizzi application. Use Android tethering BPF map dumps, read through the Shizuku UserService, to associate translated TUN packets with their original hotspot clients. Reuse the application's existing per-client blocking and bandwidth policies.

Deliver working code, meaningful automated tests, and an installable signed test APK if the environment supports building it. This is an implementation task, not another standalone diagnostics application or a broad rewrite.

The user wants to keep a selected client associated with Wi-Fi while pausing its internet or limiting its bandwidth, without disrupting other clients, while Shizzi shares a VPN connection.

**Experimental scope:** the collected evidence establishes readable NAT mappings for two clients. It does not establish complete enforcement, first-packet coverage, or a reliable bandwidth limit. Preserve that distinction throughout code, UI, tests, and delivery notes.

## 1. Establish the actual working baseline

Repositories discussed by the user:

- Original: https://github.com/geraldotech/shizzylua
- Later development: https://github.com/geraldotech/shizzyluna

Work in the checkout supplied for this task. Inspect its remote, branch, current commit, local changes, and applicable AGENTS.md before editing. Do not overwrite newer work with either historical repository. Record the actual base commit in the delivery report.

Historical references, not assumptions about the current checkout:

- Original snapshot: `0cc882c7d7e7aa55e4b3bcf970be2f3912e03c45`.
- Later snapshot: `0b0d7595ffc5605b3582bd639c3f7ff14cbd10e2`.
- Device diagnostics subsequently reported lua5/code10 and lua6/code11. Suffixes such as `+lua-6` are diagnostic labels, not necessarily resolvable Git commits.

Locate the current equivalents of `TunTrafficEngine`, `HostFirewall`, `ClientManager`, `TetherSession`, the Shizuku service/client/AIDL contract, and connected-device diagnostics. Historical relevant methods include `resolveClientMacForPacket()` and `evaluateAndShape()`; do not assume their signatures or line numbers are unchanged.

Inspect the actual packet path before integrating. Determine where TUN packets are read, where policies run in each direction, and whether existing cached decisions could bypass a new block. Preserve existing VPN reconnect behavior and unrelated features.

## 2. Device evidence and what it proves

Device: Samsung Galaxy S23 Ultra, `SM-S918B`, Android 14/API 34, firmware `UP1A.231005.007.S918BXXU7CXK4`. Shizuku runs as UID 2000, SELinux `u:r:shell:s0`, without effective Linux capabilities.

Previously tested limitations on this device:

- iptables/ip6tables access and writes were denied.
- `ip rule show` was readable, but rule installation was denied.
- `/proc/net/nf_conntrack` and `/proc/self/net/nf_conntrack` returned EACCES.
- Legacy ip_conntrack paths were absent.
- These results do not imply that every privileged service-mediated read is unavailable.

The standalone Shizzi Samsung PoC 0.1.0 subsequently obtained successful, untruncated results for:

```text
dumpsys tethering bpf
dumpsys tethering bpfRawMap --upstream4
ip neigh show dev swlan0
```

These commands ran in its Shizuku UserService as UID 2000.

### Two-client capture

Evidence file: `22shizzi-poc-1793125251327.json`, timestamp `1793125251327`, scenario selected as `VPN + Shizzi`.

| Client MAC | Original IPv4 | TCP upstream entries | UDP upstream entries | Total |
| --- | --- | ---: | ---: | ---: |
| `e2:15:cd:54:e4:9b` | `192.168.167.151` | 82 | 6 | 88 |
| `f2:ff:8b:3d:b2:a6` | `192.168.167.17` | 10 | 0 | 10 |

There were 98 IPv4 upstream entries, 98 matching downstream entries, and 98 raw upstream-map rows. Every upstream tuple had a matching reverse entry with the expected client MAC. All six UDP entries targeted port 443; this is compatible with QUIC but does not identify the application protocol by itself.

The capture used downstream `swlan0`/ifindex 215 and upstream `testtun46`/ifindex 214, translated IPv4 `192.0.2.2`. IPv6 downstream address-to-MAC mappings existed for both clients. The preceding one-client capture used different interface indices and `testtun45`; identifiers must be discovered per session.

All captured source ports happened to be preserved by NAT. Port rewriting and collisions still require tests. A map entry is not proof that a connection is currently active, that all traffic is represented, or that a policy was enforced.

The report's manual connectivity outcomes were all `Not tested`; events were empty. Do not mark physical blocking or shaping tests as passed based on this capture.

### Actual text examples

```text
IPv4 Upstream: proto [inDstMac] iif(iface) src -> nat -> dst [outDstMac] pmtu age
  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:51006 -> 214(testtun46) 192.0.2.2:51006 -> 108.158.147.26:443 [00:00:00:00:00:00] 1500 230026ms
  tcp [82:2d:00:30:5f:2d] 215(215) 192.168.167.17:51842 -> 214(testtun46) 192.0.2.2:51842 -> 104.21.81.128:443 [00:00:00:00:00:00] 1500 75499ms
  udp [82:2d:00:30:5f:2d] 215(215) 192.168.167.151:38223 -> 214(testtun46) 192.0.2.2:38223 -> 187.32.103.226:443 [00:00:00:00:00:00] 1500 184962ms

IPv4 Downstream: proto [inDstMac] iif(iface) src -> nat -> dst [outDstMac] pmtu age
  tcp [00:00:00:00:00:00] 214(testtun46) 108.158.147.26:443 -> 215(215) 192.0.2.2:51006 -> 192.168.167.151:51006 [e2:15:cd:54:e4:9b] 1500 230033ms
  tcp [00:00:00:00:00:00] 214(testtun46) 104.21.81.128:443 -> 215(215) 192.0.2.2:51842 -> 192.168.167.17:51842 [f2:ff:8b:3d:b2:a6] 1500 75545ms
```

**Parsing trap:** upstream `inDstMac` is the hotspot interface's MAC, shared by both clients. It is not the client's source MAC. Resolve the original source IP through the current downstream binding, and cross-check the matching downstream `outDstMac` when present.

The named capture files may be supplied separately. If absent, use these excerpts as fixtures and clearly state that full-capture replay was unavailable. Never fabricate the remaining rows.

## 3. Architecture and implementation boundaries

Use small components with testable responsibilities; adapt names to the codebase:

1. `BpfMapReader`: bounded privileged command execution and collection status.
2. `BpfDumpParser`: pure parsing into typed entries, with explicit rejection reasons.
3. `NatFlowAttributor`: session-scoped, immutable mapping snapshots and lookups.
4. Existing traffic engine: lookup, policy decision, counters, and enforcement.

Start with the text dump whose format was observed on the device. Tolerate whitespace and numeric interface labels such as `215(215)`, while rejecting structurally invalid entries. Separate IPv4 upstream, IPv4 downstream, and IPv6 sections explicitly.

The raw map is an optional optimization or cross-check, not a prerequisite. Do not guess binary layouts, byte order, or offsets. If implementing raw decoding, verify against matching Android source structures, validate sizes, test byte order and changed ports, and compare decoded entries against text fixtures. Unsupported layouts must report unsupported instead of producing plausible mappings.

Do not add root commands, write BPF maps, change global offload settings, install netfilter rules, or manipulate global routes as part of this feature. Reading through dumpsys does not grant direct map-write permission.

## 4. Collection must stay off the packet path

- Execute dumpsys only in the Shizuku UserService with its intended shell identity. Clear/restore Binder calling identity where needed.
- Use a dedicated worker with at most one collection in flight. Packet forwarding threads must never launch a process, wait for dumpsys, or parse a large dump.
- Read stdout and stderr concurrently, impose a real execution deadline and byte limits, and terminate timed-out processes. Record exit code, duration, truncation, read failures, and parse failures separately.
- Publish a new immutable snapshot atomically only after validation. A failed, truncated, or partially parsed dump must not become a silently trusted complete snapshot.
- Keep last-known data only under an explicit short freshness limit and unchanged session/bindings; expose its stale state. Never retain attribution indefinitely after reader failure.
- Use monotonic time for age, expiry, and scheduling. The dump's `age` field must not be assumed to mean connection creation time or remaining validity.
- Make collection interval configurable for development. Start conservatively, for example around one second, and measure command cost and attribution delay before reducing it. The dump's `Polling interval: 5000 ms` describes the tethering component, not a required interval for this reader.
- Stop collection with the session; avoid busy retries after permission or service failures. Keep retry/backoff observable.
- Bound map/cache memory. If a limit is reached, report incomplete coverage rather than silently suggesting full enforcement.

## 5. Match complete translated flows

For IPv4 TCP/UDP, use at least this effective lookup identity:

```text
session/network generation
active downstream and upstream interface identities
address family + transport protocol
translated source IP + translated source port
remote destination IP + remote destination port
```

An entry also stores original client IP/port, verified MAC/binding generation, collection time, source, and freshness/conflict information.

For upload, match the packet's translated source and remote destination. For download, reverse the remote/translated endpoints before lookup. Ports may change during NAT: preserve both original and translated ports. Never index by translated IP alone, port alone, destination alone, or source-port equality assumptions.

Cross-check entries with the active downstream client inventory and interface generation. Neighbor tables contain stale entries: association evidence and current IP ownership must be considered. Where available, use the dump's `Client Information` and reverse-map MAC as additional evidence. Contradictory ownership is ambiguous, not a reason to pick the first match.

Treat interface indices as session-bound; they can be reused. Reset/invalidate on hotspot restart, VPN/upstream replacement, binding reassignment, client removal, and service restart. In-flight dumps from an old generation must not repopulate a new session. Do not hardcode `testtun46`, `192.0.2.2`, or `swlan0` as universal values.

An identical translated tuple can be reused for a later connection. A TTL alone does not prove ownership. Handle observed removals/conflicts and new TCP SYNs conservatively, and document the remaining reuse ambiguity for UDP and between collection snapshots. Add tests for it.

Preserve direct, verified IPv6 attribution where the original address is visible. A client can have several temporary IPv6 addresses. Do not infer working IPv6 internet from the existence of an address or forwarding rule alone. Do not classify link-local multicast control traffic as ordinary unassigned internet traffic.

Non-initial fragments, ICMP errors, unsupported transports, and malformed packets need explicit handling. Do not read imaginary transport ports from them. Only attribute them through a validated implementation; otherwise mark unsupported/unattributed and report the coverage gap.

## 6. The first-packet problem must remain explicit

BPF offload entries may appear only after a flow has progressed. Inspect the relevant Android tethering implementation and verify timing on this device. A readable established-flow map is not a synchronous pre-NAT classifier.

Do not claim that polling faster guarantees zero leakage. Do not hold every unknown flow waiting indefinitely for a map entry: withholding initial packets can prevent the flow from reaching the state needed to create that entry.

For the initial experimental release:

- Preserve the application's existing treatment of unknown traffic, but explicitly label the feature as partial/experimental whenever unknown internet traffic is allowed while a restrictive policy is active.
- Count unknown packets/bytes and how many were forwarded. Do not assign them to the blocked client merely because another client is allowed.
- Do not globally drop unknown traffic to make client A appear blocked while breaking client B.
- Never restore the historical `singleActiveClientMac` shortcut. Client count is not packet ownership, and it must not seed durable flow mappings.
- Do not add a strict zero-leak guarantee unless independently demonstrated for all supported traffic paths. If this architecture cannot meet that requirement, state it clearly and keep the feature experimental.

Separate the milestone “selective handling of mapped flows” from “complete internet block including new flows.” The first can pass while the second fails.

## 7. Reuse blocking and shaping correctly

Once a packet has a valid owner, evaluate the current policy for that MAC. Do not cache an ALLOW decision indefinitely with a flow mapping. Changing a policy must affect existing identified flows as well as newly identified ones, in both directions.

Maintain separate counters for policy-block drops, shaping drops/delays, directly attributed packets, BPF-attributed packets, unknown forwarded packets, ambiguous/stale lookups, and local control traffic. Tie enforcement counters to the current policy version and session; accumulated historical drops must not prove a new block.

Inspect the bandwidth limiter before reusing it. Historical code slept on a shared forwarding thread, which could throttle unrelated clients. Per-client shaping must not stall client B while delaying A. Use bounded per-client scheduling/queues or an explicitly measured nonblocking mechanism consistent with the existing architecture. Define bandwidth units, burst allowance, queue bounds, and overload behavior.

If isolated shaping cannot be completed and tested in this change, deliver mapping/blocking experiments first and clearly keep per-client bandwidth unverified or unavailable. Do not present a saved limit, data quota, or a few dropped packets as proof of a rate limit.

On policy change, cancel or re-evaluate queued packets so they cannot escape using an old policy. Report treatment of active connections and queued traffic.

## 8. UI, diagnostics, and feature flag

Add an explicit experimental opt-in, disabled by default for existing installations. Keep UI changes limited to controls and evidence needed to test this feature.

Distinguish requested policy from observed enforcement. Suggested states:

- `DISABLED`
- `COLLECTING`
- `MAPPINGS_AVAILABLE`
- `PARTIAL_ENFORCEMENT`
- `STALE_OR_UNAVAILABLE`

The details should expose collection status, map age, current generation/interfaces, entries per client and protocol, matched/unknown/conflicting traffic, policy version, and drop/shape deltas. State “block requested” separately from any evidence that mapped packets were dropped. Mapping availability is never itself `BLOCKED_VERIFIED`.

Export a bounded report containing collection metadata, parser version, mapping counts, policy changes, traffic deltas, and separately labeled manual observations. Record unknown traffic as unknown, not automatically as a leak from A. A few packets from B do not prove B retained internet connectivity.

Avoid payload capture. Full IP/MAC/remote endpoint dumps contain network metadata; make detailed export explicit and do not send reports anywhere automatically.

Bump APK version and relevant UserService contract/build identification consistently with the project. Ensure an update cannot silently continue running an old Shizuku process; verify/rebind using the actual current service mechanism.

## 9. Samsung API work is deferred

Both captures obtained the `sem_wifi` Binder and found the pause/data-limit/time-limit method signatures. `getWifiApClientDetails()` returned null, and no pause operation was established by these reports.

The standalone PoC converted the MAC to uppercase before querying. Case sensitivity is one hypothesis, not a confirmed root cause. Do not make Samsung API success a dependency of BPF attribution or call vendor setters without verified client identity and recoverable original state.

Do not conflate Samsung mobile-data quota APIs with bandwidth-rate limiting. Do not guess Binder transaction codes. Keep vendor API investigation separate from this integration.

## 10. Required automated verification

Use pure parser/attribution tests and the existing engine test facilities where possible. Cover behavior rather than just mirroring implementation:

1. Parse the supplied two-client excerpts, TCP and UDP, numeric interface labels, and distinct MAC owners.
2. If the complete capture is supplied, reproduce 98 upstream entries: A has 82 TCP + 6 UDP; B has 10 TCP. Verify all 98 reverse mappings. Keep sensitive full captures out of public commits unless explicitly authorized; use sanitized fixtures preserving relationships.
3. Two clients sharing a translated IP; source-port rewriting; equal ports with different destinations; TCP and UDP with identical numeric endpoints; ambiguous duplicate keys.
4. Correct download reverse lookup and no use of upstream `inDstMac` as client identity.
5. Truncated/malformed/unsupported output, permission denial, timeout, valid empty dump, and service loss are distinguishable.
6. Session change during collection, interface-index reuse, expired data, client IP reassignment, tuple reuse, and rejected late results from old generations.
7. Policy changes affect already mapped flows; old policy counters cannot prove current enforcement.
8. Empty cache and new flows stay unknown until evidence appears; tests never invent attribution to satisfy a block.
9. Local IPv6 control traffic, multiple IPv6 addresses, unsupported fragments/transports.
10. A's shaping does not block B's forwarding; queued packets honor policy changes, if shaping is included.

Run the relevant project checks and build. Record exact results and failures. Do not claim Samsung device validation from JVM tests, a successful compilation, or an emulator alone.

## 11. Physical validation matrix

Use two real clients, mobile data disabled, with known MACs and simultaneous traffic. Keep Wi-Fi association and local gateway access under observation. Measure results at both clients; server-side receipts or controlled transfers can help distinguish real completion from cached content.

| Scenario | Evidence required |
| --- | --- |
| Both allowed | Both reach the internet; baseline throughput and attribution coverage recorded |
| A blocked during existing transfers | A's identified traffic stops within a measured interval; B remains usable; A stays associated |
| A opens new connections while blocked | Measure initial/unidentified traffic and actual application success; do not prelabel this a pass |
| A unblocked | Traffic resumes without hotspot restart |
| Roles reversed | B affected, A remains usable |
| A limited, B unrestricted | Measured sustained rate and bursts for A; independent throughput/latency for B |
| IPv4 TCP and UDP/QUIC; IPv6 | Separate outcomes, including unsupported/unattributed paths |
| Empty cache / reader failure | Honest degraded status, no stale cross-client attribution or forwarding-thread stalls |
| Client reconnects or changes IP | Old ownership invalidated; no policy transferred to another client |
| VPN/upstream replacement | Old generation invalidated; mappings recollected; existing reconnect behavior preserved |
| One client, then second joins | No single-client shortcut or attribution migration |
| Port collision/reuse | Controlled test or synthetic automated evidence; distinguish what was physically verified |

Record collection latency, mapping-appearance delay when measurable, matched/unknown packet and byte deltas, and client-observed results. An unknown packet is a coverage gap; it is a confirmed blocked-client leak only with independent attribution or controlled endpoint evidence.

## 12. Acceptance and delivery

Deliver:

- Focused source changes and a summary of the actual integration points.
- Automated test results, build results, and remaining failures.
- A signed test APK, version/build identity, base commit, SHA-256, signing/update compatibility, and installation instructions. If building is blocked, describe the exact blocker without claiming an APK exists.
- A short operator guide to enable the experiment, test A/B, export results, disable the feature, and restore normal operation.
- A clear list of physically untested scenarios and known coverage limits.

Acceptance for this iteration is: correct two-client flow attribution, selective enforcement on valid mapped flows, observable unknown traffic, lifecycle correctness, and no demonstrated cross-client disruption. Full firewall and bandwidth guarantees require the corresponding physical evidence.

Do not publish a release or push unrelated changes. Do not mark the feature production-ready merely because the map parser works. Finish the feasible implementation and build; report any fundamental first-packet limitation instead of hiding it behind success counters.
