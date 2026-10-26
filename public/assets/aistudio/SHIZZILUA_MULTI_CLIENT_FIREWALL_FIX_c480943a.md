# ShizziLua — Fix Per-Client Firewall Enforcement With Multiple Connected Devices

**Status:** Bug report and implementation requirements. This document does not claim that the fix has been implemented or validated.

Repository: https://github.com/geraldotech/shizzylua

**Source revision inspected:** `0cc882c` (`control per host`, 2026-10-26 20:05:58 -0300). Recheck the commit before implementation if the branch moves.

## Critical Bug

Per-client internet blocking reportedly works while exactly **one** device is connected to the hotspot. As soon as a **second** client connects, the blocked client can access the internet again. The problem must be fixed in the packet-processing and client-identity pipeline, not by changing UI labels.

In the supplied screenshot, the hotspot reports two connected clients and `Datapath: USERSPACE_PROXY / Backend: USERSPACE`:

| Client | MAC | IPv4 | Intended policy | Displayed packet counters |
| --- | --- | --- | --- | --- |
| Host-D0D3 | `00:A5:54:56:D0:D3` | `192.168.167.242` | Allowed | 3,823 seen; 358 matched; 358 dropped |
| Host-E49B | `E2:15:CD:54:E4:9B` | `192.168.167.151` | **Blocked** | 7,896 seen; 1,082 matched; 1,082 dropped |

The UI says `Blocked (verified • 1082 pkts dropped)`, yet the user reports that **both devices still have internet access**. The unblocked device also shows dropped packets; investigate whether these drops are caused by firewall policy, stale/cumulative counters, misattribution, or unrelated traffic handling. Screenshot values are not proof of why packets were dropped. Counters may reflect prior activity and must be assessed as deltas during controlled tests.

## Source-Verified Multi-Client Failure Mechanism

The current revision **still contains the one-client shortcut and the multi-client attribution gap**. In `app/src/main/java/dev/shizzi/TunTrafficEngine.kt`:

1. `updatePolicies()` sets `singleActiveClientMac` only when `currentConnectedMacs.size == 1` (approximately lines 420–424).
2. `resolveClientMacForPacket()` accepts the single MAC for post-NAT TUN packets when only one client is connected (approximately lines 663–684).
3. When there are multiple clients, it instead calls `maybeResolveConntrackFlows()` and checks `flowToMacCache` (approximately lines 686–693).
4. `maybeResolveConntrackFlows()` only attempts to read `/proc/net/nf_conntrack` or `/proc/net/ip_conntrack`; it returns without a mapping if those files are absent/inaccessible (approximately lines 922–944). **Shizuku shell access to these nodes is not established**. Diagnose file existence/readability and actual parsed flow counts on the phone.
5. If no client is resolved, `evaluateAndShape()` increments `unmatchedPackets` and returns `PacketDecision.ALLOW` (approximately lines 740–745). **This is the key fail-open path.**

Consequently, a NATed packet may be attributed to the only client when one is connected, but become unattributed and pass through when a second connects. This is a source-supported **likely root cause**, not yet proven by on-device packet traces.

The implementation also adds conntrack flow matching, IPv6 heuristics, new counters, and backend-state logging. Those improvements do not by themselves prove end-to-end enforcement with multiple clients.

**Important additional finding:** in `updatePolicies()` around lines 393–405, the old IP set is pruned only when `ipToMac[oldIp]` already names a *different* MAC. A stale address still owned by the same MAC may survive even when it is absent from the latest verified IP list. Reconcile this with address reassignment and flow-cache invalidation.

**Important UI finding:** `HostFirewall.computeClientEnforcementState()` calls a block `PACKETS_DROPPED` whenever `counters.droppedPackets > 0` (approximately lines 136–143). This uses a lifetime/cumulative threshold, not a fresh drop delta or proof that every relevant packet is intercepted. The label `Blocked (verified)` should not imply total internet denial based on that counter alone.

Also test incorrect packet-direction selection, NAT rewriting, IPv6 paths, stale IP/MAC mappings, and a datapath path that is not fully intercepted despite a `USERSPACE_PROXY` UI label.

## Identity and Enforcement Model

**Store and configure policy by normalized MAC address. Enforce it on the actual observed traffic using verified client-to-packet identity.**

- **MAC** is the persistent identity used to look up the saved client policy. MAC addresses can be randomized by client devices, so retain aliases and handle a changed MAC as a new identity unless explicitly re-associated.
- **IPv4/IPv6** are the current addresses used for matching L3 packets when they remain visible at the enforcement point.
- The **MAC-to-current-IP mapping** must come from verified SoftAP clients and downstream-interface-scoped neighbor/address observations. Bind every known IPv4 and IPv6 address, and expire old bindings on disconnect, reassignment, or lease change.
- A TUN interface carries IP packets rather than Wi-Fi Ethernet frames; do not assume a packet contains the client's MAC.
- If NAT has already translated a client's source/destination address at the interception point, identify a reliable **pre-NAT hook or connection translation mapping**. Do not use one global client or assume a private IP is enough to determine identity.
- If a packet cannot be attributed, record it as `UNATTRIBUTED`; do not falsely count it as belonging to a blocked client or claim the block succeeded.

Example policy mapping:

```text
E2:15:CD:54:E4:9B -> BLOCKED  -> IPv4 192.168.167.151; verified IPv6 addresses
00:A5:54:56:D0:D3 -> ALLOWED -> IPv4 192.168.167.242; verified IPv6 addresses
```

Changing the number of connected clients must **never change the effective rule of an existing client**.

## Required Code Changes

### 1. Fix `TunTrafficEngine.kt`

1. Audit `singleActiveClientMac`, `resolvePolicyForIp()`, `allowAndShapePacket()`, `ipToMac`, and `macToIps` against the latest code.
   In revision `0cc882c`, the relevant current methods are `resolveClientMacForPacket()` and `evaluateAndShape()`; prioritize these instead of relying on old method names.
2. Replace single-client heuristics with deterministic multi-client mapping; support any number of clients.
3. Confirm the packet's real source and destination in **both** TUN directions. Never infer client identity from the first non-TUN IP without proving it is the downstream client.
4. Determine whether the TUN sees a pre-NAT client address. If it does not, implement an appropriate mapping/inspection point instead of guessing.
5. Handle IPv4, IPv6, reconnects, DHCP reassignment, MAC randomization, and simultaneous upload/download.
6. Remove stale entries and stale policy-to-IP associations when clients leave or addresses change. Avoid one client's mapping or counters leaking into another's.
7. Make counters per session, client, direction, and **policy decision**: packets seen, attributed, matched to policy, explicitly dropped by block, dropped by shaping, forwarded, and unclassified.
8. Ensure policy updates are atomic or otherwise safe while packet relay threads are running.
9. Remove dependence on `/proc/net/nf_conntrack` availability for the only reliable multi-client path. If using conntrack, validate capability, parsing, flow direction, NAT tuple matching, and IPv4/IPv6 behavior. Consider collecting client identity at an earlier/pre-NAT point or an explicit per-flow mapping at the point where the original downstream source is still known.
10. Decide and document the unmatched-packet security policy: for a protected/blocked client, silent `ALLOW` on failed attribution is a policy bypass. Avoid globally dropping unknown traffic in a way that disconnects permitted clients; produce an explicit degraded/unavailable state until a safe selective enforcement mechanism is established.

### 2. Fix `DownstreamInspector.kt` and policy synchronization

1. Use live connected SoftAP MACs as the authoritative active-client set.
2. Associate addresses only when supported by downstream-specific evidence; do not import stale upstream neighbor records.
3. Reconcile mappings whenever clients connect, disconnect, or change address, not only when the user opens the screen.
4. Apply saved MAC policies to current verified addresses immediately and without restarting the hotspot.

### 3. Fix `HostFirewall.kt` and enforcement status

1. Distinguish policy configuration from real packet enforcement.
2. `Blocked (verified)` must require actual, recent evidence of dropping traffic **attributed to that client**; a cumulative positive counter from an earlier session is insufficient.
3. Do not call a rule `enforced` merely because a policy object was inserted or because a process attempted to run `iptables`.
4. Report actual engine state, fallback state, matching and drop deltas, and errors.
5. Keep kernel netfilter operations capability-checked and report process exit codes; Shizuku shell privileges must not be treated as root.

### 4. Prevent policy bypasses

1. Confirm that all tethered upload/download traffic reaches the actual enforcement point with Wi-Fi and mobile-data upstreams.
2. Check tethering offload, NAT, VPN changes, IPv6, and direct-TUN fallback for uncontrolled traffic paths.
3. If enforcement becomes unavailable, report it explicitly and follow a documented user-selected safe behavior; never silently display a green or red success badge without protection.
4. Preserve internet access for an allowed client while blocking another. Do not globally block the TUN or shared upstream as a shortcut.

## Diagnostic Logs Required

Add bounded, opt-in metadata logging (never payload contents), for example:

```text
Clients: active=2 apInterface=<iface>
Mapping: mac=E2:15:CD:54:E4:9B ips=[192.168.167.151] source=softap+neighbor
Mapping: mac=00:A5:54:56:D0:D3 ips=[192.168.167.242] source=softap+neighbor
Datapath: mode=USERSPACE_PROXY attached=true direction=UPLOAD
Packet: src=<actual> dst=<actual> attributedMac=<mac|none> policy=<BLOCK|ALLOW|NONE> decision=<DROP|FORWARD>
CounterDelta: mac=<mac> interval=10s seen=N attributed=N blockedDrops=N shapeDrops=N forwarded=N
UnattributedTraffic: packets=N sampleSrc=<ip> sampleDst=<ip>
```

Counters displayed in the UI must be clear about their time scope (current session, since connection, or lifetime) and must not be treated as proof that **all** traffic is blocked. Diagnose unexpected drops on allowed clients separately.

## Mandatory Device Tests

Perform actual browsing and transfer tests using **at least two physical clients**. Repeat with **mobile-data upstream** and **Wi-Fi upstream** wherever supported.

1. Connect Client A alone; block A; verify fresh connections fail and blocked-drop delta increases.
2. Keep A blocked and connect Client B; **A must remain blocked** while **B can browse normally**.
3. Disconnect B; A must remain blocked without depending on a single-client fallback.
4. Unblock A; A can browse again without hotspot restart.
5. Block B while A is allowed; only B loses internet.
6. Block A and B; both lose internet and attribution remains distinct.
7. Add a third device; existing policies remain unchanged.
8. Assign/reassign IPv4 addresses; saved MAC policies follow verified current addresses, not stale addresses.
9. Test IPv6-only or dual-stack destinations, DNS, TCP, UDP/QUIC, and pre-existing sessions to rule out policy bypass.
10. Change a per-device bandwidth cap during active transfers; verify only that client's upload/download rates are affected.
11. Restart the VPN/hotspot or reconnect devices; policy restoration and counters remain correct.
12. Deliberately trigger a datapath attach failure; UI must show `ENFORCEMENT_UNAVAILABLE`, not `Blocked (verified)`.

**Pass criteria:** A blocked client has no working internet connectivity while allowed clients continue to work. The result must remain correct for zero, one, two, and more active clients. Packet attribution and drop counters must match the actual client and behavior. Do not claim completion from unit tests or successful APK compilation alone.

## Developer Deliverables

- Explain the confirmed root cause with specific source references.
- Inspect and report the actual runtime values of `activeConnectedMacs`, `singleActiveClientMac`, `flowToMacCache.size`, `unmatchedPackets`, and readable conntrack paths before and after the second client connects.
- Implement the real traffic-path fix (not just a UI or counter patch).
- Add regression tests for multi-client identity, connection order, stale mappings, and IPv4/IPv6.
- Provide Android on-device validation logs and before/after behavior, or explicitly state which physical tests remain unverified.
- List modified files, risks, and any unsupported Android configurations.
