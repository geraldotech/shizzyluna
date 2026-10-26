# ShizziLua — Hotspot Traffic Control: Findings and Required Fixes

## Status

**Diagnosis and implementation plan — not an implemented fix.**

This document describes problems observed in the ShizziLua source and on-device tests. The project uses Shizuku and Android tethering with a TestNetwork TUN datapath. The intended result is reliable per-client internet blocking and bandwidth limiting when the phone shares either mobile data or an upstream Wi-Fi connection.

Repository: https://github.com/geraldotech/shizzylua

## Reproduction

- Device hosting the hotspot: Samsung Android device with Shizuku enabled.
- Connected client: `S25`, MAC `E2:15:CD:54:E4:9B`, IPv4 `192.168.167.151` in the captured test.
- The Connected Devices page correctly shows **1 connected client**.
- The UI shows **Blocked by administrator** and **Enforced Cap: 1 Mbps**.
- Logs report `TrafficControl: BLOCKING ...` and `1 rule(s) enforced on live traffic`.
- Nevertheless, the connected client continues accessing the internet and its speed is not effectively limited.
- The failure was reproduced with both **Wi-Fi upstream** and **mobile-data upstream**.

Do not assume that these labels or log messages prove packet-level enforcement.

## Confirmed Source-Level Issues

### 1. Configuration is reported as enforcement

In `app/src/main/java/dev/shizzi/HostFirewall.kt`, `enforcedOnConnected` increments when a connected host has an active restriction. It does not check whether the datapath is attached, whether a packet matched the policy, whether packets were dropped or shaped, or whether a kernel command succeeded. Likewise, `TrafficControl: BLOCKING` describes policy intent rather than an observed drop.

**Fix:** Expose separate states such as `CONFIGURED`, `DATAPATH_ACTIVE`, `POLICY_INSTALLED`, `PACKETS_MATCHED`, `PACKETS_DROPPED`, `THROTTLING_OBSERVED`, and `ENFORCEMENT_UNAVAILABLE`. Report actual counters and errors, not a synthetic success count.

### 2. Kernel firewall commands can fail silently

`HostFirewall.execute()` starts a process and waits up to one second without checking the process exit code, completed status, or stderr. Non-root Shizuku normally runs under the shell UID, which does not automatically have `CAP_NET_ADMIN` for `iptables`, `ip6tables`, or policy routing changes.

**Fix:** Collect exit code, stderr, timeout, and command identity; terminate timed-out subprocesses safely. Treat netfilter as an optional, capability-checked enforcement backend. Never mark rules as applied based only on invoking a command.

### 3. Direct-TUN fallback bypasses the userspace policy engine

`SessionResources.startDatapath()` falls back to `Datapath.start(descriptor.fd, mtu)` after a proxy attach/start failure and calls `TunTrafficEngine.stop()`. The internet may remain functional, while the only rootless traffic filtering path is inactive.

**Fix:** Expose fallback status prominently. If per-client enforcement is required, do not silently describe this mode as protected or throttled. Provide a policy-driven choice between refusing unmanaged forwarding (fail closed) and continuing with explicit `ENFORCEMENT_UNAVAILABLE` warnings; never unexpectedly interrupt the user's entire hotspot without an explicit setting.

### 4. IP-to-client matching is unverified at packet level

`TunTrafficEngine.resolvePolicyForIp()` returns no policy for unknown addresses, and `allowAndShapePacket()` then returns `true`. The engine extracts source/destination IPs from TUN packets, but the application has not demonstrated that these addresses still correspond to downstream client IPs after any tethering NAT/translation or that all traffic traverses the proxy. A TUN L3 packet does not itself carry the downstream client's Ethernet MAC.

**Fix:** Record safe, sampled packet metadata in both directions (IP version, source/destination address, length, interface/datapath direction, matched client/policy, and result). Verify how client IPs appear **before and after NAT**, compare against the verified SoftAP/neighbor mappings, and remove stale mappings at disconnect. Never infer identity from unrelated private IPs. Handle IPv6 consistently and test multiple simultaneous clients.

### 5. Traffic shaping needs on-device validation

The current userspace Token Bucket implementation delays or drops packets on the relay threads. Its bandwidth semantics, burst behavior, fairness, and handling of TCP/UDP traffic have not been demonstrated against measured throughput.

**Fix:** Define whether `bandwidthLimitKbps` is per-direction or combined and document units. Test measured upload and download throughput and latency under sustained traffic. Ensure per-client fairness, independent direction limits if required, sensible queues, monotonic counters, and safe rate updates without restarting the hotspot.

## Required Architecture and Runtime Checks

1. **Client discovery:** Obtain current SoftAP clients from the authoritative Wi-Fi/tethering state. Maintain `MAC -> current downstream IPv4/IPv6 addresses` using interface-scoped neighbor information. Keep saved rules for offline MACs without counting them as connected.
2. **Rule association:** On connect, locate an existing rule by normalized MAC, bind it to current verified IPs, and update the active enforcement table. On IP changes, reconnect, or disconnect, invalidate old mappings and rebind safely.
3. **Datapath verification:** Prove that tethered upload and download packets actually traverse `TunTrafficEngine`. Verify this independently for Wi-Fi and cellular upstreams, and detect any Android tethering/offload path that bypasses the engine.
4. **Backend capability:** Record whether the session is using the userspace proxy, direct-TUN fallback, or available kernel netfilter. Differentiate root and Shizuku-shell permissions.
5. **Real enforcement:** On each packet, match the correct client and current policy, drop blocked packets, or apply bandwidth shaping. Persist counters for received, forwarded, matched, dropped, and shaped bytes/packets by client and direction.
6. **Honest UI:** Show `Blocked (verified)` only when enforcement is available and packet-level evidence confirms the policy; otherwise show `Block configured — not enforced` with a diagnostic reason. Use the same principle for bandwidth caps.
7. **No false success:** A successful build or unit test is not proof of network enforcement. Any fallback, mismatch, permission failure, or silent datapath loss must be visible in logs and status.

## Diagnostics to Add

Provide logs resembling the following (illustrative, not claimed current output):

```text
Datapath: mode=USERSPACE_PROXY attached=true upstream=testtun18
Firewall: backend=USERSPACE kernelNetfilterAvailable=false uid=2000
ClientMap: mac=E2:15:CD:54:E4:9B ips=[192.168.167.151] interface=<softap-iface>
Traffic: direction=UPLOAD src=<observed> dst=<observed> matchedMac=<mac-or-none> decision=DROP
Traffic: direction=DOWNLOAD src=<observed> dst=<observed> matchedMac=<mac-or-none> decision=RATE_LIMIT
Counters: mac=<mac> seenPackets=N matchedPackets=N droppedPackets=N shapedBytes=N
```

Avoid logging sensitive payload contents, and keep verbose per-packet diagnostics opt-in and bounded.

## Acceptance Tests (Physical Devices Required)

Run each relevant case separately with **Wi-Fi upstream** and **mobile-data upstream**:

| Test | Expected result |
| --- | --- |
| No clients | UI shows zero active clients. |
| Single client | Exactly one verified client and correct MAC/IP mapping. |
| Manual block | Existing and new internet connections from that client stop; verified drop counters increase. |
| Unblock | Connectivity returns without restarting the hotspot, when supported. |
| 500 Kbps cap | Sustained measured throughput approaches the configured cap within documented tolerance; counters show shaping. |
| Change cap while active | Traffic responds promptly to the new rate. |
| Reconnect / IP reassignment | Saved MAC rule follows the verified client and stale IP mapping is removed. |
| Two clients | Blocking or shaping one client does not unintentionally affect the other. |
| IPv4 and IPv6 | Policies cannot be bypassed by switching address family. |
| Proxy attach failure | App visibly reports enforcement unavailable; no false `enforced` status. |
| Kernel permission failure | Explicit error/status, with no assertion that iptables rules succeeded. |
| Hotspot/VPN upstream changes | Datapath and policy state revalidated; no silent bypass. |

Use a second device to perform actual web requests, long-running transfers, and repeated speed tests. Record the app's datapath mode and packet counters together with observed client behavior.

## Recommended Implementation Order

1. Add reliable datapath/backend diagnostics and packet counters.
2. Confirm or repair the userspace proxy's traffic interception and eliminate misleading fallback behavior.
3. Fix client IP/MAC matching at the actual observed packet stage, including NAT and IPv6 cases.
4. Make blocking work and prove packet drops on a real device.
5. Implement/calibrate download and upload bandwidth enforcement against measured traffic.
6. Update UI statuses, error handling, reconnection behavior, and regression tests.

## Definition of Done

The issue is resolved only when a physically connected client can be blocked and rate-limited in real traffic under **both** Wi-Fi and mobile-data upstreams, without unexpected effects on other clients. Logs and UI must accurately distinguish intended policy from confirmed datapath enforcement, and fallback or permission failures must not be reported as success.
