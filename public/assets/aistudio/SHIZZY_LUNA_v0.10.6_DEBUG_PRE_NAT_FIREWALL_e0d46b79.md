# Shizzy Luna v0.10.6-debug — Exclusive Blocking Mode & Pre-NAT Firewall Feasibility

**Status:** Implementation specification / experimental only  
**Target package:** `dev.shizzyluna.proxy.debug` (verify actual build configuration)  
**Goal:** Determine whether the existing non-root Shizuku (ADB shell, UID 2000) environment can safely enforce **per-hotspot-client** blocking before NAT, without affecting any other connected client. Do not claim full enforcement unless an independently observed two-client test proves it.

## 1. Background and evidence

The v0.10.5-debug `EXPERIMENTAL_ENFORCEMENT` report shows verified-owner drops and cache-policy corrections, but `UNKNOWN_OWNER => ALLOW` still forwards unmatched traffic. In that run: 2,539 verified drops, 125,262 unattributed packets (110,572,501 bytes), and 116,575 unknown-owner packets after block. Those unknown-owner counters are **global**, not proof that all belong to the blocked client. WhatsApp/Telegram messages reportedly continued to deliver intermittently after blocking, while browsers stopped loading. Prior rootless diagnostics found shell UID 2000, no `CAP_NET_ADMIN`, and rejected netfilter writes. Thus a pre-NAT backend is a **capability-gated hypothesis**, not a promised workaround.

## 2. Non-negotiable constraints

1. **Exactly one packet-enforcement engine** may be active at a time. Use `BPF_NAT_VPN` (existing partial enforcement) or `PRE_NAT_FIREWALL` (experimental). BPF read-only telemetry may run while Pre-NAT is selected, but its drop path must be disabled.
2. **No root, no Magisk, no vendor privilege assumptions, no silent privilege escalation.** Shizuku ADB-shell permission does not imply `CAP_NET_ADMIN` or permission to mutate tethering BPF/netfilter state.
3. **Fail closed on activation status, not globally on traffic:** if Pre-NAT cannot be verified, never label it active or claim successful block. Do not insert broad DROP rules on unknown traffic; preserve the existing operating state and provide an explicit error.
4. **Never conflate command availability with capability.** `iptables --version`, `nft --version`, readable `dumpsys` output, or readable maps are not evidence that a rule can be installed and take effect.
5. **Protect other clients:** no unscoped FORWARD DROP, default-policy changes, chain flushes, routing-table resets, tethering restart, or unverified IPv6 blanket rules.
6. **Explicit experimental opt-in** and **user-approved scoped test** are required before mutating packet rules. No privilege or rule probing by mutation during routine app startup.
7. Do not call the new method “100% blocking” unless tests support that claim across configured IPv4/IPv6 pathways and tested protocols.

## 3. Blocking Mode architecture

```text
BlockingMode = BPF_NAT_VPN | PRE_NAT_FIREWALL
RequestedMode != EffectiveMode until capability + activation verification succeeds

                  [Exclusive Blocking Mode Controller]
                               |
                 [serialized mode transition lock]
                    /                       \
           BPF_NAT_VPN                  PRE_NAT_FIREWALL
       existing packet policy       capability-gated rule backend
          + BPF attribution            + rule lifecycle
                    \                       /
               read-only unified diagnostics
```

State must distinguish `requestedMode`, `effectiveMode`, `previousStableMode`, `transitionId`, `policyGeneration`, and `engineHealth`. Persist the effective mode **only after** successful verification; do not restore an experimental engine blindly on reboot or service reconnect.

**Transition rules:**

- The mode selector behaves as a **radio group** (only one selection). Do not permit concurrent enforcement or a moment where both engines apply policy.
- Serialize all transitions; reject/coalesce duplicate requests. Include session/binding generation in async work so stale callbacks cannot install rules.
- For BPF → Pre-NAT: prepare capabilities and exact scoped rule plan while the current engine is active; then enter a short explicit controlled transition; disable old enforcement before enabling new enforcement; verify target enforcement; commit effective mode. If enabling fails, clean up target rules before restoring the previous engine. Surface any transition gap and never claim atomic handover if unavailable.
- For Pre-NAT → BPF: remove and verify removal of owned Pre-NAT rules before reactivating the previous engine. On cleanup uncertainty, **do not enable another engine**; enter `RECOVERY_REQUIRED`, show clear user steps, and avoid destructive generic cleanup.
- Use idempotent start/stop, generation-scoped state and a single owner for rule mutations. Process crashes, Shizuku disconnects, revoked permissions, VPN restart, interface replacement and hotspot disconnect must trigger reconciliation.
- Pre-NAT test results and permissions are bound to device/build, shell identity, SELinux context, downstream interface index, upstream interface index, hotspot session and IPv4/IPv6 configuration. Invalidate on changes.

## 4. Capability checks (read-only first)

Collect and report **actual** results; no hardcoded success:

- Android build/API level, device model (redacted on export where appropriate), Shizuku running state, Shizuku mode (`ADB_SHELL` vs privileged, if detectable), UID/GID, SELinux context, effective capabilities (including `CAP_NET_ADMIN`), execution exit code and stderr.
- Available firewall technology: `iptables`/`ip6tables` variants, `nft` support, tethering chain ownership where readable, relevant BPF map/program visibility, `tc` availability, and kernel routing/firewall restrictions. Do not assume one backend applies to all devices.
- Current downstream/upstream name and OS ifindex; actual connected client IP/MAC bindings and IPv6 address lifetimes; whether rule matching can unambiguously identify a client on **ingress** before NAT.
- Identify whether the proposed hooks intercept **all** tested tethered traffic rather than only a subset. Detect possible hardware/software offload bypass; observational testing is mandatory.
- Classify each family separately: `IPV4_SUPPORTED`, `IPV6_SUPPORTED`, `IPV4_UNAVAILABLE`, `IPV6_UNAVAILABLE`, `UNKNOWN`. No overall full-support verdict if either required family is uncovered.

### Capability state machine

`UNCHECKED → CHECKING_READ_ONLY → NEEDS_USER_APPROVED_PROBE → PROBING → VERIFIED_AVAILABLE | UNAVAILABLE_PERMISSION | UNAVAILABLE_HOOK | UNAVAILABLE_IPV6 | INCONCLUSIVE | ERROR`

A **mutation probe** is optional and must require a separate explicit user action after previewing the exact add/remove operation. Probe only with a temporary, narrowly scoped, non-disruptive test rule (for example, counter-only if supported); never use a catch-all DROP. Capture exact rule identifiers, validate counter effects using controlled client traffic, then delete and verify cleanup. If non-disruptive rule proof is not possible, report `INCONCLUSIVE`, not `VERIFIED_AVAILABLE`. Use a short-lived watchdog where feasible, but do not represent app-side cleanup as guaranteed if the process dies or loses privilege.

Given the previously observed shell UID 2000 and missing `CAP_NET_ADMIN`, **expect** `UNAVAILABLE_PERMISSION` on standard netfilter writes unless a genuinely permitted path is demonstrated. Do not repeatedly retry privileged commands after a definitive permission denial.

## 5. Pre-NAT rule backend specification

Provide a backend interface (adapt names to existing project conventions):

```kotlin
interface BlockingEngine {
    suspend fun inspectCapability(): CapabilityReport
    suspend fun prepare(plan: ScopedRulePlan): PreparedPlan
    suspend fun activate(prepared: PreparedPlan): ActivationResult
    suspend fun verify(expected: PolicySnapshot): VerificationResult
    suspend fun deactivate(): CleanupResult
    fun observe(): EngineTelemetry
}
```

`ScopedRulePlan` includes immutable `sessionGeneration`, `bindingGeneration`, client identity (MAC and validated current IPv4/IPv6 bindings), downstream interface + ifindex, hook and ordering, rule family, intended policy, rule ownership tag, and exact removal instructions. Strongly prefer a unique **app-owned chain or uniquely tagged rules**, avoiding edits to existing platform chains except minimal insertion/removal of app-owned jumps where actually permitted.

- Enforce on **ingress/forwarding before source NAT**, using validated incoming client IP + downstream interface and, if truly supported at the hook, MAC. MAC alone may be randomized or unavailable at later hooks. Never assume the post-NAT source IP identifies a client.
- Apply equivalent safety guarantees to IPv6 (which may not be NATed at all). If IPv6 can bypass an IPv4-only rule, mark the target engine as `PARTIAL` / not full enforcement; do not silently drop all IPv6 clients.
- Derive allow/block/quota actions from the **same canonical policy store** used by the current engine; increment policy generation on changes. Apply policy changes only after successful atomic-or-reconciled scoped rule update; never expose an outdated success indicator.
- For selected blocked client, target all relevant protocols (TCP/UDP/ICMP/other forwarding) for the configured families; do not rely on application names, DNS blocking, or QUIC-only blocking.
- For permitted clients, preserve all normal connectivity. In particular, no default DROP outside exact blocked-client matches.
- If legitimate pre-NAT control is unsupported, return capability failure and **do not simulate success using post-NAT BPF attribution**.

## 6. Rollback, watchdog and recovery

- Before mutation, save an **app-owned rule journal** with transaction ID, scope, insertion points, exact intended undo operations, active interface/binding generation, and progress states. Avoid dumping unrelated rule tables with sensitive network details.
- On activation failure, remove **only** rules created by the transaction and verify absence. Restore previous stable engine only after cleanup is certain.
- On disconnect/restart, reconcile owned-rule journal against current kernel state; stale scoped rules must not be silently assumed removed. Never flush system chains or reset the hotspot to “fix” cleanup.
- On interface recreation, invalidate old mappings and require capability re-verification before any experimental reactivation.
- Prefer bounded operations and explicit cancellation. A local watchdog can attempt cleanup but cannot guarantee recovery after privilege loss or process death; mark `RECOVERY_REQUIRED` and provide manual instructions if safe cleanup is impossible.
- Report `ROLLBACK_SUCCEEDED`, `ROLLBACK_FAILED`, `CLEANUP_UNVERIFIED`, and exact remaining owned rule IDs. Do not report success until absence is confirmed.

## 7. UI/UX states

Under **Settings → Blocking Mode**, show one radio-group selection:

- `BPF/NAT + VPN (Current)` — **Partial enforcement**, existing behavior.
- `Pre-NAT Firewall (Experimental)` — **Capability check required**, disabled for activation until validation succeeds.

Show `Requested mode`, `Active mode`, `Capability`, `IPv4 coverage`, `IPv6 coverage`, `Shizuku privilege`, `Downstream/upstream`, and last verification timestamp. Buttons: **Check capability** (read-only), **Review scoped probe**, **Run scoped probe** (confirmation), **Activate** (only when verified), **Restore current engine**, **Export diagnostics**. Display the rule plan before a probe or activation.

Runtime states: `CURRENT_ACTIVE`, `PRE_NAT_UNCHECKED`, `CHECKING`, `PROBE_APPROVAL_REQUIRED`, `PROBING`, `PRE_NAT_AVAILABLE`, `PRE_NAT_UNAVAILABLE_PERMISSION`, `PRE_NAT_UNAVAILABLE_HOOK`, `PRE_NAT_IPV6_PARTIAL`, `TRANSITIONING`, `PRE_NAT_ACTIVE_VERIFIED`, `ROLLING_BACK`, `RECOVERY_REQUIRED`, `ERROR`.

Do not use a green “Active / Fully blocked” indicator if only permission checks or an installation command succeeded. Explain precisely why Pre-NAT is unavailable in rootless mode; preserve the option for future rooted/custom-ROM devices without claiming it works on the current phone.

## 8. Diagnostics schema / reporting

Export versioned JSON and human-readable Markdown. Recommended fields:

```json
{
  "schemaVersion": 4,
  "requestedMode": "PRE_NAT_FIREWALL",
  "effectiveMode": "BPF_NAT_VPN",
  "exclusiveEngineInvariant": true,
  "capability": {
    "status": "UNAVAILABLE_PERMISSION",
    "shizukuUid": 2000,
    "capNetAdmin": false,
    "ipv4": "UNAVAILABLE",
    "ipv6": "UNAVAILABLE",
    "probePerformed": false,
    "reason": "Permission-denied netfilter mutation; no verified pre-NAT backend"
  },
  "activation": {
    "attempted": false,
    "verified": false,
    "previousModeRestored": true,
    "ownedRuleCount": 0
  },
  "clientValidation": {
    "blockedClientDeliveryObserved": null,
    "allowedClientConnectivityPreserved": null,
    "independentMeasurement": false
  }
}
```

Also record guarded mutation commands (redacted), exit status, timeouts, chain/rule ownership tags, baseline/post counters, offload-path coverage, interface generations, cleanup outcomes, per-family verification, timestamps, and **evidence source** (`KERNEL_COUNTER`, `HOST_VPN`, `CLIENT_RECEIPT`). Never interpret aggregate `UNKNOWN_OWNER` traffic as traffic from a specific client.

## 9. Reproducible tests

All live rule tests require owner-authorized devices and explicit opt-in. Use **Client A** (target) and **Client B** (control), both with cellular/alternate network disabled. Validate delivery from an independent receiving endpoint and record policy transition timestamps.

| ID | Test | Expected |
|---|---|---|
| PN01 | Rootless Shizuku identity/capability inspection | UID, capabilities, SELinux and backend availability truthfully reported |
| PN02 | Missing `CAP_NET_ADMIN` or denied write | `UNAVAILABLE_PERMISSION`; no false activation, no broad rules |
| PN03 | Read-only capability check | No kernel rules changed |
| PN04 | User-approved non-disruptive mutation probe | Exact scoped addition, observation and verified cleanup or `INCONCLUSIVE` |
| PN05 | Switch selection repeatedly | Only one effective enforcement engine; serialized transitions |
| PN06 | Failed Pre-NAT activation | Remove owned rules; restore previous engine only after confirmed cleanup |
| PN07 | Failed cleanup / revoked Shizuku | `RECOVERY_REQUIRED`; do not activate second engine concurrently |
| PN08 | Block Client A, permit Client B (IPv4 TCP) | A's new and established application connections fail; B continues normally |
| PN09 | Repeat for UDP/443 and UDP/53 | A's useful traffic cannot reach external service; B unaffected |
| PN10 | WhatsApp/Telegram post-block controlled messages | No independently confirmed delivery from A; B can communicate |
| PN11 | IPv6 traffic with available IPv6 route | No bypass for A; no collateral blocking for B; else explicitly mark partial |
| PN12 | Client A reconnect/MAC randomization/IP change | Stale bindings invalidated; no collateral blocking |
| PN13 | Hotspot/VPN interface recreation | Re-detect interfaces, avoid stale rules, recover safe state |
| PN14 | Service crash/restart | Journal reconciliation and cleanup truthfully reported |
| PN15 | Background load and multi-client throughput | No unexpected disruption to B; log overhead and latency |
| PN16 | Unavailable pre-NAT hook/offload bypass | Mark unavailable/inconclusive; never claim complete enforcement |

Tests PN08–PN16 execute **only if** capabilities and a user-approved scoped probe support safe activation. Otherwise mark `BLOCKED_BY_CAPABILITY`, not PASS.

## 10. Acceptance criteria

- **AC01** Exclusive selection: never two active enforcement engines simultaneously.
- **AC02** Requested and effective engine clearly distinguished in UI and report.
- **AC03** Shizuku shell identity/capability/SELinux checks are real, timestamped and device-bound.
- **AC04** A read-only check causes zero rule mutations.
- **AC05** Any mutation probe needs explicit approval, uses narrow scope and verifies removal.
- **AC06** Permission-denied paths report `UNAVAILABLE_PERMISSION` and avoid repeated privileged retries.
- **AC07** Only an installed **and behaviorally verified** per-client pre-NAT rule can yield `PRE_NAT_ACTIVE_VERIFIED`.
- **AC08** On failure, app-owned rules are removed/verified; uncertain cleanup yields `RECOVERY_REQUIRED` and no dual-engine activation.
- **AC09** Client B connectivity remains normal during client A blocking in controlled tests.
- **AC10** A’s IPv4 TCP, UDP and existing sessions are blocked after enforcement under the tested conditions; application delivery checked independently.
- **AC11** IPv6 is checked separately; bypass or lack of hook is explicitly `PARTIAL`/unavailable, never “full success”.
- **AC12** Disconnect/reconnect, session generation changes, crashes and privilege loss do not create stale silent enforcement claims.
- **AC13** No blanket unknown-owner drop or platform firewall flush; app-owned changes only.
- **AC14** Report includes exact evidence, limitations, fallback outcome and reproducible test results.
- **AC15** If rootless pre-NAT enforcement is impossible, return a **definitive negative capability result** for this environment and leave the current mode available without claiming a fix.

## 11. Implementation deliverables for the coding LLM

1. Locate actual engine/controller classes and policy/cache flows; produce a brief implementation map before modifying code.
2. Implement exclusive mode enum, serialized transitions, generation checks, and requested-vs-effective state persistence.
3. Implement **read-only** capability inspector and auditable optional scoped probe. Do not add unverified destructive shell commands.
4. Implement Pre-NAT adapter **only if capability truly exists**; otherwise implement an explicit unavailable backend rather than faking enforcement.
5. Implement journaled rollback, UI states, per-family diagnostics, export schema migration, and automated unit/integration tests with mock shell executor.
6. Preserve current `BPF_NAT_VPN` functionality and all existing feature flags in its mode; ensure VPN packet drops are not simultaneously enforced by the Pre-NAT engine.
7. Provide build/run steps, changed files, test matrix results, failed/unverified requirements and **clear go/no-go conclusion** for rootless Samsung + Shizuku.

### Final decision rule

**GO** only when the exact device and OS permit installing, verifying and safely removing a scoped pre-NAT rule *and* two-client tests demonstrate no collateral disruption and no independently observed target traffic bypass. Otherwise **NO-GO** for Pre-NAT on this device; do not continue iterating on diagnostics as if a permissions barrier could be solved by additional polling.
