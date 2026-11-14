# Shizzy Luna v0.10.8-debug — Blocking Engine Simplification & Domain Filtering

## 1. Objective and context

Implement actual domain filtering, globally and per connected hotspot client, while simplifying the blocking engine selector to two existing choices. Keep the VPN/TUN architecture, rootless Shizuku operation, native Android hotspot and no client-side agent. Do not start another experimental firewall investigation.

Inspect the repository and current debug branch before editing. Preserve the application ID, existing working controls and stable branch. Proposed version: `0.10.8-debug`; increment serviceBuildId from 22 and report schema from 5 if those are still current. Do not assume class names or build configuration without inspecting the code.

### Evidence and decisions

- v0.10.7 reports `SOFTAP_MAC_BLOCK` requested but `BPF_NAT_VPN` effective, with `HAL_UNSUPPORTED`, force-disconnect capability false and no live probe. The user's observation that the modes appear to behave alike is consistent with fallback; it is not proof that native SoftAP blocking works.
- Keep both modes for future improvements; do not weaken SoftAP activation gates or claim native enforcement on this firmware.
- Remove `PRE_NAT_FIREWALL` as a selectable or executable engine. Prior checks did not demonstrate usable rootless pre-NAT mutation. Do not invest further in it in this release.
- Samsung native pause works without VPN but not with VPN in the user's tests. VPN remains a project requirement; Samsung native enforcement is out of scope.
- BPF/NAT identifies some owners after NAT; unknown-owner traffic currently passes. Domain filtering must not silently turn this into a global per-client drop or promise complete enforcement.

## 2. Simplify blocking modes

Persist only two selectable modes:

```kotlin
enum class BlockingMode {
    BPF_NAT_VPN,
    SOFTAP_MAC_BLOCK
}
```

Display `BPF/NAT + VPN` and `SoftAP MAC Block (Experimental)`. Show requested mode, effective mode and fallback reason. Keep BPF/NAT as default. Preserve SoftAP capability checks, ownership journal, approved live probe, cleanup and rollback. When unavailable, explicitly show BPF/NAT as effective; do not show a successful SoftAP block. Never force-enable unsupported HAL functionality.

Remove Pre-NAT option, screens, capability-check actions, background jobs, mutation paths and active diagnostic matrix from normal runtime. Retain only the minimal migration/cleanup code needed for legacy persisted state or app-owned rules. If an old Pre-NAT journal contains outstanding mutations, clean up only provably app-owned rules and verify removal before enabling another engine. If cleanup cannot be verified, enter `ROLLBACK_REQUIRED` and do not activate a competing engine. Never clear arbitrary system rules. Migrate legacy selected `PRE_NAT_FIREWALL` to `BPF_NAT_VPN`; handle unknown enum values safely. Preserve client policies and existing user/OEM SoftAP entries.

One whole-client enforcement engine at a time; domain filtering is a separate shared policy layer, not a third engine. Retain VPN transport in both modes. Do not accidentally re-enable whole-client BPF DROP/throttle in effective SoftAP mode. Domain-specific filtering through TUN is explicitly permitted in either mode and must be reported separately. If existing architecture cannot separate these paths, refactor before enabling domain filtering in SoftAP mode. Keep existing quota accounting and limitations, including unsupported throttling in native SoftAP mode.

Serialize transitions; invalidate stale binding/session decisions on interface recreation. Do not restart hotspot automatically on every switch unless necessary and explicitly communicated. Preserve safe rollback and show READY only after fresh bindings. Domain rules persist across engine changes; flush volatile flow and DNS attribution caches as appropriate.

## 3. Domain blocking requirements

Implement deny-only rules in two scopes:

- Global: applies to eligible hotspot traffic from every connected client, including owner-unknown packets only when hotspot provenance and matching domain are established.
- Per host: applies only to the selected verified hotspot client (station MAC/client identity); here host means connected device, not destination hostname.

Support exact hostname and hostname plus subdomains. Default to hostname plus subdomains, expose match mode clearly. Examples: `example.com` matches itself and `www.example.com`, never `notexample.com`. No arbitrary URL paths, regex, category feeds, allowlist overrides, TLS interception or IP-blocking UI in this iteration. Accept plain domains; reject URLs, ports, IP literals, empty labels, invalid IDNs and wildcards except a documented optional leading `*.` if implemented. Normalize lowercase, strip trailing DNS root dot, convert IDNs to ASCII using platform IDNA support; validate label/total lengths. Reject ambiguous input with inline error. Keep original display form if useful.

Rule fields: stable ID, scope (GLOBAL/CLIENT), client ID for CLIENT, normalized domain, match mode, enabled, created/updated timestamps. Persist using existing storage architecture. Deduplicate equivalent rules per scope; allow same domain in separate scopes. Rules are OR-combined: any applicable deny wins; a disabled rule has no effect. Removing a global deny does not remove a client deny and vice versa. Default allow if no applicable rule. Whole-client block always wins over domain decisions. Domain filters never unblock quota, schedule or manual blocks.

Client identity must use the existing verified station binding, not a display name or IP alone. On MAC randomization a new identity may require manual reassignment; do not transfer rules to another client automatically. Keep offline client rules visible and editable.

## 4. Implementation approach: DNS first, additional evidence only when safe

### 4.1 Inspect the actual packet pipeline

Locate TUN receive/send paths, DNS forwarding/resolver code, flow parser, BPF/NAT attribution and packet policy decisions. Determine which DNS packets actually traverse the VPN, whether upstream DNS is forwarded internally, and whether host-originated traffic can be distinguished from tethered traffic. Do not invent a DNS interception path. Document the integration point and confirm forwarding works for allowed queries.

### 4.2 Enforce observable plaintext DNS

Implement bounded, validated DNS parsing for UDP/53 and TCP/53 where the existing transport supports it. Handle IPv4 and IPv6, question name normalization, A/AAAA and other query types, compression pointers safely, truncation, malformed packets, EDNS and TCP framing. Reassemble TCP DNS only through an existing reliable stream path or a properly bounded implementation; report TCP DNS unsupported if not safely implemented. No simplistic packet-string search.

Before forwarding a DNS query, evaluate applicable rules using verified owner and provenance. For a blocked query, return a valid local DNS refusal (recommended RCODE REFUSED) with matching transaction ID/question and correct transport handling; alternatively drop only if safe response generation is unavailable and document timeout behavior. Do not send blocked queries upstream. For allowed queries preserve existing forwarding, response handling and DNSSEC behavior. Never forge a successful answer or redirect to an external page. Ensure correct packet lengths/checksums and no response loops.

For global rules, require positive evidence that the traffic is from hotspot clients or an existing explicitly scoped hotspot-only path. Do not apply a global hotspot rule to the phone's own traffic merely because it uses the same TUN. For per-client rules, use DIRECT_IP or verified BPF_NAT/current binding evidence; never infer owner from remote IP, domain, last active client, or number of connected devices. If unresolved, preserve current fail-open behavior, record `DOMAIN_CLIENT_OWNER_UNKNOWN`, and do not charge/drop against a guessed client. A later verified packet may be filtered normally. Existing Phase B refresh may help attribution but is not a prerequisite to this feature; no unbounded synchronous waiting.

### 4.3 Optional connection-level domain evidence

DNS blocking alone will not stop cached IPs or existing encrypted connections. If the existing forwarding pipeline exposes reliable plaintext HTTP Host or TLS ClientHello SNI, add a bounded, separately testable hostname classifier for new connections. Use verified provenance and ownership rules above. Parse HTTP/TLS correctly, account for fragmented TCP records, bound memory/time, and do not decrypt TLS or install a CA. Only block when the actual hostname is confidently observed and the relevant scope is established. Do not treat DNS-derived IPs as definitive host identity: shared CDN IPs can serve many unrelated domains. DNS answer associations may be telemetry/hints, scoped to client, TTL and generation, not a sole DROP reason. Do not implement destination-IP denial as a shortcut.

Do not claim QUIC hostname inspection unless a real supported parser exists and has been tested. DoH, DoT, ECH, cached DNS, direct IP connections and unobserved forwarding paths can bypass this release. Do not globally block UDP/443, TCP/853, public DNS resolvers or arbitrary HTTPS to force a result; that would be a separate opt-in policy outside scope. Existing connections may continue after a new rule; explicitly report that limitation. If optional SNI/HTTP work is not feasible, ship working DNS filtering with honest capability labels, not another diagnostics-only version.

## 5. Policy integration and decision order

Use a shared domain rule store and evaluator with immutable snapshots or equivalent thread-safe reads. Example conceptual decision order (adapt to actual pipeline):

```text
Packet / DNS request
  -> classify hotspot provenance and verified owner if available
  -> existing whole-client policy (effective engine only)
  -> evaluate observed hostname against enabled global rules
  -> evaluate observed hostname against enabled rules of verified owner
  -> refuse/drop if domain deny is proven; otherwise preserve existing forwarding
```

If native SoftAP already disconnected a blocked client, domain filtering has no work for that device. Do not double-count drops or quota bytes. Domain decisions must not change quota exhaustion, manual block state, schedule or throttle. Preserve existing accounting semantics and document whether rejected requests are counted. Invalidate rule decision caches immediately on rule edits and use rule generation tokens. Flush volatile flow associations on binding changes; bound caches and diagnostic ring buffers. Avoid UI-thread I/O, per-packet database reads, per-packet shell calls and unnecessary refreshes. No payload logging, no DNS history persistence by default.

## 6. UI

Add `Domain Blocking` screen (or an existing navigation section if suitable). Provide Global Rules and Per Host sections. Global list shows all domains, match mode, enabled toggle, add/edit/delete. Client details expose Domain Rules for that client, with an indication that global rules also apply. Use current app design and localization conventions. Show empty states, validation, disabled states, confirmation for destructive bulk operations and clear status when filtering is unavailable.

Example:

```text
Domain Blocking
  Global Rules (2)
    example.com       Include subdomains    ON
    ads.example.net   Exact hostname        ON
    + Add domain
  Per Host
    A55               1 rule
    Laptop            0 rules

A55 > Domain Rules
  Global rules also apply
  social.example      Include subdomains    ON
  + Add domain
```

Display actual capability: `DNS_FILTER_ACTIVE`, `DNS_FILTER_UNAVAILABLE`, optional `HOSTNAME_FILTER_ACTIVE`, `PARTIAL_DOMAIN_ENFORCEMENT`. Explain encrypted DNS/cached connection limitations and unknown-owner caveat in concise help text. Do not label domains as universally blocked unless tested under that transport. Keep normal clients UI and manual block controls intact.

## 7. Telemetry and diagnostics

Add a compact domain section to JSON/Markdown export; avoid expanding old experimental reports unnecessarily. Suggested counters: queries observed (UDP/TCP, IPv4/IPv6), hotspot provenance unknown, owner verified/unknown, global rule matches, per-client rule matches, refusals sent, drops, allowed requests, malformed/unsupported queries, unknown-owner client-rule skips, optional HTTP/SNI matches, cache hits/evictions, rule generation and effective engine. Separate match from actual refusal/drop and response generation errors. Include per-rule and per-client aggregates only for verified ownership; global unknown counts stay separate. Redact client MAC/IP and domain names by default (domain rules are user browsing policy data); never export payloads, Wi-Fi credentials or raw DNS logs. Distinguish test/unit evidence from actual device runtime proof; no synthetic PASS labels. Remove Pre-NAT test matrix from current report except a compact legacy migration/cleanup status if applicable.

## 8. Reproducible tests

Use two hotspot clients A and B plus the host phone; disable cellular fallback on test clients, ensure traffic actually goes through the hotspot, and choose a reachable controlled domain or example.com after confirming baseline connectivity. Use a DNS test tool with explicit resolver, unique uncached names when possible, and controlled HTTP/HTTPS endpoints. Repeat on cellular and Wi-Fi upstream where supported. Record Android/firmware, VPN state, requested/effective engine, verified owner evidence and actual client observations.

| ID | Test | Expected |
|---|---|---|
| DB01 | Upgrade with legacy Pre-NAT selection | BPF/NAT selected; two options only; no stale engine mutations |
| DB02 | Upgrade with unresolved legacy owned rules | Safe cleanup or ROLLBACK_REQUIRED; no conflicting engine |
| DB03 | Select unsupported SoftAP | Explicit fallback, one effective engine; no false native success |
| DB04 | Global deny, A and B query blocked domain | Both refused on observable hotspot DNS; unrelated domain works |
| DB05 | Per-host deny for A only | A refused when owner verified; B and host unaffected |
| DB06 | Global and per-host overlap; delete one | Remaining applicable deny still effective |
| DB07 | Exact vs subdomain, uppercase, trailing dot, IDN, lookalike suffix | Correct normalization and boundary matching |
| DB08 | Unknown owner with per-host rule | No guessed drop; skip counter increments |
| DB09 | Host phone requests globally denied domain | Host unaffected unless independently verified as in scope (not default) |
| DB10 | UDP/TCP DNS, A/AAAA, IPv4/IPv6 | Supported paths enforce; unsupported paths explicitly reported |
| DB11 | Malformed DNS and fragmented inputs | No crash, unsafe allocation, or false match |
| DB12 | DoH/DoT, QUIC, cached DNS and direct IP | Observe limitations, no false claim or broad collateral block |
| DB13 | Rule edit/disable/delete, process restart | Immediate new decisions; persisted rules restored |
| DB14 | Client reconnect/IP change/MAC change | Correct binding invalidation; no rule transferred to unrelated client |
| DB15 | Manual block/quota/schedule plus domain rules | Existing whole-client policy remains authoritative |
| DB16 | Switch engines and restart hotspot/VPN | Rules persist, no dual whole-client engine, no stale attribution |
| DB17 | Shared CDN / unrelated site | No IP-based collateral denial |
| DB18 | Load test with multiple clients | Bounded memory, no ANR, allowed traffic remains usable |
| DB19 | Optional HTTP/SNI classifier | Proven hostname blocks; unavailable/encrypted hostname does not cause guessed DROP |
| DB20 | Export diagnostics | Accurate counters, no credentials/payload/raw MAC or domain history |

## 9. Acceptance criteria and delivery

1. Only BPF/NAT and SoftAP MAC are selectable; no Pre-NAT runtime activation path remains after safe migration.
2. Existing BPF/NAT functionality, quota, schedule and manual controls are not regressed; SoftAP safeguards and fallback remain intact.
3. Global and per-host deny rules can be created, edited, toggled, deleted and persisted.
4. A verified observable DNS query matching a global rule is actually prevented from reaching the resolver and receives the intended refusal or documented drop.
5. A verified per-host rule blocks A's matching query without blocking B's same query; host phone is not affected by hotspot-only rules.
6. Unknown owner is never guessed, and the report explicitly records per-host enforcement gaps.
7. Domain matching is boundary-correct and validated; no broad IP, QUIC or encrypted DNS denial as an undocumented workaround.
8. Domain enforcement stays separate from exclusive whole-client engines, with no dual policy DROP/throttle and safe transitions.
9. Actual device tests distinguish supported DNS paths, optional hostname paths and known bypasses; no claim of 100% domain or device blocking.
10. Tests and build succeed; provide changed files, implementation decisions, known limitations and exact manual validation steps. If a path is infeasible, explain the blocker and ship only verified functionality; do not substitute a report for the requested working DNS feature.

Deliver a debug APK/build instructions, automated tests for rule matching and policy composition, migration tests, and updated README/report schema. Keep future IP blocking, encrypted DNS controls, captive portal, Samsung native investigation and further whole-client enforcement improvements out of this release.
