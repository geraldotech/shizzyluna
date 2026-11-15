# Shizzy Luna v0.10.3 — Release UI Cleanup & Production Surface Specification

## Objective
Prepare the **final non-debug release** as **version `0.10.3`**, based on the current working feature set, but with a **clean production UI**.

This release must **remove visible debug / diagnostic / engineering-only UI blocks** highlighted by the user and keep only end-user-facing controls and concise status information.

The goal is to ship a **stable consumer-facing build** with the current practical functionality:
- hotspot client listing
- block / unblock
- quota / limits
- bandwidth limit (where supported)
- schedule support (where already implemented)
- domain blocking (global and per-host)
- blocking mode selection
- VPN recovery option

This release is **not** a feature-expansion build. It is mainly a **UI cleanup + release hardening** build.

---

## Target Version
- **Release Version Name**: `0.10.3`
- **Build Type**: `release`
- **Release Surface**: production UI only
- **No debug wording should appear in visible UI** unless hidden behind a developer-only area.

---

## Product Direction
The user wants the app to feel like a final product, not a lab build.

Therefore:
1. Keep working features.
2. Remove engineering noise from the main UI.
3. Hide diagnostic text, raw counters, verbose state labels, permission internals, attribution internals, and probe details from normal users.
4. Preserve internal logging/diagnostics **in code and export flows** where useful, but not visibly rendered in normal screens.

---

# 1. Functional Scope To Keep In Release

## 1.1 Connected Devices
Keep:
- device alias / host name
- IP address
- MAC address
- connected / blocked state
- usage summary
- toggle / block action
- open domain rules for a host
- configure limits
- delete / remove host rule record if already supported
- refresh action if needed
- search field
- add MAC action

Do not remove the underlying enforcement logic.

## 1.2 Settings
Keep:
- logging toggle (if intended for production)
- experimental BPF NAT attribution toggle (if still required)
- blocking mode selector
- VPN disconnect behavior option
- any user-facing switches still needed for real operation

## 1.3 Domain Blocking
Keep:
- global rules tab
- per-host rules tab
- add/edit/delete/toggle rules
- domain matching modes (root + subdomains / exact hostname)
- clear button if already supported

## 1.4 Blocking Mode
Keep only the two supported modes:
- `BPF/NAT + VPN`
- `SoftAP MAC Block (Experimental)`

`Pre-NAT Firewall` must remain removed from normal UI.

---

# 2. UI Cleanup Required

The user highlighted red-marked sections that must be removed from the visible production UI.

## 2.1 Connected Devices Screen — Remove Debug Overlay / Verbose Technical Block
A top text block or overlapped engineering text is visible above the action buttons and search area.

### Remove from visible UI
Any raw / verbose debug text such as:
- backend labels like `USERSPACE`, `PROXY`, etc. when rendered as loose diagnostic text
- raw connected / blocked / bandwidth / datapath debug text clutter
- attribution internals shown outside the device card in a broken/overlapping layout
- any malformed or clipped debug content at the top of the screen

### Keep
- page title `Connected Devices`
- action row (`refresh`, `Domains`, `Add MAC`) if intended
- search field
- clean device cards only

### Acceptance target
The screen should visually start with:
1. App bar/title
2. action buttons row
3. search field
4. clean device cards

No stray engineering text should be visible above or behind these elements.

---

## 2.2 Settings Screen — Remove BPF Attribution Diagnostics Debug Card
The large card titled similar to:
- `BPF Attribution Diagnostics (Debug)`
- Phase B refresh stats
- raw latency / breaker / coverage / failure reason text

must be removed from the normal settings UI.

### Remove from visible UI
- raw packet / byte counters
- flow counts
- direct IP / BPF NAT / conntrack counters
- unattributed traffic counters
- protocol splits
- blocked/quota/rate policy counters
- Phase B stats, latency, breaker state
- any debug-only diagnostic paragraphs
- any UNAVAILABLE / debug labels shown only for engineering interpretation

### Keep
- the actual operational toggle(s) that matter to end users, if those toggles are still intended for release

### Recommended release surface
Settings should show concise options only, for example:
- Logging
- Experimental BPF NAT Attribution
- Blocking Mode
- Stop hotspot when VPN disconnects
- Developer options (optional entry point, hidden or collapsed)

---

## 2.3 Settings Screen — Clean Exclusive Blocking Mode Card
Inside the blocking mode section, remove the lower verbose status block that currently displays lines such as:
- requested mode
- active mode
- state
- transitionId
- policyGen
- fallback explanations
- invariant text
- raw mode status diagnostics

### Keep visible
- section title
- short explanatory copy
- the two radio/selectable options only:
  - `BPF/NAT + VPN`
  - `SoftAP MAC Block (Experimental)`

### Optional small status
A single concise user-facing line is allowed, e.g.:
- `Current mode: BPF/NAT + VPN`
- `Current mode: SoftAP MAC Block`

Do not show raw internal state strings like `CURRENT_ACTIVE`, `PERMISSION_DENIED`, `policyGen`, etc.

### Buttons
Review whether these buttons should remain visible:
- `Restore BPF/NAT mode`
- `Export diagnostics`

For release UI:
- keep `Export diagnostics` only if useful for support
- hide `Restore BPF/NAT mode` unless there is a real user-facing need
- support actions should preferably be placed under a separate support/developer area, not the main mode card

---

## 2.4 Settings Screen — Remove SoftAP Experimental Diagnostic Block
The long block for:
- `SoftAP MAC Blocklist Engine (Experimental)`
- permission status details
- internal API get/set capability lines
- shizuku identity lines
- provenance
- config snapshot
- 2-client live probe results
- raw exception text
- `Check SoftAP capability`
- `Run 2-client live probe`
- `Activate SoftAP`

must be removed from the normal production UI.

### Important
The user no longer wants the release app to expose this engineering surface.

### Keep only what matters in normal UI
If SoftAP mode is selectable, the UI may show a short helper sentence under the mode option, for example:
- `Disconnects blocked clients from the hotspot. Bandwidth throttling is not supported in this mode.`

### If capability fails
Show a concise user-facing message only when needed, such as:
- `SoftAP MAC Block is unavailable on this device.`

Do **not** render raw `SecurityException`, shell UID details, capability bitfields, or internal probe information on the main settings page.

---

## 2.5 Domain Blocking Screen — Remove Debug/Diagnostic Status Header Card
The top card currently showing:
- `Status: PARTIAL_DOMAIN_ENFORCEMENT`
- `DNS Inspected`
- `DNS Blocked`
- `SNI/Host Drops`
- explanatory diagnostic paragraph

should be removed from the normal release UI.

### Remove from visible UI
- enforcement state constant strings
- counters for DNS inspected / blocked
- SNI/Host counters
- long internal limitation note

### Keep
- page title `Domain Blocking`
- tabs: `Global Rules`, `Per Host`
- section cards and domain rule lists
- add / clear / edit / delete / enable controls

### Optional replacement
Instead of the large diagnostic card, optionally show a small, non-technical note:
- `Global rules work best with standard DNS. Per-host rules may be limited by traffic attribution.`

This note should be brief and human-readable.

---

# 3. Release UI Behavior Guidelines

## 3.1 Keep UI user-facing, not engineering-facing
Visible text should avoid raw internal terms such as:
- `CURRENT_ACTIVE`
- `PARTIAL_ENFORCEMENT`
- `PERMISSION_DENIED`
- `UNAVAILABLE`
- `policyGen`
- `transitionId`
- `DIRECT_IP`
- `BPF_NAT`
- `CONNTRACK`
- `Phase B`
- `breaker`
- `probe`
- `snapshot`

Replace them with concise user language when needed.

## 3.2 Preserve diagnostics internally
The cleanup is primarily about **visible UI**.

Internal data may still be kept for:
- logs
- support export
- debug builds
- hidden developer screens

## 3.3 Optional hidden Developer section
If maintaining diagnostics is useful, move them behind one of these patterns:
- hidden `Developer Options` section
- long-press gesture
- separate `Diagnostics` screen hidden from normal users
- debug-build-only composables

For the final `0.10.3 release`, these details must not appear on primary screens.

---

# 4. Version Cleanup / Naming

## 4.1 Rebrand from debug surface to release surface
Anywhere in the visible UI, remove or update:
- `v0.10.9`
- `debug`
- `experimental report`
- diagnostic build wording

For the final app surface, display only:
- `Shizzy Luna 0.10.3`
or equivalent release naming.

## 4.2 Build / package expectations
- Generate a release-ready build flavor if not already present.
- Ensure any `BuildConfig.DEBUG` gated content is hidden in release.
- Ensure developer composables are not shown by default in release builds.

---

# 5. Connected Device Card Cleanup

Keep the device card compact and useful.

## Recommended device card fields
Visible:
- Device name / alias
- IP
- MAC
- on/off or blocked toggle
- connection badge (`Connected`, optionally with duration)
- quota summary (`Unlimited` or limit)
- usage summary (`download / upload / total`)
- warning note only if relevant (`Usage may be incomplete` can remain if concise)
- actions:
  - `Domains`
  - `Configure Limits`
  - optional delete/remove icon

## Remove or simplify
- raw version labels like `v1`
- raw `seen=... (bpf=..., direct=...)`
- raw attribution counters inside cards unless moved to hidden diagnostics

A production user should not need to see attribution-source statistics per host.

---

# 6. Domain Blocking Release Behavior

## 6.1 Keep current functionality
Do not remove:
- working global DNS block behavior
- per-host domain rules UI

## 6.2 Simplify wording
Use concise language:
- `Global Rules`
- `Per Host`
- `Add Global Domain`
- `Add Host Rule`
- `Root + Subdomains`
- `Exact Hostname Only`

## 6.3 If needed, add a small info note
Allowed minimal note:
- `For best results, use standard DNS on connected devices.`

Keep it short.

---

# 7. Blocking Mode Release Behavior

## Visible mode options
Only show:
1. `BPF/NAT + VPN`
2. `SoftAP MAC Block (Experimental)`

## Recommended copy
### BPF/NAT + VPN
`Userspace VPN mode with internet blocking, data limits, bandwidth limits, and domain rules.`

### SoftAP MAC Block (Experimental)
`Uses hotspot-level MAC blocking to disconnect blocked clients. Bandwidth throttling is not supported in this mode.`

## Optional small status line
- `Current mode: BPF/NAT + VPN`
- `Current mode: SoftAP MAC Block`

Nothing more verbose than that.

---

# 8. VPN Disconnect Recovery Option

This feature should remain visible because it is useful, not diagnostic.

## User-facing wording
Suggested setting label:
- `Stop hotspot when VPN disconnects`

Description:
- `Turn this off to keep the hotspot on while the app waits for the VPN to reconnect.`

Keep the wording simple.

---

# 9. Migration / Cleanup Rules

When upgrading from current debug builds:
- preserve existing client records
- preserve domain rules
- preserve selected blocking mode if valid
- remove obsolete Pre-NAT mode references from stored settings
- remove debug UI flags from user-facing preferences if they are no longer used

If any saved debug mode points to unsupported UI sections, safely ignore them.

---

# 10. Acceptance Criteria

## AC01 — Connected Devices cleanup
No debug or clipped text appears above the action buttons/search field.

## AC02 — Clean settings page
The large BPF diagnostics card is not visible in the release UI.

## AC03 — Clean blocking mode section
Only the two mode choices are visible, with concise descriptions.

## AC04 — No verbose mode internals
Requested mode / active mode / transitionId / policyGen / invariant text are not displayed on the main settings page.

## AC05 — No SoftAP diagnostic panel
The SoftAP capability/probe/exception block is not shown in the main release UI.

## AC06 — Clean domain blocking screen
The top domain diagnostic status card is removed from visible UI.

## AC07 — Domain rules preserved
Existing global and per-host domain rules remain functional after the cleanup.

## AC08 — Release version naming
Visible versioning reflects `0.10.3` release surface rather than `0.10.9 debug`.

## AC09 — Support/export still possible
If diagnostics export is preserved, it is accessible without cluttering the main UI.

## AC10 — No raw engineering constants in normal UI
Strings like `PARTIAL_DOMAIN_ENFORCEMENT`, `CURRENT_ACTIVE`, `PERMISSION_DENIED`, etc. are absent from main screens.

## AC11 — Device cards simplified
Per-device cards no longer show raw attribution counts such as `seen=...`, `bpf=...`, `direct=...`.

## AC12 — Functional parity maintained
Cleaning the UI must not break blocking, limits, domain rules, or VPN recovery.

---

# 11. Implementation Notes

Recommended implementation approach:
1. Keep current state/data models intact.
2. Remove or gate debug composables from the normal navigation flow.
3. Introduce concise release-facing status text where needed.
4. Use `BuildConfig.DEBUG` or a developer visibility flag for hidden diagnostic surfaces.
5. Validate all five user-provided screens after cleanup.

---

# 12. Final Deliverable
Produce a **release-oriented `0.10.3` build** with:
- cleaned UI
- two blocking modes only
- no visible debug panels on main screens
- preserved existing functionality
- production-friendly wording

This version should feel like a **final usable app**, not an engineering dashboard.
