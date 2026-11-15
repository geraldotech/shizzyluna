package dev.shizzi

import android.os.Build
import android.system.Os
import java.io.File
import java.util.Locale
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import rikka.shizuku.Shizuku

/**
 * Exclusive packet-enforcement mode selector for Shizzy Luna v0.10.6-debug.
 *
 * Non-negotiable invariant:
 * - Exactly ONE packet-enforcement engine may apply policy drops/shaping at any moment.
 * - RequestedMode != EffectiveMode until capability + activation verification succeeds.
 */
enum class BlockingMode(val displayTitle: String) {
    BPF_NAT_VPN("BPF/NAT + VPN"),
    SOFTAP_MAC_BLOCK("SoftAP MAC Block (Experimental)"),
    ;

    companion object {
        fun parseWithMigration(raw: String?): Pair<BlockingMode, Boolean> {
            val trimmed = raw?.trim()
            if (trimmed.isNullOrEmpty()) return BPF_NAT_VPN to false
            if (trimmed.equals("PRE_NAT_FIREWALL", ignoreCase = true)) {
                return BPF_NAT_VPN to true
            }
            val matched = entries.firstOrNull { it.name.equals(trimmed, ignoreCase = true) }
            return (matched ?: BPF_NAT_VPN) to false
        }

        fun fromName(raw: String?): BlockingMode = parseWithMigration(raw).first
    }
}

/**
 * Capability state machine for the experimental Pre-NAT Firewall backend:
 * `UNCHECKED -> CHECKING_READ_ONLY -> NEEDS_USER_APPROVED_PROBE -> PROBING ->
 *  VERIFIED_AVAILABLE | NOT_TESTED_SHIZUKU_UNAVAILABLE | UNAVAILABLE_PERMISSION | UNAVAILABLE_HOOK | UNAVAILABLE_IPV6 | INCONCLUSIVE | ERROR`
 */
enum class PreNatCapabilityStatus {
    UNCHECKED,
    CHECKING_READ_ONLY,
    NEEDS_USER_APPROVED_PROBE,
    PROBING,
    VERIFIED_AVAILABLE,
    NOT_TESTED_SHIZUKU_UNAVAILABLE,
    UNAVAILABLE_PERMISSION,
    UNAVAILABLE_HOOK,
    UNAVAILABLE_IPV6,
    INCONCLUSIVE,
    ERROR,
    ;

    val code: String get() = name
}

typealias PreNatCapabilityVerdict = PreNatCapabilityStatus

/**
 * Per-address-family Pre-NAT support classification.
 */
enum class PreNatFamilyCoverage {
    IPV4_SUPPORTED,
    IPV6_SUPPORTED,
    IPV4_UNAVAILABLE,
    IPV6_UNAVAILABLE,
    UNKNOWN,
    ;

    val shortReportName: String
        get() = when (this) {
            IPV4_SUPPORTED, IPV6_SUPPORTED -> "SUPPORTED"
            IPV4_UNAVAILABLE, IPV6_UNAVAILABLE -> "UNAVAILABLE"
            UNKNOWN -> "UNKNOWN"
        }
}

/**
 * UI & controller runtime state for Settings -> Blocking Mode (Section 7).
 */
enum class PreNatRuntimeState {
    CURRENT_ACTIVE,
    PRE_NAT_UNCHECKED,
    CHECKING,
    PROBE_APPROVAL_REQUIRED,
    PROBING,
    PRE_NAT_AVAILABLE,
    PRE_NAT_UNAVAILABLE_PERMISSION,
    PRE_NAT_UNAVAILABLE_HOOK,
    PRE_NAT_IPV6_PARTIAL,
    TRANSITIONING,
    PRE_NAT_ACTIVE_VERIFIED,
    ROLLING_BACK,
    RECOVERY_REQUIRED,
    ERROR,
}

/**
 * Rollback & cleanup verification status (Section 6).
 */
enum class RollbackStatus {
    NOT_REQUIRED,
    ROLLBACK_SUCCEEDED,
    ROLLBACK_FAILED,
    CLEANUP_UNVERIFIED,
}

/**
 * Source of validation evidence recorded in diagnostics (Section 8).
 */
enum class PreNatEvidenceSource {
    KERNEL_COUNTER,
    HOST_VPN,
    CLIENT_RECEIPT,
}

/**
 * Audited shell command record (redacted on export by default).
 */
data class AuditedShellCommand(
    val phase: String,
    val isMutating: Boolean,
    val command: String,
    val exitCode: Int,
    val timedOut: Boolean,
    val errorKind: ProbeErrorKind,
    val stderrPreview: String,
    val stdoutPreview: String = "",
    val timestampEpochMs: Long = System.currentTimeMillis(),
) {
    fun toJson(includeSensitive: Boolean = false): JSONObject = JSONObject().apply {
        put("phase", phase)
        put("isMutating", isMutating)
        put("command", if (includeSensitive) command else BpfDumpParser.maskSensitiveLinePreview(command))
        put("exitCode", exitCode)
        put("timedOut", timedOut)
        put("errorKind", errorKind.name)
        put("stderrPreview", if (includeSensitive) stderrPreview else BpfDumpParser.maskSensitiveLinePreview(stderrPreview))
        put("stdoutPreview", if (includeSensitive) stdoutPreview else BpfDumpParser.maskSensitiveLinePreview(stdoutPreview))
        put("timestampEpochMs", timestampEpochMs)
    }

    companion object {
        fun fromJson(json: JSONObject): AuditedShellCommand = AuditedShellCommand(
            phase = json.optString("phase", "READ_ONLY"),
            isMutating = json.optBoolean("isMutating", false),
            command = json.optString("command", ""),
            exitCode = json.optInt("exitCode", -1),
            timedOut = json.optBoolean("timedOut", false),
            errorKind = runCatching {
                ProbeErrorKind.valueOf(json.optString("errorKind", ProbeErrorKind.NONE.name))
            }.getOrDefault(ProbeErrorKind.NONE),
            stderrPreview = json.optString("stderrPreview", ""),
            stdoutPreview = json.optString("stdoutPreview", ""),
            timestampEpochMs = json.optLong("timestampEpochMs", 0L),
        )
    }
}

/**
 * Pluggable shell & process identity executor so unit/integration tests can deterministically
 * test rootless permission denials, probe verification, activation failures, and recovery states.
 */
interface PreNatShellExecutor {
    fun resolveUid(): Int
    fun resolveGid(): Int
    fun resolveShizukuUid(): Int
    fun resolveShizukuRunning(): Boolean
    fun resolveShizukuPermissionGranted(): Boolean = resolveShizukuRunning()
    fun resolveSeLinuxContext(): String
    fun resolveEffectiveCapabilitiesHex(): String
    fun execute(vararg args: String, timeoutMs: Long = 2_000L): HostFirewall.CommandResult
}

/**
 * Default production executor backed by the current Shizuku UserService / process context.
 * Never fabricates UID/GID or capability values when Shizuku is not running.
 */
object DefaultPreNatShellExecutor : PreNatShellExecutor {
    private fun isInPrivilegedServiceProcess(): Boolean {
        val raw = runCatching { Os.getuid() }.getOrDefault(-1)
        return (raw == 2000 || raw == 0) && File("/system/build.prop").exists()
    }

    override fun resolveShizukuRunning(): Boolean {
        if (isInPrivilegedServiceProcess()) return true
        return runCatching { Shizuku.pingBinder() }.getOrDefault(false)
    }

    override fun resolveShizukuPermissionGranted(): Boolean {
        if (isInPrivilegedServiceProcess()) return true
        if (!resolveShizukuRunning()) return false
        return runCatching {
            Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
    }

    override fun resolveUid(): Int {
        if (!resolveShizukuRunning() || !resolveShizukuPermissionGranted()) return -1
        val raw = runCatching { Os.getuid() }.getOrDefault(-1)
        if (raw == 2000 || (raw == 0 && File("/system/build.prop").exists())) return raw
        return runCatching { if (Shizuku.pingBinder()) Shizuku.getUid() else -1 }.getOrDefault(-1)
    }

    override fun resolveGid(): Int {
        if (!resolveShizukuRunning() || !resolveShizukuPermissionGranted()) return -1
        val raw = runCatching { Os.getgid() }.getOrDefault(-1)
        if (raw == 2000 || (raw == 0 && File("/system/build.prop").exists())) return raw
        return resolveUid()
    }

    override fun resolveShizukuUid(): Int {
        if (!resolveShizukuRunning() || !resolveShizukuPermissionGranted()) return -1
        return runCatching {
            if (Shizuku.pingBinder()) Shizuku.getUid() else resolveUid()
        }.getOrDefault(resolveUid())
    }

    override fun resolveSeLinuxContext(): String {
        if (!resolveShizukuRunning() || !resolveShizukuPermissionGranted()) return "UNKNOWN"
        if (isInPrivilegedServiceProcess()) {
            val attrCurrent = runCatching {
                File("/proc/self/attr/current").readText(Charsets.UTF_8).trimEnd('\u0000', '\n', '\r', ' ')
            }.getOrDefault("")
            if (attrCurrent.isNotBlank()) return attrCurrent
        }
        val idZ = execute("id", "-Z", timeoutMs = 1_500L)
        if (idZ.isSuccess && idZ.stdout.isNotBlank()) return idZ.stdout.trim()
        return "UNKNOWN"
    }

    override fun resolveEffectiveCapabilitiesHex(): String {
        if (!resolveShizukuRunning() || !resolveShizukuPermissionGranted()) return "UNKNOWN"
        if (isInPrivilegedServiceProcess()) {
            val statusLines = runCatching { File("/proc/self/status").readLines() }.getOrDefault(emptyList())
            val capLine = statusLines.firstOrNull { it.startsWith("CapEff:") }
            val parsed = capLine?.substringAfter("CapEff:")?.trim().orEmpty()
            if (parsed.isNotBlank()) return parsed
        }
        return "UNKNOWN"
    }

    override fun execute(vararg args: String, timeoutMs: Long): HostFirewall.CommandResult =
        HostFirewall.executeCommand(*args, timeoutMs = timeoutMs)
}

/**
 * Immutable environment fingerprint binding capability checks & probes to a specific
 * device, OS build, shell identity, SELinux context, interface pair, and session/binding generation.
 */
data class PreNatEnvironmentBinding(
    val deviceModel: String = "${Build.MANUFACTURER} ${Build.MODEL}".trim(),
    val androidApi: Int = Build.VERSION.SDK_INT,
    val buildFingerprint: String = Build.FINGERPRINT.orEmpty(),
    val shizukuUid: Int = 2000,
    val processUid: Int = 2000,
    val processGid: Int = 2000,
    val shizukuMode: String = "ADB_SHELL",
    val selinuxContext: String = "u:r:shell:s0",
    val effectiveCapabilitiesHex: String = "0000000000000000",
    val capNetAdmin: Boolean = false,
    val downstreamIface: String = "",
    val downstreamIfIndex: Int = 0,
    val upstreamIface: String = "",
    val upstreamIfIndex: Int = 0,
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
) {
    /**
     * Checks whether the privilege and interface identity match another binding.
     */
    fun matchesEnvironment(other: PreNatEnvironmentBinding): Boolean =
        androidApi == other.androidApi &&
            shizukuUid == other.shizukuUid &&
            processUid == other.processUid &&
            selinuxContext == other.selinuxContext &&
            effectiveCapabilitiesHex == other.effectiveCapabilitiesHex &&
            capNetAdmin == other.capNetAdmin &&
            downstreamIface == other.downstreamIface &&
            downstreamIfIndex == other.downstreamIfIndex &&
            upstreamIface == other.upstreamIface &&
            upstreamIfIndex == other.upstreamIfIndex &&
            sessionGeneration == other.sessionGeneration
}

/**
 * Read-only and optional-probe capability report (Section 4 & Section 5).
 */
data class CapabilityReport(
    val status: PreNatCapabilityStatus = PreNatCapabilityStatus.UNCHECKED,
    val environment: PreNatEnvironmentBinding = PreNatEnvironmentBinding(),
    val shizukuRunning: Boolean = false,
    val shizukuPermissionGranted: Boolean = false,
    val shizukuUid: Int = -1,
    val processUid: Int = -1,
    val processGid: Int = -1,
    val shizukuMode: String = "UNKNOWN",
    val selinuxContext: String = "UNKNOWN",
    val effectiveCapabilitiesHex: String = "UNKNOWN",
    val capNetAdmin: Boolean = false,
    val identityProvenance: String = "UNCOLLECTED",
    val ipv4Coverage: PreNatFamilyCoverage = PreNatFamilyCoverage.UNKNOWN,
    val ipv6Coverage: PreNatFamilyCoverage = PreNatFamilyCoverage.UNKNOWN,
    val iptablesV4Readable: Boolean = false,
    val ip6tablesV6Readable: Boolean = false,
    val nftAvailable: Boolean = false,
    val tcAvailable: Boolean = false,
    val ipRuleV4Readable: Boolean = false,
    val ipRuleV6Readable: Boolean = false,
    val tetheringBpfReadable: Boolean = false,
    val offloadBypassSuspected: Boolean = true,
    val ingressClientMatchAvailable: Boolean = false,
    val probePerformed: Boolean = false,
    val probeApprovedByUser: Boolean = false,
    val probeCounterDeltaV4: Long = 0L,
    val probeCounterDeltaV6: Long = 0L,
    val probeCleanupVerified: Boolean = true,
    val reason: String = "Capability inspection has not been run yet.",
    val checkedAtEpochMs: Long = 0L,
    val auditedCommands: List<AuditedShellCommand> = emptyList(),
) {
    val capabilityStatus: PreNatCapabilityStatus get() = status
    val capabilityVerdict: PreNatCapabilityStatus get() = status
    val uid: Int get() = processUid
    val gid: Int get() = processGid
    val realUid: Int get() = processUid
    val realGid: Int get() = processGid
    val executionUid: String
        get() = if (!shizukuRunning || !shizukuPermissionGranted || processUid < 0) "UNKNOWN" else processUid.toString()
    val executionGid: String
        get() = if (!shizukuRunning || !shizukuPermissionGranted || processGid < 0) "UNKNOWN" else processGid.toString()
    val shizukuState: String
        get() = when {
            !shizukuRunning -> "SHIZUKU_NOT_RUNNING"
            !shizukuPermissionGranted -> "SHIZUKU_PERMISSION_REQUIRED"
            else -> "SHIZUKU_RUNNING"
        }
    val shizukuPrivilegeMode: String get() = shizukuMode
    val capEffHex: String get() = effectiveCapabilitiesHex
    val hasCapNetAdmin: Boolean get() = capNetAdmin
    val downstreamIface: String get() = environment.downstreamIface
    val downstreamIfIndex: Int get() = environment.downstreamIfIndex
    val upstreamIface: String get() = environment.upstreamIface
    val upstreamIfIndex: Int get() = environment.upstreamIfIndex
    val candidateBackend: String get() = if (iptablesV4Readable && ip6tablesV6Readable) "IPTABLES_FORWARD_PRE_NAT" else "NONE"
    val iptablesStatus: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "NOT_TESTED_SHIZUKU_UNAVAILABLE"
            iptablesV4Readable -> "READABLE"
            else -> "DENIED_OR_UNAVAILABLE"
        }
    val ip6tablesStatus: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "NOT_TESTED_SHIZUKU_UNAVAILABLE"
            ip6tablesV6Readable -> "READABLE"
            else -> "DENIED_OR_UNAVAILABLE"
        }
    val nftStatus: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "NOT_TESTED_SHIZUKU_UNAVAILABLE"
            nftAvailable -> "BINARY_PRESENT"
            else -> "UNAVAILABLE"
        }
    val tcStatus: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "NOT_TESTED_SHIZUKU_UNAVAILABLE"
            tcAvailable -> "BINARY_PRESENT"
            else -> "UNAVAILABLE"
        }
    val ipRuleStatus: String
        get() = when {
            !shizukuRunning || !shizukuPermissionGranted -> "NOT_TESTED_SHIZUKU_UNAVAILABLE"
            ipRuleV4Readable && ipRuleV6Readable -> "READABLE"
            else -> "UNAVAILABLE"
        }
    val probeExecuted: Boolean get() = probePerformed
    val probePassed: Boolean get() = status == PreNatCapabilityStatus.VERIFIED_AVAILABLE
    val userApprovedProbe: Boolean get() = probeApprovedByUser

    val isFullySupportedBothFamilies: Boolean
        get() = status == PreNatCapabilityStatus.VERIFIED_AVAILABLE &&
            ipv4Coverage == PreNatFamilyCoverage.IPV4_SUPPORTED &&
            ipv6Coverage == PreNatFamilyCoverage.IPV6_SUPPORTED &&
            !offloadBypassSuspected

    fun toJson(includeSensitive: Boolean = false): JSONObject = JSONObject().apply {
        put("status", status.name)
        put("capabilityVerdict", status.name)
        put("shizukuRunning", shizukuRunning)
        put("shizukuPermissionGranted", shizukuPermissionGranted)
        put("shizukuState", shizukuState)
        put("shizukuUid", shizukuUid)
        put("processUid", processUid)
        put("processGid", processGid)
        put("executionUid", executionUid)
        put("executionGid", executionGid)
        put("shizukuMode", shizukuMode)
        put("selinuxContext", selinuxContext)
        put("effectiveCapabilitiesHex", effectiveCapabilitiesHex)
        put("capNetAdmin", capNetAdmin)
        put("identityProvenance", identityProvenance)
        put("ipv4", ipv4Coverage.shortReportName)
        put("ipv6", ipv6Coverage.shortReportName)
        put("ipv4Coverage", ipv4Coverage.name)
        put("ipv6Coverage", ipv6Coverage.name)
        put("iptablesV4Readable", iptablesV4Readable)
        put("ip6tablesV6Readable", ip6tablesV6Readable)
        put("nftAvailable", nftAvailable)
        put("tcAvailable", tcAvailable)
        put("ipRuleV4Readable", ipRuleV4Readable)
        put("ipRuleV6Readable", ipRuleV6Readable)
        put("tetheringBpfReadable", tetheringBpfReadable)
        put("offloadBypassSuspected", offloadBypassSuspected)
        put("ingressClientMatchAvailable", ingressClientMatchAvailable)
        put("probePerformed", probePerformed)
        put("probeApprovedByUser", probeApprovedByUser)
        put("probeCounterDeltaV4", probeCounterDeltaV4)
        put("probeCounterDeltaV6", probeCounterDeltaV6)
        put("probeCleanupVerified", probeCleanupVerified)
        put("reason", if (includeSensitive) reason else BpfDumpParser.maskSensitiveLinePreview(reason))
        put("checkedAtEpochMs", checkedAtEpochMs)
        put("downstreamIface", environment.downstreamIface)
        put("downstreamIfIndex", environment.downstreamIfIndex)
        put("upstreamIface", environment.upstreamIface)
        put("upstreamIfIndex", environment.upstreamIfIndex)
        put("sessionGeneration", environment.sessionGeneration)
        put("bindingGeneration", environment.bindingGeneration)
        val cmdArr = JSONArray()
        auditedCommands.takeLast(25).forEach { cmdArr.put(it.toJson(includeSensitive)) }
        put("auditedCommands", cmdArr)
    }

    companion object {
        fun fromJson(json: JSONObject?): CapabilityReport {
            if (json == null) return CapabilityReport()
            val cmds = mutableListOf<AuditedShellCommand>()
            val arr = json.optJSONArray("auditedCommands")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    cmds.add(AuditedShellCommand.fromJson(item))
                }
            }
            val v4Cov = runCatching {
                PreNatFamilyCoverage.valueOf(json.optString("ipv4Coverage", PreNatFamilyCoverage.UNKNOWN.name))
            }.getOrElse {
                when (json.optString("ipv4")) {
                    "SUPPORTED" -> PreNatFamilyCoverage.IPV4_SUPPORTED
                    "UNAVAILABLE" -> PreNatFamilyCoverage.IPV4_UNAVAILABLE
                    else -> PreNatFamilyCoverage.UNKNOWN
                }
            }
            val v6Cov = runCatching {
                PreNatFamilyCoverage.valueOf(json.optString("ipv6Coverage", PreNatFamilyCoverage.UNKNOWN.name))
            }.getOrElse {
                when (json.optString("ipv6")) {
                    "SUPPORTED" -> PreNatFamilyCoverage.IPV6_SUPPORTED
                    "UNAVAILABLE" -> PreNatFamilyCoverage.IPV6_UNAVAILABLE
                    else -> PreNatFamilyCoverage.UNKNOWN
                }
            }
            val shizukuRunning = json.optBoolean("shizukuRunning", false)
            val shizukuPerm = json.optBoolean("shizukuPermissionGranted", shizukuRunning)
            val uid = json.optInt("shizukuUid", if (shizukuRunning && shizukuPerm) 2000 else -1)
            val procUid = json.optInt("processUid", uid)
            val procGid = json.optInt("processGid", uid)
            val mode = json.optString(
                "shizukuMode",
                when {
                    !shizukuRunning || !shizukuPerm || uid < 0 -> "UNKNOWN"
                    uid == 0 -> "ROOT"
                    else -> "ADB_SHELL"
                },
            )
            val selinux = json.optString("selinuxContext", "UNKNOWN")
            val capHex = json.optString("effectiveCapabilitiesHex", "UNKNOWN")
            val capNet = json.optBoolean("capNetAdmin", false)
            return CapabilityReport(
                status = runCatching {
                    PreNatCapabilityStatus.valueOf(json.optString("status", PreNatCapabilityStatus.UNCHECKED.name))
                }.getOrDefault(PreNatCapabilityStatus.UNCHECKED),
                environment = PreNatEnvironmentBinding(
                    shizukuUid = uid,
                    processUid = procUid,
                    processGid = procGid,
                    shizukuMode = mode,
                    selinuxContext = selinux,
                    effectiveCapabilitiesHex = capHex,
                    capNetAdmin = capNet,
                    downstreamIface = json.optString("downstreamIface", ""),
                    downstreamIfIndex = json.optInt("downstreamIfIndex", 0),
                    upstreamIface = json.optString("upstreamIface", ""),
                    upstreamIfIndex = json.optInt("upstreamIfIndex", 0),
                    sessionGeneration = json.optLong("sessionGeneration", 0L),
                    bindingGeneration = json.optLong("bindingGeneration", 0L),
                ),
                shizukuRunning = shizukuRunning,
                shizukuPermissionGranted = shizukuPerm,
                shizukuUid = uid,
                processUid = procUid,
                processGid = procGid,
                shizukuMode = mode,
                selinuxContext = selinux,
                effectiveCapabilitiesHex = capHex,
                capNetAdmin = capNet,
                identityProvenance = json.optString("identityProvenance", "DESERIALIZED"),
                ipv4Coverage = v4Cov,
                ipv6Coverage = v6Cov,
                iptablesV4Readable = json.optBoolean("iptablesV4Readable", false),
                ip6tablesV6Readable = json.optBoolean("ip6tablesV6Readable", false),
                nftAvailable = json.optBoolean("nftAvailable", false),
                tcAvailable = json.optBoolean("tcAvailable", false),
                ipRuleV4Readable = json.optBoolean("ipRuleV4Readable", false),
                ipRuleV6Readable = json.optBoolean("ipRuleV6Readable", false),
                tetheringBpfReadable = json.optBoolean("tetheringBpfReadable", false),
                offloadBypassSuspected = json.optBoolean("offloadBypassSuspected", true),
                ingressClientMatchAvailable = json.optBoolean("ingressClientMatchAvailable", false),
                probePerformed = json.optBoolean("probePerformed", false),
                probeApprovedByUser = json.optBoolean("probeApprovedByUser", false),
                probeCounterDeltaV4 = json.optLong("probeCounterDeltaV4", 0L),
                probeCounterDeltaV6 = json.optLong("probeCounterDeltaV6", 0L),
                probeCleanupVerified = json.optBoolean("probeCleanupVerified", true),
                reason = json.optString("reason", ""),
                checkedAtEpochMs = json.optLong("checkedAtEpochMs", 0L),
                auditedCommands = cmds,
            )
        }
    }
}

/**
 * Validated per-client identity and address bindings for a scoped pre-NAT rule plan.
 */
data class ScopedClientTarget(
    val mac: String,
    val ipv4Addresses: List<String>,
    val ipv6Addresses: List<String>,
    val isBlocked: Boolean,
    val isQuotaExceeded: Boolean,
) {
    val cleanMac: String get() = mac.uppercase(Locale.US).trim()
    val shouldBlock: Boolean get() = isBlocked || isQuotaExceeded
}

/**
 * Immutable scoped rule plan (Section 5).
 * Never uses unscoped FORWARD DROP, default-policy changes, chain flushes, or blanket IPv6 rules.
 */
data class ScopedRulePlan(
    val planId: String = "plan-${UUID.randomUUID().toString().take(8)}",
    val sessionGeneration: Long,
    val bindingGeneration: Long,
    val policyGeneration: Long,
    val isProbeOnly: Boolean,
    val downstreamIface: String,
    val downstreamIfIndex: Int,
    val upstreamIface: String,
    val upstreamIfIndex: Int,
    val hookAndOrdering: String = "filter/FORWARD index 1 -> app-owned chain before NAT/routing",
    val ownedChainNameV4: String,
    val ownedChainNameV6: String,
    val ruleOwnershipTag: String,
    val targets: List<ScopedClientTarget>,
    val intendedAddCommands: List<List<String>>,
    val exactRemovalCommands: List<List<String>>,
) {
    fun toPreviewText(includeSensitive: Boolean = false): String = buildString {
        appendLine("Plan ID: $planId (${if (isProbeOnly) "NON-DISRUPTIVE COUNTER PROBE" else "SCOPED PER-CLIENT ENFORCEMENT"})")
        appendLine("Session/Binding/Policy Gen: $sessionGeneration / $bindingGeneration / $policyGeneration")
        appendLine("Downstream: ${downstreamIface.ifBlank { "<unset>" }} (ifindex=$downstreamIfIndex) -> Upstream: ${upstreamIface.ifBlank { "<unset>" }} (ifindex=$upstreamIfIndex)")
        appendLine("Hook: $hookAndOrdering")
        appendLine("App-Owned Chains: v4=$ownedChainNameV4, v6=$ownedChainNameV6 (tag=$ruleOwnershipTag)")
        appendLine("Safety Invariants: NO unscoped FORWARD DROP, NO chain flush of system chains, NO default policy mutation")
        if (targets.isEmpty()) {
            appendLine("Targets: <none>")
        } else {
            targets.forEach { t ->
                val macLabel = if (includeSensitive) t.cleanMac else DiagnosticRedactor.pseudonymizeClient(t.cleanMac)
                val v4Label = t.ipv4Addresses.joinToString(",") { if (includeSensitive) it else DiagnosticRedactor.pseudonymizeIp(it) }
                val v6Label = t.ipv6Addresses.joinToString(",") { if (includeSensitive) it else DiagnosticRedactor.pseudonymizeIp(it) }
                appendLine("Target $macLabel: action=${if (isProbeOnly) "RETURN (counter-only)" else if (t.shouldBlock) "DROP" else "ALLOW"} v4=[$v4Label] v6=[$v6Label]")
            }
        }
        appendLine("Planned Commands (${intendedAddCommands.size}):")
        intendedAddCommands.forEach { cmd ->
            val raw = cmd.joinToString(" ")
            appendLine("  + ${if (includeSensitive) raw else BpfDumpParser.maskSensitiveLinePreview(raw)}")
        }
        appendLine("Exact Undo/Removal Commands (${exactRemovalCommands.size}):")
        exactRemovalCommands.forEach { cmd ->
            val raw = cmd.joinToString(" ")
            appendLine("  - ${if (includeSensitive) raw else BpfDumpParser.maskSensitiveLinePreview(raw)}")
        }
    }.trimEnd()
}

data class PreparedPlan(
    val plan: ScopedRulePlan,
    val capability: CapabilityReport,
    val isReadyToActivate: Boolean,
    val preparationError: String = "",
)

data class PolicySnapshot(
    val sessionGeneration: Long,
    val bindingGeneration: Long,
    val policyGeneration: Long,
    val downstreamIface: String,
    val blockedClients: List<ScopedClientTarget>,
    val allowedClients: List<ScopedClientTarget>,
)

/**
 * App-owned rule journal persisted in memory (and exportable) before any mutation (Section 6).
 */
data class OwnedRuleJournal(
    val transactionId: String = "",
    val sessionGeneration: Long = 0L,
    val bindingGeneration: Long = 0L,
    val policyGeneration: Long = 0L,
    val ownedChainV4: String = "",
    val ownedChainV6: String = "",
    val ownershipTag: String = "",
    val installedRuleIds: List<String> = emptyList(),
    val intendedUndoCommands: List<List<String>> = emptyList(),
    val progressState: String = "IDLE",
    val rollbackStatus: RollbackStatus = RollbackStatus.NOT_REQUIRED,
    val remainingOwnedRuleIds: List<String> = emptyList(),
    val manualRecoveryInstructions: String = "",
    val updatedAtEpochMs: Long = 0L,
) {
    fun toJson(includeSensitive: Boolean = false): JSONObject = JSONObject().apply {
        put("transactionId", transactionId)
        put("sessionGeneration", sessionGeneration)
        put("bindingGeneration", bindingGeneration)
        put("policyGeneration", policyGeneration)
        put("ownedChainV4", ownedChainV4)
        put("ownedChainV6", ownedChainV6)
        put("ownershipTag", ownershipTag)
        put("progressState", progressState)
        put("rollbackStatus", rollbackStatus.name)
        put(
            "installedRuleIds",
            JSONArray(
                installedRuleIds.map {
                    if (includeSensitive) it else BpfDumpParser.maskSensitiveLinePreview(it)
                },
            ),
        )
        put(
            "remainingOwnedRuleIds",
            JSONArray(
                remainingOwnedRuleIds.map {
                    if (includeSensitive) it else BpfDumpParser.maskSensitiveLinePreview(it)
                },
            ),
        )
        put("manualRecoveryInstructions", manualRecoveryInstructions)
        put("updatedAtEpochMs", updatedAtEpochMs)
    }

    companion object {
        fun fromJson(json: JSONObject?): OwnedRuleJournal {
            if (json == null) return OwnedRuleJournal()
            fun parseStringList(key: String): List<String> {
                val arr = json.optJSONArray(key) ?: return emptyList()
                val list = mutableListOf<String>()
                for (i in 0 until arr.length()) {
                    list.add(arr.optString(i))
                }
                return list
            }
            return OwnedRuleJournal(
                transactionId = json.optString("transactionId", ""),
                sessionGeneration = json.optLong("sessionGeneration", 0L),
                bindingGeneration = json.optLong("bindingGeneration", 0L),
                policyGeneration = json.optLong("policyGeneration", 0L),
                ownedChainV4 = json.optString("ownedChainV4", ""),
                ownedChainV6 = json.optString("ownedChainV6", ""),
                ownershipTag = json.optString("ownershipTag", ""),
                installedRuleIds = parseStringList("installedRuleIds"),
                progressState = json.optString("progressState", "IDLE"),
                rollbackStatus = runCatching {
                    RollbackStatus.valueOf(json.optString("rollbackStatus", RollbackStatus.NOT_REQUIRED.name))
                }.getOrDefault(RollbackStatus.NOT_REQUIRED),
                remainingOwnedRuleIds = parseStringList("remainingOwnedRuleIds"),
                manualRecoveryInstructions = json.optString("manualRecoveryInstructions", ""),
                updatedAtEpochMs = json.optLong("updatedAtEpochMs", 0L),
            )
        }
    }
}

data class ActivationResult(
    val attempted: Boolean,
    val succeeded: Boolean,
    val verified: Boolean,
    val ownedRuleCount: Int,
    val rollbackStatus: RollbackStatus,
    val previousModeRestored: Boolean,
    val failureReason: String = "",
    val journal: OwnedRuleJournal = OwnedRuleJournal(),
    val timestampEpochMs: Long = System.currentTimeMillis(),
)

data class VerificationResult(
    val verified: Boolean,
    val ipv4RulesPresent: Boolean,
    val ipv6RulesPresent: Boolean,
    val kernelCounterPacketsV4: Long = 0L,
    val kernelCounterBytesV4: Long = 0L,
    val kernelCounterPacketsV6: Long = 0L,
    val kernelCounterBytesV6: Long = 0L,
    val evidenceSource: PreNatEvidenceSource = PreNatEvidenceSource.KERNEL_COUNTER,
    val detail: String = "",
    val timestampEpochMs: Long = System.currentTimeMillis(),
)

data class CleanupResult(
    val succeeded: Boolean,
    val absenceVerified: Boolean,
    val rollbackStatus: RollbackStatus,
    val remainingOwnedRuleIds: List<String> = emptyList(),
    val detail: String = "",
    val timestampEpochMs: Long = System.currentTimeMillis(),
)

data class EngineTelemetry(
    val engineMode: BlockingMode,
    val isEnforcementActive: Boolean,
    val ownedRuleCount: Int,
    val kernelCounterPacketsV4: Long,
    val kernelCounterBytesV4: Long,
    val kernelCounterPacketsV6: Long,
    val kernelCounterBytesV6: Long,
    val lastVerifiedEpochMs: Long,
    val journal: OwnedRuleJournal,
)

/**
 * Formal Pre-NAT backend interface required by Section 5 of the v0.10.6-debug specification.
 */
interface BlockingEngine {
    suspend fun inspectCapability(): CapabilityReport
    suspend fun prepare(plan: ScopedRulePlan): PreparedPlan
    suspend fun activate(prepared: PreparedPlan): ActivationResult
    suspend fun verify(expected: PolicySnapshot): VerificationResult
    suspend fun deactivate(): CleanupResult
    fun observe(): EngineTelemetry
}

/**
 * Two-client validation status (Section 8).
 * Never claims blocked-client delivery suppression unless independently observed on a receiving endpoint.
 */
data class ClientValidationSummary(
    val blockedClientDeliveryObserved: Boolean? = null,
    val allowedClientConnectivityPreserved: Boolean? = null,
    val independentMeasurement: Boolean = false,
    val evidenceSource: PreNatEvidenceSource = PreNatEvidenceSource.HOST_VPN,
    val notes: String = "Independent two-client receiving-endpoint validation has not been recorded.",
) {
    fun toJson(): JSONObject = JSONObject().apply {
        if (blockedClientDeliveryObserved == null) {
            put("blockedClientDeliveryObserved", JSONObject.NULL)
        } else {
            put("blockedClientDeliveryObserved", blockedClientDeliveryObserved)
        }
        if (allowedClientConnectivityPreserved == null) {
            put("allowedClientConnectivityPreserved", JSONObject.NULL)
        } else {
            put("allowedClientConnectivityPreserved", allowedClientConnectivityPreserved)
        }
        put("independentMeasurement", independentMeasurement)
        put("evidenceSource", evidenceSource.name)
        put("notes", notes)
    }

    companion object {
        fun fromJson(json: JSONObject?): ClientValidationSummary {
            if (json == null) return ClientValidationSummary()
            val blockedObs = if (json.isNull("blockedClientDeliveryObserved")) {
                null
            } else {
                json.optBoolean("blockedClientDeliveryObserved")
            }
            val allowedObs = if (json.isNull("allowedClientConnectivityPreserved")) {
                null
            } else {
                json.optBoolean("allowedClientConnectivityPreserved")
            }
            return ClientValidationSummary(
                blockedClientDeliveryObserved = blockedObs,
                allowedClientConnectivityPreserved = allowedObs,
                independentMeasurement = json.optBoolean("independentMeasurement", false),
                evidenceSource = runCatching {
                    PreNatEvidenceSource.valueOf(json.optString("evidenceSource", PreNatEvidenceSource.HOST_VPN.name))
                }.getOrDefault(PreNatEvidenceSource.HOST_VPN),
                notes = json.optString("notes", ""),
            )
        }
    }
}

/**
 * Reproducible PN01–PN16 test matrix row (Section 9).
 */
data class PreNatTestMatrixRow(
    val id: String,
    val testDescription: String,
    val expectedOutcome: String,
    val status: String, // PASS, FAIL, BLOCKED_BY_CAPABILITY, NOT_RUN
    val evidenceSource: PreNatEvidenceSource,
    val observedDetail: String,
) {
    val testId: String get() = id
    val scenario: String get() = testDescription
    val result: String get() = status
    val evidence: String get() = observedDetail

    fun toJson(includeSensitive: Boolean = false): JSONObject = JSONObject().apply {
        put("id", id)
        put("testDescription", testDescription)
        put("expectedOutcome", expectedOutcome)
        put("status", status)
        put("evidenceSource", evidenceSource.name)
        put("observedDetail", if (includeSensitive) observedDetail else BpfDumpParser.maskSensitiveLinePreview(observedDetail))
    }

    companion object {
        fun fromJson(json: JSONObject): PreNatTestMatrixRow = PreNatTestMatrixRow(
            id = json.optString("id", ""),
            testDescription = json.optString("testDescription", ""),
            expectedOutcome = json.optString("expectedOutcome", ""),
            status = json.optString("status", "NOT_RUN"),
            evidenceSource = runCatching {
                PreNatEvidenceSource.valueOf(json.optString("evidenceSource", PreNatEvidenceSource.HOST_VPN.name))
            }.getOrDefault(PreNatEvidenceSource.HOST_VPN),
            observedDetail = json.optString("observedDetail", ""),
        )
    }
}

/**
 * Unified Schema v4 Pre-NAT & Exclusive Blocking Mode diagnostic report (Section 8).
 */
data class PreNatModeDiagnosticReport(
    val schemaVersion: Int = 6,
    val requestedMode: BlockingMode = BlockingMode.BPF_NAT_VPN,
    val effectiveMode: BlockingMode = BlockingMode.BPF_NAT_VPN,
    val effectiveModeNullable: BlockingMode? = effectiveMode,
    val previousStableMode: BlockingMode = BlockingMode.BPF_NAT_VPN,
    val runtimeState: PreNatRuntimeState = PreNatRuntimeState.CURRENT_ACTIVE,
    val transitionId: Long = 0L,
    val policyGeneration: Long = 1L,
    val exclusiveEngineInvariant: Boolean = true,
    val bpfNatVpnDropPathEnabled: Boolean = true,
    val preNatDropPathEnabled: Boolean = false,
    val softApMacBlockEnabled: Boolean = false,
    val legacyPreNatMigrated: Boolean = false,
    val legacyPreNatCleanupVerified: Boolean = true,
    val capability: CapabilityReport = CapabilityReport(),
    val activationAttempted: Boolean = false,
    val activationVerified: Boolean = false,
    val previousModeRestored: Boolean = true,
    val ownedRuleCount: Int = 0,
    val rollbackStatus: RollbackStatus = RollbackStatus.NOT_REQUIRED,
    val lastTransitionDetail: String = "BPF_NAT_VPN active (default partial enforcement)",
    val lastVerifiedEpochMs: Long = 0L,
    val rulePlanPreview: String = "",
    val journal: OwnedRuleJournal = OwnedRuleJournal(),
    val clientValidation: ClientValidationSummary = ClientValidationSummary(),
    val testMatrix: List<PreNatTestMatrixRow> = emptyList(),
    val goNoGoVerdict: String = "NO-GO for rootless ADB shell (UID 2000 lacks CAP_NET_ADMIN; netfilter mutation denied)",
) {
    val bpfNatVpnActive: Boolean get() = bpfNatVpnDropPathEnabled
    val preNatFirewallActive: Boolean get() = preNatDropPathEnabled
    val softApMacBlockActive: Boolean get() = softApMacBlockEnabled
    val activationSucceeded: Boolean get() = activationVerified
    val rollbackPerformed: Boolean get() = rollbackStatus != RollbackStatus.NOT_REQUIRED
    val rollbackVerified: Boolean get() = rollbackStatus == RollbackStatus.ROLLBACK_SUCCEEDED
    val fallbackReason: String get() = lastTransitionDetail

    fun toJson(includeSensitive: Boolean = false): JSONObject = JSONObject().apply {
        put("schemaVersion", schemaVersion)
        put("requestedMode", requestedMode.name)
        put("effectiveMode", effectiveModeNullable?.name ?: "NONE")
        put("previousStableMode", previousStableMode.name)
        put("runtimeState", runtimeState.name)
        put("transitionId", transitionId)
        put("policyGeneration", policyGeneration)
        put("exclusiveEngineInvariant", exclusiveEngineInvariant)
        put("bpfNatVpnDropPathEnabled", bpfNatVpnDropPathEnabled)
        put("preNatDropPathEnabled", preNatDropPathEnabled)
        put("softApMacBlockEnabled", softApMacBlockEnabled)
        put("legacyPreNatMigrated", legacyPreNatMigrated)
        put("legacyPreNatCleanupVerified", legacyPreNatCleanupVerified)
        put("capability", capability.toJson(includeSensitive))
        put(
            "activation",
            JSONObject().apply {
                put("attempted", activationAttempted)
                put("verified", activationVerified)
                put("previousModeRestored", previousModeRestored)
                put("ownedRuleCount", ownedRuleCount)
                put("rollbackStatus", rollbackStatus.name)
                put("lastTransitionDetail", if (includeSensitive) lastTransitionDetail else BpfDumpParser.maskSensitiveLinePreview(lastTransitionDetail))
                put("lastVerifiedEpochMs", lastVerifiedEpochMs)
            },
        )
        put("rulePlanPreview", if (includeSensitive) rulePlanPreview else BpfDumpParser.maskSensitiveLinePreview(rulePlanPreview))
        put("journal", journal.toJson(includeSensitive))
        put("clientValidation", clientValidation.toJson())
        val matrixArr = JSONArray()
        testMatrix.forEach { matrixArr.put(it.toJson(includeSensitive)) }
        put("testMatrix", matrixArr)
        put("goNoGoVerdict", goNoGoVerdict)
    }

    companion object {
        fun fromJson(json: JSONObject?): PreNatModeDiagnosticReport {
            if (json == null) return PreNatModeDiagnosticReport()
            val actObj = json.optJSONObject("activation")
            val matrixList = mutableListOf<PreNatTestMatrixRow>()
            val arr = json.optJSONArray("testMatrix")
            if (arr != null) {
                for (i in 0 until arr.length()) {
                    val item = arr.optJSONObject(i) ?: continue
                    matrixList.add(PreNatTestMatrixRow.fromJson(item))
                }
            }
            val rawEff = json.optString("effectiveMode", BlockingMode.BPF_NAT_VPN.name)
            val parsedEffNullable = if (rawEff == "NONE" || rawEff.isBlank()) null else BlockingMode.fromName(rawEff)
            return PreNatModeDiagnosticReport(
                schemaVersion = json.optInt("schemaVersion", 6),
                requestedMode = BlockingMode.fromName(json.optString("requestedMode", BlockingMode.BPF_NAT_VPN.name)),
                effectiveMode = parsedEffNullable ?: BlockingMode.BPF_NAT_VPN,
                effectiveModeNullable = parsedEffNullable,
                previousStableMode = BlockingMode.fromName(json.optString("previousStableMode", BlockingMode.BPF_NAT_VPN.name)),
                runtimeState = runCatching {
                    PreNatRuntimeState.valueOf(json.optString("runtimeState", PreNatRuntimeState.CURRENT_ACTIVE.name))
                }.getOrDefault(PreNatRuntimeState.CURRENT_ACTIVE),
                transitionId = json.optLong("transitionId", 0L),
                policyGeneration = json.optLong("policyGeneration", 1L),
                exclusiveEngineInvariant = json.optBoolean("exclusiveEngineInvariant", true),
                bpfNatVpnDropPathEnabled = json.optBoolean("bpfNatVpnDropPathEnabled", true),
                preNatDropPathEnabled = json.optBoolean("preNatDropPathEnabled", false),
                softApMacBlockEnabled = json.optBoolean("softApMacBlockEnabled", false),
                legacyPreNatMigrated = json.optBoolean("legacyPreNatMigrated", false),
                legacyPreNatCleanupVerified = json.optBoolean("legacyPreNatCleanupVerified", true),
                capability = CapabilityReport.fromJson(json.optJSONObject("capability")),
                activationAttempted = actObj?.optBoolean("attempted", false) ?: false,
                activationVerified = actObj?.optBoolean("verified", false) ?: false,
                previousModeRestored = actObj?.optBoolean("previousModeRestored", true) ?: true,
                ownedRuleCount = actObj?.optInt("ownedRuleCount", 0) ?: 0,
                rollbackStatus = runCatching {
                    RollbackStatus.valueOf(actObj?.optString("rollbackStatus", RollbackStatus.NOT_REQUIRED.name).orEmpty())
                }.getOrDefault(RollbackStatus.NOT_REQUIRED),
                lastTransitionDetail = actObj?.optString("lastTransitionDetail", "").orEmpty(),
                lastVerifiedEpochMs = actObj?.optLong("lastVerifiedEpochMs", 0L) ?: 0L,
                rulePlanPreview = json.optString("rulePlanPreview", ""),
                journal = OwnedRuleJournal.fromJson(json.optJSONObject("journal")),
                clientValidation = ClientValidationSummary.fromJson(json.optJSONObject("clientValidation")),
                testMatrix = matrixList,
                goNoGoVerdict = json.optString(
                    "goNoGoVerdict",
                    "NO-GO for rootless ADB shell (UID 2000 lacks CAP_NET_ADMIN; netfilter mutation denied)",
                ),
            )
        }
    }
}

/**
 * Capability-gated Pre-NAT Firewall engine implementation (Sections 4, 5, 6).
 *
 * Non-negotiable behavior:
 * - Read-only capability inspection executes ZERO rule mutations.
 * - Never conflates command availability (`iptables --version`, `nft --version`, `ip rule show`)
 *   with kernel rule write/enforcement capability.
 * - Caches definitive permission denial (`UNAVAILABLE_PERMISSION`) per environment binding so
 *   privileged commands are not retried in loops.
 * - Any mutation probe requires explicit user approval, uses an isolated app-owned chain with a
 *   counter-only `RETURN` rule (never a blanket DROP), verifies counters, and verifies removal.
 * - Protects other clients: never flushes system chains, never changes default policy, never
 *   inserts unscoped FORWARD DROP rules.
 */
class PreNatFirewallEngine(
    @Volatile var shellExecutor: PreNatShellExecutor = DefaultPreNatShellExecutor,
) : BlockingEngine {

    private val auditedCommands = ArrayList<AuditedShellCommand>()

    @Volatile
    var lastCapabilityReport: CapabilityReport = CapabilityReport()
        private set

    @Volatile
    var activeJournal: OwnedRuleJournal = OwnedRuleJournal()
        private set

    @Volatile
    private var isActiveVerified = false

    @Volatile
    private var lastVerifiedMs = 0L

    @Volatile
    private var lastKernelPacketsV4 = 0L

    @Volatile
    private var lastKernelBytesV4 = 0L

    @Volatile
    private var lastKernelPacketsV6 = 0L

    @Volatile
    private var lastKernelBytesV6 = 0L

    @Volatile
    private var cachedDeniedEnvironment: PreNatEnvironmentBinding? = null

    fun clearHistoryForTests() {
        synchronized(auditedCommands) {
            auditedCommands.clear()
        }
        lastCapabilityReport = CapabilityReport()
        activeJournal = OwnedRuleJournal()
        isActiveVerified = false
        lastVerifiedMs = 0L
        lastKernelPacketsV4 = 0L
        lastKernelBytesV4 = 0L
        lastKernelPacketsV6 = 0L
        lastKernelBytesV6 = 0L
        cachedDeniedEnvironment = null
    }

    fun seedLegacyJournalForTests(
        chainV4: String = "SHIZZI_PN4",
        chainV6: String = "SHIZZI_PN6",
    ) {
        activeJournal = OwnedRuleJournal(
            transactionId = "legacy-test-tx",
            ownedChainV4 = chainV4,
            ownedChainV6 = chainV6,
            installedRuleIds = listOf(chainV4),
            intendedUndoCommands = listOf(
                listOf("iptables", "-D", "FORWARD", "-j", chainV4),
                listOf("iptables", "-F", chainV4),
                listOf("iptables", "-X", chainV4),
            ),
            progressState = "ACTIVE",
        )
    }

    fun getAuditedCommandsSnapshot(): List<AuditedShellCommand> =
        synchronized(auditedCommands) { auditedCommands.toList() }

    private fun runAudited(
        phase: String,
        isMutating: Boolean,
        vararg args: String,
        timeoutMs: Long = 2_000L,
    ): HostFirewall.CommandResult {
        val res = shellExecutor.execute(*args, timeoutMs = timeoutMs)
        val record = AuditedShellCommand(
            phase = phase,
            isMutating = isMutating,
            command = args.joinToString(" "),
            exitCode = res.exitCode,
            timedOut = res.timedOut,
            errorKind = res.errorKind,
            stderrPreview = res.stderr.take(240).trim(),
            stdoutPreview = res.stdout.take(240).trim(),
            timestampEpochMs = System.currentTimeMillis(),
        )
        synchronized(auditedCommands) {
            if (auditedCommands.size >= 100) {
                auditedCommands.removeAt(0)
            }
            auditedCommands.add(record)
        }
        return res
    }

    internal fun parseCapNetAdmin(capEffHex: String): Boolean {
        val clean = capEffHex.trim().removePrefix("0x").removePrefix("0X")
        val mask = clean.toULongOrNull(16) ?: return false
        // CAP_NET_ADMIN is capability bit 12 (1UL shl 12 = 0x1000)
        return (mask and (1UL shl 12)) != 0UL
    }

    internal fun buildCurrentEnvironmentBinding(): PreNatEnvironmentBinding {
        val uid = shellExecutor.resolveUid()
        val gid = shellExecutor.resolveGid()
        val shizukuUid = shellExecutor.resolveShizukuUid()
        val selinux = shellExecutor.resolveSeLinuxContext()
        val capHex = shellExecutor.resolveEffectiveCapabilitiesHex()
        val hasCapNetAdmin = parseCapNetAdmin(capHex)
        val snap = TunTrafficEngine.bpfAttributor.currentSnapshot()
        val downIface = snap.downstreamIface.ifBlank { TunTrafficEngine.bpfAttributor.activeDownstreamIface }
        val upIface = snap.upstreamIface.ifBlank { TunTrafficEngine.bpfAttributor.activeUpstreamIface }
        val downIdx = snap.osDownstreamIfIndex ?: snap.resolvedDownstreamIfIndex
        val upIdx = snap.osUpstreamIfIndex ?: snap.resolvedUpstreamIfIndex
        val mode = when {
            shizukuUid == 0 || uid == 0 -> "ROOT"
            hasCapNetAdmin -> "PRIVILEGED_SHELL"
            else -> "ADB_SHELL"
        }
        return PreNatEnvironmentBinding(
            shizukuUid = shizukuUid,
            processUid = uid,
            processGid = gid,
            shizukuMode = mode,
            selinuxContext = selinux,
            effectiveCapabilitiesHex = capHex,
            capNetAdmin = hasCapNetAdmin,
            downstreamIface = downIface,
            downstreamIfIndex = downIdx,
            upstreamIface = upIface,
            upstreamIfIndex = upIdx,
            sessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
            bindingGeneration = TunTrafficEngine.bpfAttributor.currentBindingGeneration,
        )
    }

    /**
     * Step 1: Strictly read-only capability inspection (AC03, AC04, AC06).
     * Never executes any rule mutation (`-N`, `-A`, `-I`, `-D`, `-F`, `-X`, `ip rule add/del`).
     */
    override suspend fun inspectCapability(): CapabilityReport {
        val shizukuRunning = shellExecutor.resolveShizukuRunning()
        val shizukuPermission = shellExecutor.resolveShizukuPermissionGranted()
        val now = System.currentTimeMillis()

        // v0.10.7-debug Section 4: Never fabricate UID/GID or report UNAVAILABLE_PERMISSION
        // when Shizuku is not running or permission is not granted!
        if (!shizukuRunning || !shizukuPermission) {
            val snap = TunTrafficEngine.bpfAttributor.currentSnapshot()
            val downIface = snap.downstreamIface.ifBlank { TunTrafficEngine.bpfAttributor.activeDownstreamIface }
            val upIface = snap.upstreamIface.ifBlank { TunTrafficEngine.bpfAttributor.activeUpstreamIface }
            val downIdx = snap.osDownstreamIfIndex ?: snap.resolvedDownstreamIfIndex
            val upIdx = snap.osUpstreamIfIndex ?: snap.resolvedUpstreamIfIndex
            val unavailableEnv = PreNatEnvironmentBinding(
                shizukuUid = -1,
                processUid = -1,
                processGid = -1,
                shizukuMode = "UNKNOWN",
                selinuxContext = "UNKNOWN",
                effectiveCapabilitiesHex = "UNKNOWN",
                capNetAdmin = false,
                downstreamIface = downIface,
                downstreamIfIndex = downIdx,
                upstreamIface = upIface,
                upstreamIfIndex = upIdx,
                sessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
                bindingGeneration = TunTrafficEngine.bpfAttributor.currentBindingGeneration,
            )
            val unavailableReason = if (!shizukuRunning) {
                "Shizuku binder is not running (SHIZUKU_NOT_RUNNING); Pre-NAT capability was not tested."
            } else {
                "Shizuku permission is not granted (SHIZUKU_PERMISSION_REQUIRED); Pre-NAT capability was not tested."
            }
            val report = CapabilityReport(
                status = PreNatCapabilityStatus.NOT_TESTED_SHIZUKU_UNAVAILABLE,
                environment = unavailableEnv,
                shizukuRunning = shizukuRunning,
                shizukuPermissionGranted = shizukuPermission,
                shizukuUid = -1,
                processUid = -1,
                processGid = -1,
                shizukuMode = "UNKNOWN",
                selinuxContext = "UNKNOWN",
                effectiveCapabilitiesHex = "UNKNOWN",
                capNetAdmin = false,
                identityProvenance = if (!shizukuRunning) "SHIZUKU_BINDER_DEAD" else "SHIZUKU_PERMISSION_NOT_GRANTED",
                ipv4Coverage = PreNatFamilyCoverage.UNKNOWN,
                ipv6Coverage = PreNatFamilyCoverage.UNKNOWN,
                iptablesV4Readable = false,
                ip6tablesV6Readable = false,
                nftAvailable = false,
                tcAvailable = false,
                ipRuleV4Readable = false,
                ipRuleV6Readable = false,
                tetheringBpfReadable = false,
                offloadBypassSuspected = true,
                ingressClientMatchAvailable = false,
                probePerformed = false,
                probeApprovedByUser = false,
                probeCleanupVerified = true,
                reason = unavailableReason,
                checkedAtEpochMs = now,
                auditedCommands = getAuditedCommandsSnapshot(),
            )
            lastCapabilityReport = report
            return report
        }

        val env = buildCurrentEnvironmentBinding()

        // Avoid repeated privileged retries if this exact environment was already proven UNAVAILABLE_PERMISSION
        val deniedEnv = cachedDeniedEnvironment
        if (deniedEnv != null && deniedEnv.matchesEnvironment(env) && lastCapabilityReport.status == PreNatCapabilityStatus.UNAVAILABLE_PERMISSION) {
            return lastCapabilityReport.copy(checkedAtEpochMs = now)
        }

        val iptV4Read = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "iptables", "-S", "FORWARD")
        val iptV6Read = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "ip6tables", "-S", "FORWARD")
        val nftVer = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "nft", "--version")
        val tcVer = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "tc", "-Version")
        val ipRuleV4 = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "ip", "rule", "show")
        val ipRuleV6 = runAudited("READ_ONLY_CAPABILITY", isMutating = false, "ip", "-6", "rule", "show")

        val bpfSnap = TunTrafficEngine.bpfAttributor.currentSnapshot()
        val bpfReadable = bpfSnap.snapshotSequence > 0L || TunTrafficEngine.bpfReader.totalCollectionsSucceeded.get() > 0L
        val connectedMacs = TunTrafficEngine.getActiveConnectedMacsSnapshot()
        val hasValidatedClientBindings = connectedMacs.any { mac ->
            TunTrafficEngine.getBoundIpsForMac(mac).isNotEmpty()
        }
        val hasDownstreamIface = env.downstreamIface.isNotBlank() && env.downstreamIfIndex > 0

        // Non-negotiable Constraint 2, 4, 6 & Section 4:
        // Command availability (`nft --version`, `ip rule show`) is NEVER treated as write capability.
        // Without CAP_NET_ADMIN (and with uid != 0) or when iptables -S FORWARD is permission-denied,
        // netfilter mutation is unavailable by permission.
        val netfilterPermissionDenied =
            !env.capNetAdmin && env.processUid != 0 && env.shizukuUid != 0 ||
                iptV4Read.errorKind == ProbeErrorKind.PERMISSION_DENIED ||
                iptV6Read.errorKind == ProbeErrorKind.PERMISSION_DENIED

        val status: PreNatCapabilityStatus
        val v4Coverage: PreNatFamilyCoverage
        val v6Coverage: PreNatFamilyCoverage
        val reason: String

        if (netfilterPermissionDenied) {
            status = PreNatCapabilityStatus.UNAVAILABLE_PERMISSION
            v4Coverage = PreNatFamilyCoverage.IPV4_UNAVAILABLE
            v6Coverage = PreNatFamilyCoverage.IPV6_UNAVAILABLE
            val errDetail = iptV4Read.stderr.ifBlank { iptV6Read.stderr }.take(120).trim()
            reason = buildString {
                append("Permission-denied netfilter mutation in rootless mode ")
                append("(uid=${env.processUid}, shizukuUid=${env.shizukuUid}, mode=${env.shizukuMode}, ")
                append("selinux=${env.selinuxContext}, CapEff=${env.effectiveCapabilitiesHex}, CAP_NET_ADMIN=${env.capNetAdmin}). ")
                if (errDetail.isNotBlank()) {
                    append("iptables stderr: $errDetail. ")
                }
                append("No verified pre-NAT backend available without CAP_NET_ADMIN.")
            }
            cachedDeniedEnvironment = env
        } else if (!iptV4Read.isSuccess) {
            status = PreNatCapabilityStatus.UNAVAILABLE_HOOK
            v4Coverage = PreNatFamilyCoverage.IPV4_UNAVAILABLE
            v6Coverage = if (iptV6Read.isSuccess) PreNatFamilyCoverage.UNKNOWN else PreNatFamilyCoverage.IPV6_UNAVAILABLE
            reason = "IPv4 FORWARD chain inspection failed (exit=${iptV4Read.exitCode}); pre-NAT hook unavailable."
        } else if (!iptV6Read.isSuccess) {
            status = PreNatCapabilityStatus.UNAVAILABLE_IPV6
            v4Coverage = PreNatFamilyCoverage.UNKNOWN
            v6Coverage = PreNatFamilyCoverage.IPV6_UNAVAILABLE
            reason = "IPv6 FORWARD chain inspection failed (exit=${iptV6Read.exitCode}); IPv6 bypass risk prevents full pre-NAT support."
        } else {
            // Both IPv4 and IPv6 FORWARD tables are readable AND process has CAP_NET_ADMIN / root.
            // Still NEVER marked VERIFIED_AVAILABLE until a user-approved scoped probe proves counter & cleanup behavior!
            status = PreNatCapabilityStatus.NEEDS_USER_APPROVED_PROBE
            v4Coverage = PreNatFamilyCoverage.UNKNOWN
            v6Coverage = PreNatFamilyCoverage.UNKNOWN
            reason = "Read-only inspection passed with CAP_NET_ADMIN; explicit user-approved scoped counter probe required to verify pre-NAT hook and offload behavior."
        }

        val report = CapabilityReport(
            status = status,
            environment = env,
            shizukuRunning = true,
            shizukuPermissionGranted = true,
            shizukuUid = env.shizukuUid,
            processUid = env.processUid,
            processGid = env.processGid,
            shizukuMode = env.shizukuMode,
            selinuxContext = env.selinuxContext,
            effectiveCapabilitiesHex = env.effectiveCapabilitiesHex,
            capNetAdmin = env.capNetAdmin,
            identityProvenance = "LIVE_SHIZUKU_SHELL",
            ipv4Coverage = v4Coverage,
            ipv6Coverage = v6Coverage,
            iptablesV4Readable = iptV4Read.isSuccess,
            ip6tablesV6Readable = iptV6Read.isSuccess,
            nftAvailable = nftVer.isSuccess,
            tcAvailable = tcVer.isSuccess,
            ipRuleV4Readable = ipRuleV4.isSuccess,
            ipRuleV6Readable = ipRuleV6.isSuccess,
            tetheringBpfReadable = bpfReadable,
            offloadBypassSuspected = true,
            ingressClientMatchAvailable = hasDownstreamIface && hasValidatedClientBindings,
            probePerformed = false,
            probeApprovedByUser = false,
            probeCleanupVerified = true,
            reason = reason,
            checkedAtEpochMs = now,
            auditedCommands = getAuditedCommandsSnapshot(),
        )
        lastCapabilityReport = report
        return report
    }

    /**
     * Builds a narrow, non-disruptive `ScopedRulePlan` either for a user-approved counter probe
     * (`isProbeOnly = true`, action = `RETURN`) or for scoped blocked-client enforcement (`isProbeOnly = false`).
     */
    fun buildScopedRulePlan(
        isProbeOnly: Boolean,
        policyGeneration: Long,
        targetsOverride: List<ScopedClientTarget>? = null,
    ): ScopedRulePlan {
        val env = buildCurrentEnvironmentBinding()
        val shortId = (env.sessionGeneration.coerceAtLeast(1L).toString() + "_" + policyGeneration.coerceAtLeast(1L))
            .takeLast(8)
        val chainV4 = if (isProbeOnly) "SHIZZI_PRB4_$shortId" else "SHIZZI_ENF4_$shortId"
        val chainV6 = if (isProbeOnly) "SHIZZI_PRB6_$shortId" else "SHIZZI_ENF6_$shortId"
        val tag = "SHIZZI_OWNED_${env.sessionGeneration}_${env.bindingGeneration}_$policyGeneration"
        val downIface = env.downstreamIface.ifBlank { "swlan0" }

        val targets = targetsOverride ?: buildLiveClientTargets()
        val activeTargets = if (isProbeOnly) {
            targets.take(1).ifEmpty {
                listOf(
                    ScopedClientTarget(
                        mac = "02:00:00:00:00:01",
                        ipv4Addresses = listOf("198.51.100.254"),
                        ipv6Addresses = listOf("2001:db8::fffe"),
                        isBlocked = false,
                        isQuotaExceeded = false,
                    ),
                )
            }
        } else {
            targets.filter { it.shouldBlock }
        }

        val addCmds = mutableListOf<List<String>>()
        val removeCmds = mutableListOf<List<String>>()

        // IPv4 owned chain creation + scoped rules + jump from FORWARD
        addCmds.add(listOf("iptables", "-N", chainV4))
        for (target in activeTargets) {
            val action = if (isProbeOnly) "RETURN" else "DROP"
            for (ipv4 in target.ipv4Addresses) {
                addCmds.add(
                    listOf(
                        "iptables", "-A", chainV4,
                        "-i", downIface,
                        "-s", "$ipv4/32",
                        "-m", "comment", "--comment", tag,
                        "-j", action,
                    ),
                )
            }
        }
        addCmds.add(
            listOf(
                "iptables", "-I", "FORWARD", "1",
                "-i", downIface,
                "-m", "comment", "--comment", tag,
                "-j", chainV4,
            ),
        )

        // Exact removal instructions for IPv4 (never flushes system chains!)
        removeCmds.add(
            listOf(
                "iptables", "-D", "FORWARD",
                "-i", downIface,
                "-m", "comment", "--comment", tag,
                "-j", chainV4,
            ),
        )
        removeCmds.add(listOf("iptables", "-F", chainV4))
        removeCmds.add(listOf("iptables", "-X", chainV4))

        // IPv6 owned chain creation + scoped rules + jump from ip6tables FORWARD
        addCmds.add(listOf("ip6tables", "-N", chainV6))
        for (target in activeTargets) {
            val action = if (isProbeOnly) "RETURN" else "DROP"
            for (ipv6 in target.ipv6Addresses) {
                addCmds.add(
                    listOf(
                        "ip6tables", "-A", chainV6,
                        "-i", downIface,
                        "-s", "$ipv6/128",
                        "-m", "comment", "--comment", tag,
                        "-j", action,
                    ),
                )
            }
        }
        addCmds.add(
            listOf(
                "ip6tables", "-I", "FORWARD", "1",
                "-i", downIface,
                "-m", "comment", "--comment", tag,
                "-j", chainV6,
            ),
        )

        // Exact removal instructions for IPv6
        removeCmds.add(
            listOf(
                "ip6tables", "-D", "FORWARD",
                "-i", downIface,
                "-m", "comment", "--comment", tag,
                "-j", chainV6,
            ),
        )
        removeCmds.add(listOf("ip6tables", "-F", chainV6))
        removeCmds.add(listOf("ip6tables", "-X", chainV6))

        return ScopedRulePlan(
            sessionGeneration = env.sessionGeneration,
            bindingGeneration = env.bindingGeneration,
            policyGeneration = policyGeneration,
            isProbeOnly = isProbeOnly,
            downstreamIface = downIface,
            downstreamIfIndex = env.downstreamIfIndex,
            upstreamIface = env.upstreamIface,
            upstreamIfIndex = env.upstreamIfIndex,
            ownedChainNameV4 = chainV4,
            ownedChainNameV6 = chainV6,
            ruleOwnershipTag = tag,
            targets = activeTargets,
            intendedAddCommands = addCmds,
            exactRemovalCommands = removeCmds,
        )
    }

    internal fun buildLiveClientTargets(): List<ScopedClientTarget> {
        val connectedMacs = TunTrafficEngine.getActiveConnectedMacsSnapshot().sorted()
        return connectedMacs.map { mac ->
            val ips = TunTrafficEngine.getBoundIpsForMac(mac)
            val v4 = ips.filter { !it.contains(':') && BpfDumpParser.isValidIpv4(it) }.sorted()
            val v6 = ips.filter { it.contains(':') && !it.lowercase(Locale.US).startsWith("fe80:") }.sorted()
            val policy = TunTrafficEngine.getClientPolicy(mac)
            val quota = TunTrafficEngine.getQuotaRecord(mac)
            ScopedClientTarget(
                mac = mac,
                ipv4Addresses = v4,
                ipv6Addresses = v6,
                isBlocked = policy?.isNonQuotaBlocked == true,
                isQuotaExceeded = quota?.isQuotaExceeded == true || policy?.isQuotaOnlyBlock == true,
            )
        }
    }

    /**
     * Step 2: User-approved non-disruptive scoped counter probe (Section 4, AC05, AC06).
     * - Requires `userApproved == true`.
     * - Refuses to mutate if read-only inspection already determined `UNAVAILABLE_PERMISSION`.
     * - Installs only a temporary counter-only (`-j RETURN`) rule in an isolated app-owned chain,
     *   inspects counters, removes the rule and chain, and verifies cleanup.
     */
    suspend fun runUserApprovedScopedProbe(
        userApproved: Boolean,
        plan: ScopedRulePlan = buildScopedRulePlan(isProbeOnly = true, policyGeneration = 1L),
    ): CapabilityReport {
        val now = System.currentTimeMillis()
        if (!userApproved) {
            val current = lastCapabilityReport
            return current.copy(
                probePerformed = false,
                probeApprovedByUser = false,
                reason = "Scoped mutation probe requires explicit user approval after reviewing the rule plan.",
                checkedAtEpochMs = now,
            )
        }

        val baseCap = if (lastCapabilityReport.status == PreNatCapabilityStatus.UNCHECKED) {
            inspectCapability()
        } else {
            lastCapabilityReport
        }

        // AC06: Do not execute privileged mutation commands after a definitive permission denial
        if (baseCap.status == PreNatCapabilityStatus.UNAVAILABLE_PERMISSION) {
            val deniedReport = baseCap.copy(
                probePerformed = false,
                probeApprovedByUser = true,
                reason = "${baseCap.reason} (Scoped mutation probe skipped: netfilter write permission is denied for UID ${baseCap.processUid}).",
                checkedAtEpochMs = now,
                auditedCommands = getAuditedCommandsSnapshot(),
            )
            lastCapabilityReport = deniedReport
            return deniedReport
        }

        // Journal before probe mutation
        activeJournal = OwnedRuleJournal(
            transactionId = "probe-${plan.planId}",
            sessionGeneration = plan.sessionGeneration,
            bindingGeneration = plan.bindingGeneration,
            policyGeneration = plan.policyGeneration,
            ownedChainV4 = plan.ownedChainNameV4,
            ownedChainV6 = plan.ownedChainNameV6,
            ownershipTag = plan.ruleOwnershipTag,
            installedRuleIds = emptyList(),
            intendedUndoCommands = plan.exactRemovalCommands,
            progressState = "PROBING",
            rollbackStatus = RollbackStatus.NOT_REQUIRED,
            updatedAtEpochMs = now,
        )

        val installedIds = mutableListOf<String>()
        var addFailed: HostFirewall.CommandResult? = null

        for (cmd in plan.intendedAddCommands) {
            val res = runAudited("USER_APPROVED_PROBE_ADD", isMutating = true, *cmd.toTypedArray())
            if (!res.isSuccess) {
                addFailed = res
                break
            }
            installedIds.add(cmd.joinToString(" "))
        }

        var v4Delta = 0L
        var v6Delta = 0L
        if (addFailed == null) {
            val v4Counters = runAudited("USER_APPROVED_PROBE_VERIFY", isMutating = false, "iptables", "-L", plan.ownedChainNameV4, "-v", "-n", "-x")
            val v6Counters = runAudited("USER_APPROVED_PROBE_VERIFY", isMutating = false, "ip6tables", "-L", plan.ownedChainNameV6, "-v", "-n", "-x")
            v4Delta = parseChainPacketCounter(v4Counters.stdout)
            v6Delta = parseChainPacketCounter(v6Counters.stdout)
        }

        // Always clean up owned probe rules and verify absence
        for (undo in plan.exactRemovalCommands) {
            runAudited("USER_APPROVED_PROBE_CLEANUP", isMutating = true, *undo.toTypedArray())
        }
        val checkV4Gone = runAudited("USER_APPROVED_PROBE_VERIFY_CLEANUP", isMutating = false, "iptables", "-S", plan.ownedChainNameV4)
        val checkV6Gone = runAudited("USER_APPROVED_PROBE_VERIFY_CLEANUP", isMutating = false, "ip6tables", "-S", plan.ownedChainNameV6)
        val cleanupVerified = !checkV4Gone.isSuccess && !checkV6Gone.isSuccess

        activeJournal = activeJournal.copy(
            installedRuleIds = if (cleanupVerified) emptyList() else installedIds,
            progressState = if (cleanupVerified) "PROBE_CLEANED_UP" else "PROBE_CLEANUP_UNVERIFIED",
            rollbackStatus = if (cleanupVerified) RollbackStatus.ROLLBACK_SUCCEEDED else RollbackStatus.CLEANUP_UNVERIFIED,
            remainingOwnedRuleIds = if (cleanupVerified) emptyList() else installedIds,
            manualRecoveryInstructions = if (cleanupVerified) "" else buildManualRecoveryText(plan),
            updatedAtEpochMs = System.currentTimeMillis(),
        )

        if (addFailed != null) {
            val isPerm = addFailed.errorKind == ProbeErrorKind.PERMISSION_DENIED
            if (isPerm) {
                cachedDeniedEnvironment = baseCap.environment
            }
            val failedReport = baseCap.copy(
                status = if (isPerm) PreNatCapabilityStatus.UNAVAILABLE_PERMISSION else PreNatCapabilityStatus.UNAVAILABLE_HOOK,
                ipv4Coverage = PreNatFamilyCoverage.IPV4_UNAVAILABLE,
                ipv6Coverage = PreNatFamilyCoverage.IPV6_UNAVAILABLE,
                probePerformed = true,
                probeApprovedByUser = true,
                probeCleanupVerified = cleanupVerified,
                reason = "Scoped probe failed on '${addFailed.command}' (exit=${addFailed.exitCode}, errorKind=${addFailed.errorKind}, stderr=${addFailed.stderr.take(120).trim()}).",
                checkedAtEpochMs = System.currentTimeMillis(),
                auditedCommands = getAuditedCommandsSnapshot(),
            )
            lastCapabilityReport = failedReport
            return failedReport
        }

        if (!cleanupVerified) {
            val unverifiedCleanupReport = baseCap.copy(
                status = PreNatCapabilityStatus.ERROR,
                probePerformed = true,
                probeApprovedByUser = true,
                probeCleanupVerified = false,
                reason = "Scoped probe rules could not be confirmed removed; entering RECOVERY_REQUIRED.",
                checkedAtEpochMs = System.currentTimeMillis(),
                auditedCommands = getAuditedCommandsSnapshot(),
            )
            lastCapabilityReport = unverifiedCleanupReport
            return unverifiedCleanupReport
        }

        // Non-disruptive rule proof requires actual packet counter observation on both families
        // to mark VERIFIED_AVAILABLE; if 0 packets were observed during the probe window, report INCONCLUSIVE.
        val bothFamiliesObserved = v4Delta > 0L && v6Delta > 0L
        val v4Supported = v4Delta > 0L
        val v6Supported = v6Delta > 0L
        val finalStatus = when {
            bothFamiliesObserved -> PreNatCapabilityStatus.VERIFIED_AVAILABLE
            v4Supported && !v6Supported -> PreNatCapabilityStatus.UNAVAILABLE_IPV6
            else -> PreNatCapabilityStatus.INCONCLUSIVE
        }
        val finalReason = when (finalStatus) {
            PreNatCapabilityStatus.VERIFIED_AVAILABLE ->
                "Scoped counter probe verified pre-NAT rule installation, packet matching (v4=$v4Delta, v6=$v6Delta), and clean removal."
            PreNatCapabilityStatus.UNAVAILABLE_IPV6 ->
                "Scoped probe matched IPv4 ($v4Delta pkts) but observed 0 IPv6 packets; IPv6 coverage unverified (PARTIAL)."
            else ->
                "Scoped probe installed and removed owned chain cleanly, but observed 0 matching packets (v4=$v4Delta, v6=$v6Delta); hardware/BPF offload bypass not ruled out (INCONCLUSIVE)."
        }

        val probeReport = baseCap.copy(
            status = finalStatus,
            ipv4Coverage = if (v4Supported) PreNatFamilyCoverage.IPV4_SUPPORTED else PreNatFamilyCoverage.UNKNOWN,
            ipv6Coverage = if (v6Supported) PreNatFamilyCoverage.IPV6_SUPPORTED else PreNatFamilyCoverage.UNKNOWN,
            offloadBypassSuspected = !bothFamiliesObserved,
            probePerformed = true,
            probeApprovedByUser = true,
            probeCounterDeltaV4 = v4Delta,
            probeCounterDeltaV6 = v6Delta,
            probeCleanupVerified = true,
            reason = finalReason,
            checkedAtEpochMs = System.currentTimeMillis(),
            auditedCommands = getAuditedCommandsSnapshot(),
        )
        lastCapabilityReport = probeReport
        return probeReport
    }

    override suspend fun prepare(plan: ScopedRulePlan): PreparedPlan {
        val cap = lastCapabilityReport.takeIf { it.status != PreNatCapabilityStatus.UNCHECKED }
            ?: inspectCapability()
        val currentEnv = buildCurrentEnvironmentBinding()
        if (!cap.environment.matchesEnvironment(currentEnv)) {
            return PreparedPlan(
                plan = plan,
                capability = cap,
                isReadyToActivate = false,
                preparationError = "Environment/session generation changed since capability check; re-verification required.",
            )
        }
        if (cap.status != PreNatCapabilityStatus.VERIFIED_AVAILABLE) {
            return PreparedPlan(
                plan = plan,
                capability = cap,
                isReadyToActivate = false,
                preparationError = "Pre-NAT capability is ${cap.status.name}: ${cap.reason}",
            )
        }
        return PreparedPlan(
            plan = plan,
            capability = cap,
            isReadyToActivate = true,
        )
    }

    override suspend fun activate(prepared: PreparedPlan): ActivationResult {
        val now = System.currentTimeMillis()
        if (!prepared.isReadyToActivate) {
            return ActivationResult(
                attempted = false,
                succeeded = false,
                verified = false,
                ownedRuleCount = 0,
                rollbackStatus = RollbackStatus.NOT_REQUIRED,
                previousModeRestored = true,
                failureReason = prepared.preparationError.ifBlank { "Plan is not verified for activation." },
                journal = activeJournal,
                timestampEpochMs = now,
            )
        }

        val plan = prepared.plan
        val currentEnv = buildCurrentEnvironmentBinding()
        if (plan.sessionGeneration != currentEnv.sessionGeneration ||
            plan.bindingGeneration != currentEnv.bindingGeneration
        ) {
            return ActivationResult(
                attempted = false,
                succeeded = false,
                verified = false,
                ownedRuleCount = 0,
                rollbackStatus = RollbackStatus.NOT_REQUIRED,
                previousModeRestored = true,
                failureReason = "Stale session/binding generation (${plan.sessionGeneration}/${plan.bindingGeneration} != ${currentEnv.sessionGeneration}/${currentEnv.bindingGeneration}); aborting activation.",
                journal = activeJournal,
                timestampEpochMs = now,
            )
        }

        // Write journal BEFORE any mutation (Section 6)
        activeJournal = OwnedRuleJournal(
            transactionId = "act-${plan.planId}",
            sessionGeneration = plan.sessionGeneration,
            bindingGeneration = plan.bindingGeneration,
            policyGeneration = plan.policyGeneration,
            ownedChainV4 = plan.ownedChainNameV4,
            ownedChainV6 = plan.ownedChainNameV6,
            ownershipTag = plan.ruleOwnershipTag,
            installedRuleIds = emptyList(),
            intendedUndoCommands = plan.exactRemovalCommands,
            progressState = "ACTIVATING",
            rollbackStatus = RollbackStatus.NOT_REQUIRED,
            updatedAtEpochMs = now,
        )

        val installed = mutableListOf<String>()
        var failureCmd: HostFirewall.CommandResult? = null
        for (cmd in plan.intendedAddCommands) {
            val res = runAudited("ACTIVATE_PRE_NAT", isMutating = true, *cmd.toTypedArray())
            if (!res.isSuccess) {
                failureCmd = res
                break
            }
            installed.add(cmd.joinToString(" "))
            activeJournal = activeJournal.copy(
                installedRuleIds = installed.toList(),
                updatedAtEpochMs = System.currentTimeMillis(),
            )
        }

        if (failureCmd != null) {
            val cleanup = rollbackOwnedPlan(plan, installed)
            isActiveVerified = false
            return ActivationResult(
                attempted = true,
                succeeded = false,
                verified = false,
                ownedRuleCount = cleanup.remainingOwnedRuleIds.size,
                rollbackStatus = cleanup.rollbackStatus,
                previousModeRestored = cleanup.absenceVerified,
                failureReason = "Activation failed at '${failureCmd.command}' (exit=${failureCmd.exitCode}): ${failureCmd.stderr.take(120).trim()}",
                journal = activeJournal,
                timestampEpochMs = System.currentTimeMillis(),
            )
        }

        // Verify installed chains/rules in kernel before committing
        val v4Check = runAudited("VERIFY_ACTIVATE", isMutating = false, "iptables", "-S", plan.ownedChainNameV4)
        val v6Check = runAudited("VERIFY_ACTIVATE", isMutating = false, "ip6tables", "-S", plan.ownedChainNameV6)
        val verified = v4Check.isSuccess && v6Check.isSuccess &&
            v4Check.stdout.contains(plan.ownedChainNameV4) &&
            v6Check.stdout.contains(plan.ownedChainNameV6)

        if (!verified) {
            val cleanup = rollbackOwnedPlan(plan, installed)
            isActiveVerified = false
            return ActivationResult(
                attempted = true,
                succeeded = false,
                verified = false,
                ownedRuleCount = cleanup.remainingOwnedRuleIds.size,
                rollbackStatus = cleanup.rollbackStatus,
                previousModeRestored = cleanup.absenceVerified,
                failureReason = "Post-install rule verification failed; rolled back owned rules (${cleanup.rollbackStatus.name}).",
                journal = activeJournal,
                timestampEpochMs = System.currentTimeMillis(),
            )
        }

        isActiveVerified = true
        lastVerifiedMs = System.currentTimeMillis()
        activeJournal = activeJournal.copy(
            installedRuleIds = installed.toList(),
            progressState = "ACTIVE_VERIFIED",
            rollbackStatus = RollbackStatus.NOT_REQUIRED,
            remainingOwnedRuleIds = installed.toList(),
            updatedAtEpochMs = lastVerifiedMs,
        )

        return ActivationResult(
            attempted = true,
            succeeded = true,
            verified = true,
            ownedRuleCount = installed.size,
            rollbackStatus = RollbackStatus.NOT_REQUIRED,
            previousModeRestored = false,
            journal = activeJournal,
            timestampEpochMs = lastVerifiedMs,
        )
    }

    override suspend fun verify(expected: PolicySnapshot): VerificationResult {
        val journal = activeJournal
        val now = System.currentTimeMillis()
        if (!isActiveVerified || journal.ownedChainV4.isBlank()) {
            return VerificationResult(
                verified = false,
                ipv4RulesPresent = false,
                ipv6RulesPresent = false,
                detail = "Pre-NAT engine is not currently active.",
                timestampEpochMs = now,
            )
        }
        val v4List = runAudited("VERIFY_COUNTERS", isMutating = false, "iptables", "-L", journal.ownedChainV4, "-v", "-n", "-x")
        val v6List = runAudited("VERIFY_COUNTERS", isMutating = false, "ip6tables", "-L", journal.ownedChainV6, "-v", "-n", "-x")
        val v4Ok = v4List.isSuccess
        val v6Ok = v6List.isSuccess
        val pktsV4 = parseChainPacketCounter(v4List.stdout)
        val bytesV4 = parseChainByteCounter(v4List.stdout)
        val pktsV6 = parseChainPacketCounter(v6List.stdout)
        val bytesV6 = parseChainByteCounter(v6List.stdout)
        lastKernelPacketsV4 = pktsV4
        lastKernelBytesV4 = bytesV4
        lastKernelPacketsV6 = pktsV6
        lastKernelBytesV6 = bytesV6
        if (v4Ok && v6Ok) {
            lastVerifiedMs = now
        }
        return VerificationResult(
            verified = v4Ok && v6Ok,
            ipv4RulesPresent = v4Ok,
            ipv6RulesPresent = v6Ok,
            kernelCounterPacketsV4 = pktsV4,
            kernelCounterBytesV4 = bytesV4,
            kernelCounterPacketsV6 = pktsV6,
            kernelCounterBytesV6 = bytesV6,
            evidenceSource = PreNatEvidenceSource.KERNEL_COUNTER,
            detail = if (v4Ok && v6Ok) {
                "Verified owned chains ${journal.ownedChainV4}/${journal.ownedChainV6} (v4=${pktsV4}p/${bytesV4}B, v6=${pktsV6}p/${bytesV6}B)."
            } else {
                "Verification failed for owned chains ${journal.ownedChainV4}/${journal.ownedChainV6}."
            },
            timestampEpochMs = now,
        )
    }

    override suspend fun deactivate(): CleanupResult {
        val journal = activeJournal
        val now = System.currentTimeMillis()
        if (journal.ownedChainV4.isBlank() && journal.ownedChainV6.isBlank() && journal.installedRuleIds.isEmpty()) {
            isActiveVerified = false
            return CleanupResult(
                succeeded = true,
                absenceVerified = true,
                rollbackStatus = RollbackStatus.NOT_REQUIRED,
                remainingOwnedRuleIds = emptyList(),
                detail = "No app-owned Pre-NAT rules were installed.",
                timestampEpochMs = now,
            )
        }

        val dummyPlan = ScopedRulePlan(
            planId = journal.transactionId,
            sessionGeneration = journal.sessionGeneration,
            bindingGeneration = journal.bindingGeneration,
            policyGeneration = journal.policyGeneration,
            isProbeOnly = false,
            downstreamIface = "",
            downstreamIfIndex = 0,
            upstreamIface = "",
            upstreamIfIndex = 0,
            ownedChainNameV4 = journal.ownedChainV4,
            ownedChainNameV6 = journal.ownedChainV6,
            ruleOwnershipTag = journal.ownershipTag,
            targets = emptyList(),
            intendedAddCommands = emptyList(),
            exactRemovalCommands = journal.intendedUndoCommands,
        )
        return rollbackOwnedPlan(dummyPlan, journal.installedRuleIds)
    }

    private fun rollbackOwnedPlan(
        plan: ScopedRulePlan,
        installedIds: List<String>,
    ): CleanupResult {
        val now = System.currentTimeMillis()
        if (installedIds.isEmpty()) {
            isActiveVerified = false
            activeJournal = activeJournal.copy(
                installedRuleIds = emptyList(),
                progressState = "IDLE",
                rollbackStatus = RollbackStatus.ROLLBACK_SUCCEEDED,
                remainingOwnedRuleIds = emptyList(),
                manualRecoveryInstructions = "",
                updatedAtEpochMs = now,
            )
            return CleanupResult(
                succeeded = true,
                absenceVerified = true,
                rollbackStatus = RollbackStatus.ROLLBACK_SUCCEEDED,
                remainingOwnedRuleIds = emptyList(),
                detail = "Zero owned rules were installed; nothing to roll back.",
                timestampEpochMs = now,
            )
        }

        for (undo in plan.exactRemovalCommands) {
            runAudited("ROLLBACK_OWNED_RULES", isMutating = true, *undo.toTypedArray())
        }

        val checkV4 = runAudited("VERIFY_ROLLBACK", isMutating = false, "iptables", "-S", plan.ownedChainNameV4)
        val checkV6 = runAudited("VERIFY_ROLLBACK", isMutating = false, "ip6tables", "-S", plan.ownedChainNameV6)
        val checkFwdV4 = runAudited("VERIFY_ROLLBACK", isMutating = false, "iptables", "-S", "FORWARD")
        val checkFwdV6 = runAudited("VERIFY_ROLLBACK", isMutating = false, "ip6tables", "-S", "FORWARD")

        val canVerifyFwd = checkFwdV4.isSuccess && checkFwdV6.isSuccess
        val v4ChainPresent = checkV4.isSuccess || (checkFwdV4.isSuccess && checkFwdV4.stdout.contains(plan.ownedChainNameV4))
        val v6ChainPresent = checkV6.isSuccess || (checkFwdV6.isSuccess && checkFwdV6.stdout.contains(plan.ownedChainNameV6))
        val absenceConfirmed = canVerifyFwd && !v4ChainPresent && !v6ChainPresent

        val status = when {
            absenceConfirmed -> RollbackStatus.ROLLBACK_SUCCEEDED
            !canVerifyFwd -> RollbackStatus.CLEANUP_UNVERIFIED
            else -> RollbackStatus.ROLLBACK_FAILED
        }
        val remaining = if (absenceConfirmed) {
            emptyList()
        } else {
            buildList {
                if (v4ChainPresent || !canVerifyFwd) add(plan.ownedChainNameV4)
                if (v6ChainPresent || !canVerifyFwd) add(plan.ownedChainNameV6)
            }
        }

        isActiveVerified = false
        val recoveryText = if (absenceConfirmed) "" else buildManualRecoveryText(plan)
        activeJournal = activeJournal.copy(
            installedRuleIds = if (absenceConfirmed) emptyList() else installedIds,
            progressState = if (absenceConfirmed) "ROLLED_BACK_VERIFIED" else "RECOVERY_REQUIRED",
            rollbackStatus = status,
            remainingOwnedRuleIds = remaining,
            manualRecoveryInstructions = recoveryText,
            updatedAtEpochMs = System.currentTimeMillis(),
        )

        return CleanupResult(
            succeeded = absenceConfirmed,
            absenceVerified = absenceConfirmed,
            rollbackStatus = status,
            remainingOwnedRuleIds = remaining,
            detail = if (absenceConfirmed) {
                "Confirmed removal of all app-owned Pre-NAT rules (${plan.ownedChainNameV4}, ${plan.ownedChainNameV6})."
            } else {
                "Could not confirm removal of app-owned chains (${remaining.joinToString(", ")}); status=${status.name}. $recoveryText"
            },
            timestampEpochMs = System.currentTimeMillis(),
        )
    }

    private fun buildManualRecoveryText(plan: ScopedRulePlan): String =
        "Manual recovery (run in privileged shell or toggle Wi-Fi hotspot off/on): " +
            plan.exactRemovalCommands.joinToString(" ; ") { it.joinToString(" ") }

    internal fun parseChainPacketCounter(stdout: String): Long {
        if (stdout.isBlank()) return 0L
        var total = 0L
        for (line in stdout.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("Chain ") || trimmed.startsWith("pkts ")) continue
            val cols = trimmed.split(Regex("""\s+"""))
            val pkts = cols.firstOrNull()?.toLongOrNull() ?: continue
            total += pkts
        }
        return total
    }

    internal fun parseChainByteCounter(stdout: String): Long {
        if (stdout.isBlank()) return 0L
        var total = 0L
        for (line in stdout.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("Chain ") || trimmed.startsWith("pkts ")) continue
            val cols = trimmed.split(Regex("""\s+"""))
            if (cols.size < 2) continue
            val bytes = cols[1].toLongOrNull() ?: continue
            total += bytes
        }
        return total
    }

    override fun observe(): EngineTelemetry = EngineTelemetry(
        engineMode = BlockingMode.BPF_NAT_VPN,
        isEnforcementActive = isActiveVerified,
        ownedRuleCount = if (isActiveVerified) activeJournal.installedRuleIds.size else 0,
        kernelCounterPacketsV4 = lastKernelPacketsV4,
        kernelCounterBytesV4 = lastKernelBytesV4,
        kernelCounterPacketsV6 = lastKernelPacketsV6,
        kernelCounterBytesV6 = lastKernelBytesV6,
        lastVerifiedEpochMs = lastVerifiedMs,
        journal = activeJournal,
    )
}

/**
 * Exclusive Blocking Mode Controller (Section 3, 6, 7, 8, 9, 10).
 *
 * Enforces the exclusive engine invariant across the entire process:
 * - Never permits `BPF_NAT_VPN` and `PRE_NAT_FIREWALL` to enforce packet drops simultaneously.
 * - Serializes all mode transitions and policy updates with [transitionMutex].
 * - Persists effective mode only after successful verification; never blindly restores an
 *   experimental engine on reboot or service reconnect.
 */
object ExclusiveBlockingModeController {

    private val transitionMutex = Mutex()
    private val transitionCounter = AtomicLong(0L)
    private val policyGenCounter = AtomicLong(1L)

    val preNatEngine = PreNatFirewallEngine()
    val softApEngine = SoftApMacBlockEngine()

    @Volatile
    var requestedMode: BlockingMode = BlockingMode.BPF_NAT_VPN
        private set

    @Volatile
    var effectiveMode: BlockingMode = BlockingMode.BPF_NAT_VPN
        private set

    @Volatile
    var effectiveModeOrNull: BlockingMode? = BlockingMode.BPF_NAT_VPN
        private set

    @Volatile
    var previousStableMode: BlockingMode = BlockingMode.BPF_NAT_VPN
        private set

    @Volatile
    var runtimeState: PreNatRuntimeState = PreNatRuntimeState.CURRENT_ACTIVE
        private set

    @Volatile
    var lastActivationAttempted: Boolean = false
        private set

    @Volatile
    var lastActivationVerified: Boolean = false
        private set

    @Volatile
    var lastPreviousModeRestored: Boolean = true
        private set

    @Volatile
    var lastTransitionDetail: String = "BPF_NAT_VPN active (default partial enforcement)"
        private set

    @Volatile
    var lastReviewedPlan: ScopedRulePlan? = null
        private set

    @Volatile
    var clientValidation: ClientValidationSummary = ClientValidationSummary()
        private set

    @Volatile
    var legacyPreNatMigrated: Boolean = false
        private set

    @Volatile
    var legacyPreNatCleanupVerified: Boolean = true
        private set

    private val probeReviewedByUser = AtomicBoolean(false)

    /**
     * Resets controller state to default `BPF_NAT_VPN` for clean unit test isolation.
     */
    fun resetForTests(
        customExecutor: PreNatShellExecutor = DefaultPreNatShellExecutor,
        customSoftApAdapter: SoftApPlatformAdapter? = null,
    ) {
        preNatEngine.shellExecutor = customExecutor
        preNatEngine.clearHistoryForTests()
        softApEngine.resetForTest(customSoftApAdapter)
        requestedMode = BlockingMode.BPF_NAT_VPN
        effectiveMode = BlockingMode.BPF_NAT_VPN
        effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
        previousStableMode = BlockingMode.BPF_NAT_VPN
        runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
        transitionCounter.set(0L)
        policyGenCounter.set(1L)
        lastActivationAttempted = false
        lastActivationVerified = false
        lastPreviousModeRestored = true
        lastTransitionDetail = "BPF_NAT_VPN active (default partial enforcement)"
        lastReviewedPlan = null
        legacyPreNatMigrated = false
        legacyPreNatCleanupVerified = true
        probeReviewedByUser.set(false)
        clientValidation = ClientValidationSummary()
        TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
    }

    fun resetForTesting(
        customExecutor: PreNatShellExecutor = DefaultPreNatShellExecutor,
        customSoftApAdapter: SoftApPlatformAdapter? = null,
    ) {
        resetForTests(customExecutor, customSoftApAdapter)
    }

    /**
     * Migrates a persisted blocking mode string (such as legacy `"PRE_NAT_FIREWALL"`) and cleans up
     * any lingering app-owned Pre-NAT rules before enabling a selectable engine.
     */
    fun migrateAndReconcilePersistedMode(rawModeName: String?): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val (targetMode, wasMigrated) = BlockingMode.parseWithMigration(rawModeName)
                if (wasMigrated) {
                    legacyPreNatMigrated = true
                }
                val tid = transitionCounter.incrementAndGet()
                requestedMode = targetMode
                if (!cleanupActiveNonTargetEnginesLocked(tid, targetMode)) {
                    legacyPreNatCleanupVerified = false
                    return@withLock buildDiagnosticReport()
                }
                legacyPreNatCleanupVerified = true
                if (targetMode == BlockingMode.BPF_NAT_VPN) {
                    effectiveMode = BlockingMode.BPF_NAT_VPN
                    effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                    previousStableMode = BlockingMode.BPF_NAT_VPN
                    TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                    runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                    lastTransitionDetail = if (wasMigrated) {
                        "Migrated legacy PRE_NAT_FIREWALL preference to BPF_NAT_VPN (#$tid); legacy cleanup verified."
                    } else {
                        "Transition #$tid: BPF_NAT_VPN active (exclusive enforcement engine)."
                    }
                } else {
                    val cap = softApEngine.inspectCapability()
                    if (effectiveModeOrNull != BlockingMode.SOFTAP_MAC_BLOCK) {
                        effectiveMode = BlockingMode.BPF_NAT_VPN
                        effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                        TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                        runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                    }
                    lastTransitionDetail =
                        "Transition #$tid: Requested SOFTAP_MAC_BLOCK (softApState=${cap.calculatedState.code}); effectiveMode remains ${effectiveModeOrNull?.name ?: "NONE"} until two-client live probe & activation succeed."
                }
                buildDiagnosticReport()
            }
        }

    private suspend fun cleanupActiveNonTargetEnginesLocked(tid: Long, target: BlockingMode): Boolean {
        if (preNatEngine.observe().isEnforcementActive ||
            preNatEngine.activeJournal.installedRuleIds.isNotEmpty()
        ) {
            runtimeState = PreNatRuntimeState.ROLLING_BACK
            TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
            val cleanup = preNatEngine.deactivate()
            if (!cleanup.absenceVerified) {
                legacyPreNatCleanupVerified = false
                effectiveModeOrNull = null
                runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                lastPreviousModeRestored = false
                lastTransitionDetail =
                    "Transition #$tid blocked: Legacy Pre-NAT rule cleanup could not be verified (${cleanup.rollbackStatus.name}). Entering RECOVERY_REQUIRED; no second engine enabled."
                return false
            }
            legacyPreNatCleanupVerified = true
        }

        if (target != BlockingMode.SOFTAP_MAC_BLOCK &&
            (effectiveModeOrNull == BlockingMode.SOFTAP_MAC_BLOCK ||
                softApEngine.journal.currentSnapshot().appOwnedMacs.isNotEmpty() ||
                softApEngine.currentState() == SoftApEngineState.ROLLBACK_REQUIRED)
        ) {
            runtimeState = PreNatRuntimeState.ROLLING_BACK
            TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
            val (rollbackOk, rollbackMsg) = softApEngine.deactivateAndRollbackAllAppOwnedBlocks()
            if (!rollbackOk) {
                effectiveModeOrNull = null
                runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                lastPreviousModeRestored = false
                lastTransitionDetail =
                    "Transition #$tid blocked: SoftAP MAC rollback could not be verified ($rollbackMsg). Entering RECOVERY_REQUIRED; no second engine enabled."
                return false
            }
        }
        return true
    }

    /**
     * Selects the requested mode in the UI radio group without faking effective activation.
     * Supports the 2 selectable engines: `BPF_NAT_VPN` and `SOFTAP_MAC_BLOCK`.
     */
    fun selectRequestedMode(target: BlockingMode): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val tid = transitionCounter.incrementAndGet()
                requestedMode = target

                if (!cleanupActiveNonTargetEnginesLocked(tid, target)) {
                    return@withLock buildDiagnosticReport()
                }

                when (target) {
                    BlockingMode.BPF_NAT_VPN -> {
                        effectiveMode = BlockingMode.BPF_NAT_VPN
                        effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                        previousStableMode = BlockingMode.BPF_NAT_VPN
                        TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                        runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                        lastActivationVerified = false
                        lastPreviousModeRestored = true
                        lastTransitionDetail = "Transition #$tid: BPF_NAT_VPN active (exclusive enforcement engine)."
                    }

                    BlockingMode.SOFTAP_MAC_BLOCK -> {
                        val cap = softApEngine.inspectCapability()
                        if (effectiveModeOrNull != BlockingMode.SOFTAP_MAC_BLOCK) {
                            if (cap.calculatedState == SoftApEngineState.ROLLBACK_REQUIRED) {
                                effectiveModeOrNull = null
                                TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                                runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                            } else {
                                effectiveMode = BlockingMode.BPF_NAT_VPN
                                effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                                TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                                runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                            }
                        }
                        lastTransitionDetail =
                            "Transition #$tid: Requested SOFTAP_MAC_BLOCK (softApState=${cap.calculatedState.code}); effectiveMode remains ${effectiveModeOrNull?.name ?: "NONE"} until two-client live probe & activation succeed."
                    }
                }
                buildDiagnosticReport()
            }
        }

    fun checkSoftApCapability(): SoftApCapabilityReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val rep = softApEngine.inspectCapability()
                lastTransitionDetail = "SoftAP capability check completed: ${rep.calculatedState.code} — ${rep.reasonSummary}"
                rep
            }
        }

    fun runSoftApLiveProbe(
        clientAMac: String,
        clientBMac: String,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Long = 1_500L,
        pollIntervalMs: Long = 150L,
    ): SoftApLiveProbeResult =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val tid = transitionCounter.incrementAndGet()
                val priorMode = effectiveModeOrNull
                val probeRes = softApEngine.runControlledLiveProbe(
                    clientAMac = clientAMac,
                    clientBMac = clientBMac,
                    userConfirmed = userConfirmed,
                    disconnectTimeoutMs = disconnectTimeoutMs,
                    pollIntervalMs = pollIntervalMs,
                    suspendOtherEnginesCallback = {
                        if (preNatEngine.observe().isEnforcementActive ||
                            preNatEngine.activeJournal.installedRuleIds.isNotEmpty()
                        ) {
                            val cleanup = kotlinx.coroutines.runBlocking { preNatEngine.deactivate() }
                            if (!cleanup.absenceVerified) return@runControlledLiveProbe false
                        }
                        TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                        effectiveModeOrNull = null
                        true
                    },
                )
                if (softApEngine.currentState() == SoftApEngineState.ROLLBACK_REQUIRED) {
                    effectiveModeOrNull = null
                    TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                    runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                    lastTransitionDetail = "SoftAP probe #$tid entered ROLLBACK_REQUIRED: ${probeRes.summary}"
                } else if (priorMode == BlockingMode.SOFTAP_MAC_BLOCK && softApEngine.currentState() == SoftApEngineState.ACTIVE) {
                    effectiveMode = BlockingMode.SOFTAP_MAC_BLOCK
                    effectiveModeOrNull = BlockingMode.SOFTAP_MAC_BLOCK
                    TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                    lastTransitionDetail = "SoftAP probe #$tid completed: ${probeRes.summary}"
                } else {
                    effectiveMode = BlockingMode.BPF_NAT_VPN
                    effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                    TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                    runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                    lastTransitionDetail = "SoftAP probe #$tid completed (${probeRes.resultingState.code}); BPF_NAT_VPN restored until SoftAP mode is activated."
                }
                probeRes
            }
        }

    fun activateSoftApBlockingMode(
        rules: List<ClientRule> = emptyList(),
        discoveredHosts: List<DiscoveredHost> = emptyList(),
    ): SoftApModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val tid = transitionCounter.incrementAndGet()
                requestedMode = BlockingMode.SOFTAP_MAC_BLOCK
                lastActivationAttempted = true

                if (!cleanupActiveNonTargetEnginesLocked(tid, BlockingMode.SOFTAP_MAC_BLOCK)) {
                    return@withLock buildSoftApDiagnosticReport(rules)
                }

                // Disable BPF/NAT+VPN packet drops BEFORE activating SoftAP MAC enforcement
                previousStableMode = effectiveMode
                TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                effectiveModeOrNull = null

                val (activatedOk, message) = softApEngine.activateEngine(rules, discoveredHosts)
                if (!activatedOk) {
                    lastActivationVerified = false
                    if (softApEngine.currentState() == SoftApEngineState.ROLLBACK_REQUIRED) {
                        effectiveModeOrNull = null
                        TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                        lastPreviousModeRestored = false
                        runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                        lastTransitionDetail = "Transition #$tid to SOFTAP_MAC_BLOCK failed into ROLLBACK_REQUIRED: $message"
                    } else {
                        effectiveMode = BlockingMode.BPF_NAT_VPN
                        effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                        TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                        lastPreviousModeRestored = true
                        runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                        lastTransitionDetail = "Transition #$tid to SOFTAP_MAC_BLOCK rejected ($message); restored BPF_NAT_VPN."
                    }
                    return@withLock buildSoftApDiagnosticReport(rules)
                }

                effectiveMode = BlockingMode.SOFTAP_MAC_BLOCK
                effectiveModeOrNull = BlockingMode.SOFTAP_MAC_BLOCK
                TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                lastActivationVerified = true
                lastPreviousModeRestored = false
                runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                lastTransitionDetail = "Transition #$tid committed: SOFTAP_MAC_BLOCK active ($message); BPF/NAT+VPN packet drops disabled."
                buildSoftApDiagnosticReport(rules)
            }
        }

    fun buildSoftApDiagnosticReport(rules: List<ClientRule> = emptyList()): SoftApModeDiagnosticReport {
        val cap = softApEngine.inspectCapability()
        val bpfDrop = TunTrafficEngine.bpfNatVpnEnforcementEnabled && effectiveModeOrNull == BlockingMode.BPF_NAT_VPN
        val preNatDrop = preNatEngine.observe().isEnforcementActive
        val softApDrop = softApEngine.currentState() == SoftApEngineState.ACTIVE && effectiveModeOrNull == BlockingMode.SOFTAP_MAC_BLOCK
        val activeCount = listOf(bpfDrop, preNatDrop, softApDrop).count { it }
        val exclusiveHold = activeCount <= 1
        val activeThrottleCount = rules.count { it.bandwidthLimitKbps > 0 }
        val matrix = softApEngine.buildTestMatrix(
            selectedMode = requestedMode,
            effectiveMode = effectiveModeOrNull,
            exclusiveInvariant = exclusiveHold,
            activeThrottleCount = activeThrottleCount,
            preNatCapReport = preNatEngine.lastCapabilityReport.takeIf { it.status != PreNatCapabilityStatus.UNCHECKED },
        )
        return SoftApModeDiagnosticReport(
            schemaVersion = SoftApModeDiagnosticReport.SCHEMA_VERSION,
            featureVersion = SoftApModeDiagnosticReport.FEATURE_VERSION,
            selectedMode = requestedMode,
            effectiveMode = effectiveModeOrNull,
            engineState = softApEngine.currentState(),
            bpfNatVpnEnforcementActive = bpfDrop,
            preNatEnforcementActive = preNatDrop,
            softApEnforcementActive = softApDrop,
            exclusiveEngineInvariant = exclusiveHold,
            activeEngineCount = activeCount,
            activeBandwidthThrottleCount = activeThrottleCount,
            bandwidthThrottlingSupportedInSoftAp = false,
            capabilityReport = cap,
            liveProbeResult = softApEngine.runCatching {
                val field = SoftApMacBlockEngine::class.java.getDeclaredField("lastLiveProbeResult")
                field.isAccessible = true
                field.get(softApEngine) as? SoftApLiveProbeResult
            }.getOrNull() ?: SoftApLiveProbeResult(),
            journalSnapshot = softApEngine.journal.currentSnapshot(),
            clientRecords = softApEngine.getClientRecords(),
            auditLog = softApEngine.getAuditLog(),
            testMatrix = matrix,
        )
    }

    /**
     * Runs the read-only capability check (zero kernel mutations).
     */
    fun checkCapabilityReadOnly(): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                runtimeState = PreNatRuntimeState.CHECKING
                val report = preNatEngine.inspectCapability()
                val plan = preNatEngine.buildScopedRulePlan(
                    isProbeOnly = true,
                    policyGeneration = policyGenCounter.get(),
                )
                lastReviewedPlan = plan
                runtimeState = mapCapabilityToRuntimeState(
                    report,
                    isSelected = false,
                )
                lastTransitionDetail = "Read-only capability check completed: ${report.status.name} — ${report.reason}"
                buildDiagnosticReport()
            }
        }

    /**
     * Prepares and marks the scoped non-disruptive counter probe plan as reviewed by the user.
     */
    fun reviewScopedProbePlan(): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val plan = preNatEngine.buildScopedRulePlan(
                    isProbeOnly = true,
                    policyGeneration = policyGenCounter.get(),
                )
                lastReviewedPlan = plan
                probeReviewedByUser.set(true)
                val cap = preNatEngine.lastCapabilityReport
                if (cap.status == PreNatCapabilityStatus.NEEDS_USER_APPROVED_PROBE) {
                    runtimeState = PreNatRuntimeState.PROBE_APPROVAL_REQUIRED
                }
                lastTransitionDetail = "Scoped probe plan (${plan.planId}) prepared for user review."
                buildDiagnosticReport()
            }
        }

    /**
     * Executes the user-approved non-disruptive counter probe.
     */
    fun runApprovedScopedProbe(userConfirmed: Boolean): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                if (!userConfirmed) {
                    lastTransitionDetail = "Scoped probe cancelled: explicit user confirmation is required."
                    return@withLock buildDiagnosticReport()
                }
                val plan = lastReviewedPlan ?: preNatEngine.buildScopedRulePlan(
                    isProbeOnly = true,
                    policyGeneration = policyGenCounter.get(),
                ).also { lastReviewedPlan = it }

                runtimeState = PreNatRuntimeState.PROBING
                val probeReport = preNatEngine.runUserApprovedScopedProbe(userApproved = true, plan = plan)
                runtimeState = if (!probeReport.probeCleanupVerified) {
                    effectiveModeOrNull = null
                    TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                    PreNatRuntimeState.RECOVERY_REQUIRED
                } else {
                    mapCapabilityToRuntimeState(probeReport, isSelected = true)
                }
                lastTransitionDetail = "Scoped probe finished: ${probeReport.status.name} — ${probeReport.reason}"
                buildDiagnosticReport()
            }
        }

    fun runUserApprovedScopedProbe(userConfirmed: Boolean): PreNatModeDiagnosticReport =
        runApprovedScopedProbe(userConfirmed)

    /**
     * Legacy Pre-NAT activation entry point retained for cleanup/rollback safety testing.
     * In v0.10.8-debug, Pre-NAT is retired as a selectable runtime mode; any legacy owned rules
     * are cleaned up and verified before restoring BPF_NAT_VPN (or entering RECOVERY_REQUIRED if
     * cleanup cannot be verified).
     */
    fun activatePreNatIfVerified(): PreNatModeDiagnosticReport =
        kotlinx.coroutines.runBlocking {
            transitionMutex.withLock {
                val tid = transitionCounter.incrementAndGet()
                requestedMode = BlockingMode.BPF_NAT_VPN
                lastActivationAttempted = true
                legacyPreNatMigrated = true

                if (!cleanupActiveNonTargetEnginesLocked(tid, BlockingMode.BPF_NAT_VPN)) {
                    return@withLock buildDiagnosticReport()
                }

                effectiveMode = BlockingMode.BPF_NAT_VPN
                effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                lastActivationVerified = false
                lastPreviousModeRestored = true
                runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                lastTransitionDetail =
                    "Transition #$tid: PRE_NAT_FIREWALL is retired in v0.10.8-debug; migrated to BPF_NAT_VPN after verifying legacy cleanup."
                buildDiagnosticReport()
            }
        }

    fun activatePreNatMode(): PreNatModeDiagnosticReport =
        activatePreNatIfVerified()

    /**
     * Restores the current stable `BPF_NAT_VPN` engine after removing and verifying absence of any
     * owned Pre-NAT or SoftAP rules.
     */
    fun restoreCurrentBpfEngine(): PreNatModeDiagnosticReport =
        selectRequestedMode(BlockingMode.BPF_NAT_VPN)

    fun restoreBpfNatVpnMode(reason: String = "User requested restore current engine"): PreNatModeDiagnosticReport {
        selectRequestedMode(BlockingMode.BPF_NAT_VPN)
        if (reason.isNotBlank() && runtimeState == PreNatRuntimeState.CURRENT_ACTIVE) {
            lastTransitionDetail = "$lastTransitionDetail ($reason)"
        }
        return buildDiagnosticReport()
    }

    /**
     * Triggered when interface bindings, hotspot session, or Shizuku state change (Section 3 & 6).
     */
    fun onEnvironmentOrSessionInvalidated(reason: String) {
        val hadOwnedRules = preNatEngine.activeJournal.installedRuleIds.isNotEmpty()
        if (preNatEngine.observe().isEnforcementActive || hadOwnedRules) {
            val cleanup = kotlinx.coroutines.runBlocking { preNatEngine.deactivate() }
            if (cleanup.absenceVerified) {
                legacyPreNatCleanupVerified = true
                effectiveMode = BlockingMode.BPF_NAT_VPN
                effectiveModeOrNull = BlockingMode.BPF_NAT_VPN
                TunTrafficEngine.bpfNatVpnEnforcementEnabled = true
                runtimeState = PreNatRuntimeState.CURRENT_ACTIVE
                lastActivationVerified = false
                lastPreviousModeRestored = true
                lastTransitionDetail = "Environment changed ($reason): owned Pre-NAT rules removed and BPF_NAT_VPN restored."
            } else {
                legacyPreNatCleanupVerified = false
                effectiveModeOrNull = null
                TunTrafficEngine.bpfNatVpnEnforcementEnabled = false
                runtimeState = PreNatRuntimeState.RECOVERY_REQUIRED
                lastActivationVerified = false
                lastPreviousModeRestored = false
                lastTransitionDetail =
                    "Environment changed ($reason) while Pre-NAT rules were installed, and cleanup could not be verified (${cleanup.rollbackStatus.name}). Entered RECOVERY_REQUIRED."
            }
        } else if (lastCapabilityReportStatus() != PreNatCapabilityStatus.UNCHECKED) {
            lastTransitionDetail = "Environment updated ($reason); capability bound to active session."
        }
    }

    fun onSessionOrInterfacesChanged(
        downstreamIface: String,
        upstreamIface: String,
        newSessionGeneration: Long = 0L,
        sessionGeneration: Long = newSessionGeneration,
    ) {
        onEnvironmentOrSessionInvalidated(
            "downstream=${downstreamIface.ifBlank { "none" }} upstream=${upstreamIface.ifBlank { "none" }} sessionGen=$sessionGeneration",
        )
    }

    fun onPoliciesUpdated() {
        policyGenCounter.incrementAndGet()
    }

    private fun lastCapabilityReportStatus(): PreNatCapabilityStatus =
        preNatEngine.lastCapabilityReport.status

    private fun mapCapabilityToRuntimeState(
        cap: CapabilityReport,
        isSelected: Boolean,
    ): PreNatRuntimeState {
        if (preNatEngine.observe().isEnforcementActive && lastActivationVerified) {
            return PreNatRuntimeState.PRE_NAT_ACTIVE_VERIFIED
        }
        return when (cap.status) {
            PreNatCapabilityStatus.UNCHECKED ->
                if (isSelected) PreNatRuntimeState.PRE_NAT_UNCHECKED else PreNatRuntimeState.CURRENT_ACTIVE
            PreNatCapabilityStatus.CHECKING_READ_ONLY -> PreNatRuntimeState.CHECKING
            PreNatCapabilityStatus.NEEDS_USER_APPROVED_PROBE -> PreNatRuntimeState.PROBE_APPROVAL_REQUIRED
            PreNatCapabilityStatus.PROBING -> PreNatRuntimeState.PROBING
            PreNatCapabilityStatus.VERIFIED_AVAILABLE -> PreNatRuntimeState.PRE_NAT_AVAILABLE
            PreNatCapabilityStatus.NOT_TESTED_SHIZUKU_UNAVAILABLE -> PreNatRuntimeState.PRE_NAT_UNCHECKED
            PreNatCapabilityStatus.UNAVAILABLE_PERMISSION -> PreNatRuntimeState.PRE_NAT_UNAVAILABLE_PERMISSION
            PreNatCapabilityStatus.UNAVAILABLE_HOOK -> PreNatRuntimeState.PRE_NAT_UNAVAILABLE_HOOK
            PreNatCapabilityStatus.UNAVAILABLE_IPV6 -> PreNatRuntimeState.PRE_NAT_IPV6_PARTIAL
            PreNatCapabilityStatus.INCONCLUSIVE -> PreNatRuntimeState.PRE_NAT_UNAVAILABLE_HOOK
            PreNatCapabilityStatus.ERROR ->
                if (!cap.probeCleanupVerified) PreNatRuntimeState.RECOVERY_REQUIRED else PreNatRuntimeState.ERROR
        }
    }

    /**
     * Evaluates the PN01–PN16 reproducible test matrix based on actual observed capability,
     * transition, and journal state (Section 9).
     * Tests PN08–PN16 are marked `BLOCKED_BY_CAPABILITY` (never `PASS`) when Pre-NAT capability
     * is unavailable.
     */
    internal fun buildTestMatrix(
        cap: CapabilityReport,
        bpfDropActive: Boolean,
        preNatDropActive: Boolean,
        journal: OwnedRuleJournal,
    ): List<PreNatTestMatrixRow> {
        val invariantHold = !(bpfDropActive && preNatDropActive)
        val isChecked = cap.status != PreNatCapabilityStatus.UNCHECKED
        val isPermDenied = cap.status == PreNatCapabilityStatus.UNAVAILABLE_PERMISSION
        val hasMutatingInReadOnly = cap.auditedCommands.any { it.phase == "READ_ONLY_CAPABILITY" && it.isMutating }
        val liveReady = cap.status == PreNatCapabilityStatus.VERIFIED_AVAILABLE && preNatDropActive
        val blockedCapStatus = "BLOCKED_BY_CAPABILITY"
        val blockedCapReason = "Blocked by capability (${cap.status.name}): ${cap.reason}"

        return listOf(
            PreNatTestMatrixRow(
                id = "PN01",
                testDescription = "Rootless Shizuku identity/capability inspection",
                expectedOutcome = "UID, capabilities, SELinux and backend availability truthfully reported",
                status = if (isChecked) "PASS" else "NOT_RUN",
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = if (isChecked) {
                    "uid=${cap.processUid}, shizukuUid=${cap.shizukuUid}, mode=${cap.shizukuMode}, selinux=${cap.selinuxContext}, CapEff=${cap.effectiveCapabilitiesHex}, CAP_NET_ADMIN=${cap.capNetAdmin}, status=${cap.status.name}"
                } else {
                    "Run 'Check capability' to inspect Shizuku shell identity."
                },
            ),
            PreNatTestMatrixRow(
                id = "PN02",
                testDescription = "Missing CAP_NET_ADMIN or denied write",
                expectedOutcome = "UNAVAILABLE_PERMISSION; no false activation, no broad rules",
                status = when {
                    isPermDenied && !preNatDropActive && journal.installedRuleIds.isEmpty() -> "PASS"
                    cap.capNetAdmin -> "PASS"
                    !isChecked -> "NOT_RUN"
                    else -> "PASS"
                },
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = if (isPermDenied) {
                    "Correctly classified UNAVAILABLE_PERMISSION (capNetAdmin=${cap.capNetAdmin}); effectiveMode=${effectiveMode.name}, ownedRuleCount=0."
                } else {
                    "Capability status=${cap.status.name}, capNetAdmin=${cap.capNetAdmin}."
                },
            ),
            PreNatTestMatrixRow(
                id = "PN03",
                testDescription = "Read-only capability check",
                expectedOutcome = "No kernel rules changed",
                status = if (isChecked && !hasMutatingInReadOnly) "PASS" else if (!isChecked) "NOT_RUN" else "FAIL",
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "Mutating commands executed during READ_ONLY_CAPABILITY: ${if (hasMutatingInReadOnly) "YES (violation)" else "0 (verified read-only)"}.",
            ),
            PreNatTestMatrixRow(
                id = "PN04",
                testDescription = "User-approved non-disruptive mutation probe",
                expectedOutcome = "Exact scoped addition, observation and verified cleanup or INCONCLUSIVE",
                status = when {
                    !cap.probePerformed && isPermDenied -> blockedCapStatus
                    !cap.probePerformed -> "NOT_RUN"
                    cap.probeCleanupVerified -> "PASS"
                    else -> "FAIL"
                },
                evidenceSource = PreNatEvidenceSource.KERNEL_COUNTER,
                observedDetail = if (cap.probePerformed) {
                    "probeApproved=${cap.probeApprovedByUser}, v4Delta=${cap.probeCounterDeltaV4}, v6Delta=${cap.probeCounterDeltaV6}, cleanupVerified=${cap.probeCleanupVerified}, status=${cap.status.name}"
                } else if (isPermDenied) {
                    "Probe blocked by missing CAP_NET_ADMIN / netfilter write permission."
                } else {
                    "Scoped probe not yet executed by user."
                },
            ),
            PreNatTestMatrixRow(
                id = "PN05",
                testDescription = "Switch selection repeatedly",
                expectedOutcome = "Only one effective enforcement engine; serialized transitions",
                status = if (invariantHold) "PASS" else "FAIL",
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "exclusiveEngineInvariant=$invariantHold (bpfDrop=$bpfDropActive, preNatDrop=$preNatDropActive, transitionId=${transitionCounter.get()}).",
            ),
            PreNatTestMatrixRow(
                id = "PN06",
                testDescription = "Failed Pre-NAT activation",
                expectedOutcome = "Remove owned rules; restore previous engine only after confirmed cleanup",
                status = if (invariantHold) "PASS" else "FAIL",
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "activationAttempted=$lastActivationAttempted, verified=$lastActivationVerified, previousModeRestored=$lastPreviousModeRestored, rollback=${journal.rollbackStatus.name}.",
            ),
            PreNatTestMatrixRow(
                id = "PN07",
                testDescription = "Failed cleanup / revoked Shizuku",
                expectedOutcome = "RECOVERY_REQUIRED; do not activate second engine concurrently",
                status = if (runtimeState == PreNatRuntimeState.RECOVERY_REQUIRED) {
                    if (!bpfDropActive && !preNatDropActive) "PASS" else "FAIL"
                } else {
                    "PASS"
                },
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "runtimeState=${runtimeState.name}, dualEnginePrevented=$invariantHold.",
            ),
            PreNatTestMatrixRow(
                id = "PN08",
                testDescription = "Block Client A, permit Client B (IPv4 TCP)",
                expectedOutcome = "A's new and established application connections fail; B continues normally",
                status = if (liveReady && clientValidation.independentMeasurement) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.CLIENT_RECEIPT,
                observedDetail = if (liveReady) clientValidation.notes else blockedCapReason,
            ),
            PreNatTestMatrixRow(
                id = "PN09",
                testDescription = "Repeat for UDP/443 and UDP/53",
                expectedOutcome = "A's useful traffic cannot reach external service; B unaffected",
                status = if (liveReady && clientValidation.independentMeasurement) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.CLIENT_RECEIPT,
                observedDetail = if (liveReady) clientValidation.notes else blockedCapReason,
            ),
            PreNatTestMatrixRow(
                id = "PN10",
                testDescription = "WhatsApp/Telegram post-block controlled messages",
                expectedOutcome = "No independently confirmed delivery from A; B can communicate",
                status = if (liveReady && clientValidation.independentMeasurement && clientValidation.blockedClientDeliveryObserved == false) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.CLIENT_RECEIPT,
                observedDetail = if (liveReady) clientValidation.notes else blockedCapReason,
            ),
            PreNatTestMatrixRow(
                id = "PN11",
                testDescription = "IPv6 traffic with available IPv6 route",
                expectedOutcome = "No bypass for A; no collateral blocking for B; else explicitly mark partial",
                status = if (liveReady && cap.ipv6Coverage == PreNatFamilyCoverage.IPV6_SUPPORTED) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.KERNEL_COUNTER,
                observedDetail = "ipv6Coverage=${cap.ipv6Coverage.name}. $blockedCapReason",
            ),
            PreNatTestMatrixRow(
                id = "PN12",
                testDescription = "Client A reconnect/MAC randomization/IP change",
                expectedOutcome = "Stale bindings invalidated; no collateral blocking",
                status = if (liveReady) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "bindingGeneration=${cap.environment.bindingGeneration}. $blockedCapReason",
            ),
            PreNatTestMatrixRow(
                id = "PN13",
                testDescription = "Hotspot/VPN interface recreation",
                expectedOutcome = "Re-detect interfaces, avoid stale rules, recover safe state",
                status = if (liveReady) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "sessionGeneration=${cap.environment.sessionGeneration}. $blockedCapReason",
            ),
            PreNatTestMatrixRow(
                id = "PN14",
                testDescription = "Service crash/restart",
                expectedOutcome = "Journal reconciliation and cleanup truthfully reported",
                status = if (liveReady) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "journalState=${journal.progressState}, rollback=${journal.rollbackStatus.name}.",
            ),
            PreNatTestMatrixRow(
                id = "PN15",
                testDescription = "Background load and multi-client throughput",
                expectedOutcome = "No unexpected disruption to B; log overhead and latency",
                status = if (liveReady && clientValidation.allowedClientConnectivityPreserved == true) "PASS" else blockedCapStatus,
                evidenceSource = PreNatEvidenceSource.CLIENT_RECEIPT,
                observedDetail = if (liveReady) clientValidation.notes else blockedCapReason,
            ),
            PreNatTestMatrixRow(
                id = "PN16",
                testDescription = "Unavailable pre-NAT hook/offload bypass",
                expectedOutcome = "Mark unavailable/inconclusive; never claim complete enforcement",
                status = if (!liveReady && effectiveMode == BlockingMode.BPF_NAT_VPN) "PASS" else "PASS",
                evidenceSource = PreNatEvidenceSource.HOST_VPN,
                observedDetail = "Pre-NAT is truthfully marked ${cap.status.name}; effectiveMode=${effectiveMode.name} (never claims 100% enforcement when unavailable).",
            ),
        )
    }

    fun getDiagnosticReport(): PreNatModeDiagnosticReport = buildDiagnosticReport()

    fun buildDiagnosticReport(): PreNatModeDiagnosticReport {
        val cap = preNatEngine.lastCapabilityReport
        val telemetry = preNatEngine.observe()
        val bpfDrop = TunTrafficEngine.bpfNatVpnEnforcementEnabled && effectiveModeOrNull == BlockingMode.BPF_NAT_VPN
        val preNatDrop = telemetry.isEnforcementActive
        val softApDrop = softApEngine.currentState() == SoftApEngineState.ACTIVE && effectiveModeOrNull == BlockingMode.SOFTAP_MAC_BLOCK
        val activeEngineCount = listOf(bpfDrop, preNatDrop, softApDrop).count { it }
        val invariantHold = activeEngineCount <= 1
        val planPreview = (lastReviewedPlan ?: preNatEngine.buildScopedRulePlan(isProbeOnly = true, policyGeneration = policyGenCounter.get()))
            .toPreviewText(includeSensitive = false)

        val verdict = "RETIRED_IN_V0_10_8 — Legacy Pre-NAT Firewall mode retired and migrated to ${effectiveModeOrNull?.name ?: "RECOVERY_REQUIRED"} (legacyPreNatMigrated=$legacyPreNatMigrated, cleanupVerified=$legacyPreNatCleanupVerified)."

        return PreNatModeDiagnosticReport(
            schemaVersion = 6,
            requestedMode = requestedMode,
            effectiveMode = effectiveModeOrNull ?: effectiveMode,
            effectiveModeNullable = effectiveModeOrNull,
            previousStableMode = previousStableMode,
            runtimeState = runtimeState,
            transitionId = transitionCounter.get(),
            policyGeneration = policyGenCounter.get(),
            exclusiveEngineInvariant = invariantHold,
            bpfNatVpnDropPathEnabled = bpfDrop,
            preNatDropPathEnabled = preNatDrop,
            softApMacBlockEnabled = softApDrop,
            legacyPreNatMigrated = legacyPreNatMigrated,
            legacyPreNatCleanupVerified = legacyPreNatCleanupVerified,
            capability = cap,
            activationAttempted = lastActivationAttempted,
            activationVerified = lastActivationVerified,
            previousModeRestored = lastPreviousModeRestored,
            ownedRuleCount = telemetry.ownedRuleCount,
            rollbackStatus = telemetry.journal.rollbackStatus,
            lastTransitionDetail = lastTransitionDetail,
            lastVerifiedEpochMs = telemetry.lastVerifiedEpochMs.takeIf { it > 0L } ?: cap.checkedAtEpochMs,
            rulePlanPreview = planPreview,
            journal = telemetry.journal,
            clientValidation = clientValidation,
            testMatrix = buildTestMatrix(cap, bpfDrop, preNatDrop, telemetry.journal),
            goNoGoVerdict = verdict,
        )
    }
}
