package dev.shizzi

import android.system.Os
import android.util.Log
import java.io.InputStream
import java.util.Calendar
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

enum class EnforcementState {
    UNRESTRICTED,
    CONFIGURED,
    DATAPATH_ACTIVE,
    POLICY_INSTALLED,
    PACKETS_MATCHED,
    PACKETS_DROPPED,
    PARTIAL_BPF_ENFORCEMENT,
    THROTTLING_OBSERVED,
    ENFORCEMENT_UNAVAILABLE,
    DEGRADED_MULTI_CLIENT,
}

enum class FirewallBackend {
    NONE,
    USERSPACE,
    USERSPACE_AND_KERNEL,
    KERNEL_ONLY,
}

enum class ProbeErrorKind {
    NONE,
    PERMISSION_DENIED,
    COMMAND_MISSING,
    FILE_MISSING,
    TIMEOUT,
    EMPTY_RESPONSE,
    PARSE_FAILURE,
    EXECUTION_FAILED,
}

object HostFirewall {

    private const val TAG = "HostFirewall"
    private const val CMD_TIMEOUT_MS = 2_000L
    private const val MAX_CAPTURED_BYTES = 16 * 1024

    data class CommandResult(
        val command: String,
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val timedOut: Boolean,
        val errorKind: ProbeErrorKind = classifyError(exitCode, stdout, stderr, timedOut),
    ) {
        val isSuccess: Boolean get() = !timedOut && exitCode == 0
    }

    data class KernelCapabilityMatrix(
        val uid: Int = -1,
        val canReadNetfilterV4: Boolean = false,
        val canReadNetfilterV6: Boolean = false,
        val canWriteNetfilterV4: Boolean = false,
        val canWriteNetfilterV6: Boolean = false,
        val canReadIpRuleV4: Boolean = false,
        val canReadIpRuleV6: Boolean = false,
        val canWriteIpRuleV4: Boolean = false,
        val canWriteIpRuleV6: Boolean = false,
        val writeProbesExecuted: Boolean = false,
        val netfilterV4WriteError: String = "",
        val netfilterV6WriteError: String = "",
        val ipRuleV4WriteError: String = "",
        val ipRuleV6WriteError: String = "",
        val capabilityNote: String = "",
    ) {
        val canWriteBothFamiliesNetfilter: Boolean
            get() = canWriteNetfilterV4 && canWriteNetfilterV6
        val canWriteBothFamiliesIpRule: Boolean
            get() = canWriteIpRuleV4 && canWriteIpRuleV6
    }

    data class EnforcementSummary(
        val configuredRulesCount: Int,
        val activeRulesCount: Int,
        val connectedClientsCount: Int,
        val policyInstalledOnConnectedCount: Int,
        val verifiedEnforcedOnConnectedCount: Int,
        val blockedConnectedCount: Int,
        val throttledConnectedCount: Int,
        val datapathMode: DatapathMode,
        val firewallBackend: FirewallBackend,
        val kernelNetfilterAvailable: Boolean,
    )

    private val currentlyBlockedIps = mutableSetOf<String>()
    private val currentlyBlockedMacs = mutableSetOf<String>()
    private val currentlyThrottledIps = mutableMapOf<String, Int>() // IP -> limitPkt

    private val clientConnectTimes = mutableMapOf<String, Long>()
    private val lastLoggedStateByMac = mutableMapOf<String, String>()

    @Volatile
    private var kernelCapabilityChecked = false

    @Volatile
    var capabilityMatrix: KernelCapabilityMatrix = KernelCapabilityMatrix()
        private set

    @Volatile
    var isKernelNetfilterAvailable: Boolean = false
        private set

    @Volatile
    var isIpRuleAvailable: Boolean = false
        private set

    @Volatile
    var isSuAvailable: Boolean = false
        private set

    @Volatile
    var processUid: Int = -1
        private set

    @Volatile
    private var lastLoggedBackendSignature: String = ""

    fun classifyError(
        exitCode: Int,
        stdout: String,
        stderr: String,
        timedOut: Boolean,
    ): ProbeErrorKind {
        if (timedOut) return ProbeErrorKind.TIMEOUT
        if (exitCode == 0) return ProbeErrorKind.NONE
        val combined = "$stderr $stdout".lowercase()
        return when {
            combined.contains("permission denied") ||
                combined.contains("operation not permitted") ||
                combined.contains("eperm") ||
                combined.contains("eacces") ||
                combined.contains("must be root") ||
                combined.contains("can't initialize iptables table") ||
                combined.contains("you must be root") -> ProbeErrorKind.PERMISSION_DENIED
            combined.contains("inaccessible or not found") ||
                combined.contains("command not found") ||
                combined.contains("cannot run program") ||
                combined.contains("error=2,") ||
                combined.contains("error=13,") && combined.contains("cannot run program") -> ProbeErrorKind.COMMAND_MISSING
            combined.contains("no such file or directory") ||
                combined.contains("enoent") -> ProbeErrorKind.FILE_MISSING
            else -> ProbeErrorKind.EXECUTION_FAILED
        }
    }

    private fun resolveUid(): Int {
        if (processUid >= 0) return processUid
        val rawUid = runCatching { Os.getuid() }.getOrDefault(2000)
        processUid = if (rawUid == 0 && !java.io.File("/system/build.prop").exists()) {
            2000
        } else {
            rawUid
        }
        return processUid
    }

    fun checkSuPresence(): Boolean {
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/adb/ksu/bin/su",
            "/data/adb/ap/bin/su",
        )
        return suPaths.any { java.io.File(it).exists() }
    }

    /**
     * Evaluates kernel netfilter and policy routing capabilities WITHOUT treating read-only listing
     * (`ip rule show` or `iptables -S`) as proof of write/enforcement capability, and WITHOUT
     * invoking `su` automatically in rootless ADB mode.
     *
     * By default in rootless mode (`uid != 0` and [allowWriteProbesInRootless] == `false`),
     * mutating write probes (`iptables -N/-F/-X`, `ip rule add/del`) are NOT executed repeatedly;
     * only read-only inspection is performed and the backend is reported as `USERSPACE` (no kernel write).
     * Note: skipping write probes in the rootless flow avoids repeated failed netfilter/ip-rule mutations
     * and does NOT universally prove absence of kernel write capability on other devices/modes.
     */
    @Synchronized
    fun probeKernelCapabilities(
        force: Boolean = false,
        allowWriteProbesInRootless: Boolean = false,
    ): KernelCapabilityMatrix {
        val uid = resolveUid()
        if (kernelCapabilityChecked && !force) {
            return capabilityMatrix
        }
        kernelCapabilityChecked = true
        isSuAvailable = checkSuPresence()

        // 1. Read probes (listing only - NEVER treated as write/enforcement capability)
        val readIptV4 = executeCommand("iptables", "-S", "FORWARD")
        val readIptV6 = executeCommand("ip6tables", "-S", "FORWARD")
        val readRuleV4 = executeCommand("ip", "rule", "show")
        val readRuleV6 = executeCommand("ip", "-6", "rule", "show")

        val shouldRunWriteProbes = uid == 0 || allowWriteProbesInRootless
        if (!shouldRunWriteProbes) {
            val rootlessSkipMsg =
                "Write probe skipped in rootless mode (uid=$uid, backend=USERSPACE; skipping write probes does not universally prove absence of capability on other devices)"
            val matrix = KernelCapabilityMatrix(
                uid = uid,
                canReadNetfilterV4 = readIptV4.isSuccess,
                canReadNetfilterV6 = readIptV6.isSuccess,
                canWriteNetfilterV4 = false,
                canWriteNetfilterV6 = false,
                canReadIpRuleV4 = readRuleV4.isSuccess,
                canReadIpRuleV6 = readRuleV6.isSuccess,
                canWriteIpRuleV4 = false,
                canWriteIpRuleV6 = false,
                writeProbesExecuted = false,
                netfilterV4WriteError = readIptV4.stderr.ifBlank { rootlessSkipMsg },
                netfilterV6WriteError = readIptV6.stderr.ifBlank { rootlessSkipMsg },
                ipRuleV4WriteError = rootlessSkipMsg,
                ipRuleV6WriteError = rootlessSkipMsg,
                capabilityNote = rootlessSkipMsg,
            )
            capabilityMatrix = matrix
            isIpRuleAvailable = false
            isKernelNetfilterAvailable = false
            return matrix
        }

        // 2. Write probes using isolated owned structures (only in explicitly authorized write-probe or uid=0 mode)
        val testChain = "SHIZZI_CAP_CHK"
        executeCommand("iptables", "-F", testChain)
        executeCommand("iptables", "-X", testChain)
        val writeIptV4Create = executeCommand("iptables", "-N", testChain)
        val canWriteV4 = if (writeIptV4Create.isSuccess) {
            val del = executeCommand("iptables", "-X", testChain)
            del.isSuccess
        } else {
            false
        }

        executeCommand("ip6tables", "-F", testChain)
        executeCommand("ip6tables", "-X", testChain)
        val writeIptV6Create = executeCommand("ip6tables", "-N", testChain)
        val canWriteV6 = if (writeIptV6Create.isSuccess) {
            val del = executeCommand("ip6tables", "-X", testChain)
            del.isSuccess
        } else {
            false
        }

        // 3. Policy routing write probe using RFC 5737 / RFC 3849 documentation-only addresses
        // at priority 19899, immediately deleted.
        executeCommand("ip", "rule", "del", "from", "198.51.100.254/32", "priority", "19899")
        val writeRuleV4Add = executeCommand("ip", "rule", "add", "from", "198.51.100.254/32", "lookup", "main", "priority", "19899")
        val canWriteRuleV4 = if (writeRuleV4Add.isSuccess) {
            executeCommand("ip", "rule", "del", "from", "198.51.100.254/32", "lookup", "main", "priority", "19899").isSuccess
        } else {
            false
        }

        executeCommand("ip", "-6", "rule", "del", "from", "2001:db8::fffe/128", "priority", "19899")
        val writeRuleV6Add = executeCommand("ip", "-6", "rule", "add", "from", "2001:db8::fffe/128", "lookup", "main", "priority", "19899")
        val canWriteRuleV6 = if (writeRuleV6Add.isSuccess) {
            executeCommand("ip", "-6", "rule", "del", "from", "2001:db8::fffe/128", "lookup", "main", "priority", "19899").isSuccess
        } else {
            false
        }

        val matrix = KernelCapabilityMatrix(
            uid = uid,
            canReadNetfilterV4 = readIptV4.isSuccess,
            canReadNetfilterV6 = readIptV6.isSuccess,
            canWriteNetfilterV4 = canWriteV4,
            canWriteNetfilterV6 = canWriteV6,
            canReadIpRuleV4 = readRuleV4.isSuccess,
            canReadIpRuleV6 = readRuleV6.isSuccess,
            canWriteIpRuleV4 = canWriteRuleV4,
            canWriteIpRuleV6 = canWriteRuleV6,
            writeProbesExecuted = true,
            netfilterV4WriteError = writeIptV4Create.stderr.ifBlank { "exit=${writeIptV4Create.exitCode}" },
            netfilterV6WriteError = writeIptV6Create.stderr.ifBlank { "exit=${writeIptV6Create.exitCode}" },
            ipRuleV4WriteError = writeRuleV4Add.stderr.ifBlank { "exit=${writeRuleV4Add.exitCode}" },
            ipRuleV6WriteError = writeRuleV6Add.stderr.ifBlank { "exit=${writeRuleV6Add.exitCode}" },
            capabilityNote = "Write probes executed (uid=$uid)",
        )

        capabilityMatrix = matrix
        // CRITICAL: Only mark kernel netfilter or ip rule available when WRITE is confirmed on BOTH IPv4 and IPv6.
        // Never mark available based on `ip rule show` (read-only).
        isIpRuleAvailable = matrix.canWriteBothFamiliesIpRule
        isKernelNetfilterAvailable = matrix.canWriteBothFamiliesNetfilter || matrix.canWriteBothFamiliesIpRule

        return matrix
    }

    private fun ensureKernelCapabilityChecked() {
        val uid = resolveUid()
        if (!kernelCapabilityChecked) {
            probeKernelCapabilities(force = false)
        }

        val userspaceActive = TunTrafficEngine.isAttached
        val backend = currentBackend(userspaceActive, isKernelNetfilterAvailable)
        val m = capabilityMatrix
        val sig = "${backend.name}:$isKernelNetfilterAvailable:$isIpRuleAvailable:${m.canReadIpRuleV4}:${m.canWriteIpRuleV4}:$uid:${TunTrafficEngine.datapathMode.name}"
        if (lastLoggedBackendSignature != sig) {
            lastLoggedBackendSignature = sig
            SessionLog.info(
                "Firewall: backend=${backend.name} uid=$uid datapath=${TunTrafficEngine.datapathMode.name} " +
                    "netfilter(readV4=${m.canReadNetfilterV4},writeV4=${m.canWriteNetfilterV4},writeV6=${m.canWriteNetfilterV6}) " +
                    "ipRule(readV4=${m.canReadIpRuleV4},writeV4=${m.canWriteIpRuleV4},writeV6=${m.canWriteIpRuleV6})",
            )
        }
    }

    fun currentBackend(
        userspaceAttached: Boolean = TunTrafficEngine.isAttached,
        kernelAvailable: Boolean = isKernelNetfilterAvailable,
    ): FirewallBackend = when {
        userspaceAttached && kernelAvailable -> FirewallBackend.USERSPACE_AND_KERNEL
        userspaceAttached -> FirewallBackend.USERSPACE
        kernelAvailable -> FirewallBackend.KERNEL_ONLY
        else -> FirewallBackend.NONE
    }

    /**
     * Computes honest per-client enforcement status.
     * - Never reports PACKETS_DROPPED (`Blocked (verified)`) from cumulative/stale counters or shaping drops.
     * - Requires `policyVersionBlockedDrops > 0` in the current policy version AND no unattributed
     *   post-NAT bypass traffic (`!counters.unattributedPostNatObserved && !isDegradedMultiClient`).
     */
    fun computeClientEnforcementState(
        isRestricted: Boolean,
        bandwidthLimitKbps: Int,
        counters: TunTrafficEngine.CounterSnapshot,
        datapathMode: DatapathMode = TunTrafficEngine.datapathMode,
        kernelAvailable: Boolean = isKernelNetfilterAvailable,
        isDegradedMultiClient: Boolean = TunTrafficEngine.isMultiClientDegraded,
    ): EnforcementState {
        if (!isRestricted && bandwidthLimitKbps <= 0) {
            return EnforcementState.UNRESTRICTED
        }

        val userspaceActive = datapathMode == DatapathMode.USERSPACE_PROXY
        if (!userspaceActive && !kernelAvailable) {
            return if (datapathMode == DatapathMode.DIRECT_TUN_FALLBACK) {
                EnforcementState.ENFORCEMENT_UNAVAILABLE
            } else {
                EnforcementState.CONFIGURED
            }
        }

        val postNatBypassObserved = !kernelAvailable && (isDegradedMultiClient || counters.unattributedPostNatObserved)
        val bpfMappedActive = !kernelAvailable && counters.bpfAttributedPackets > 0L

        if (isRestricted) {
            return when {
                bpfMappedActive && counters.policyVersionBlockedDrops > 0L -> EnforcementState.PARTIAL_BPF_ENFORCEMENT
                postNatBypassObserved -> EnforcementState.DEGRADED_MULTI_CLIENT
                counters.policyVersionBlockedDrops > 0L -> EnforcementState.PACKETS_DROPPED
                counters.matchedPackets > 0L -> EnforcementState.PACKETS_MATCHED
                kernelAvailable -> EnforcementState.POLICY_INSTALLED
                counters.policyInstalled -> EnforcementState.POLICY_INSTALLED
                userspaceActive -> EnforcementState.DATAPATH_ACTIVE
                else -> EnforcementState.CONFIGURED
            }
        }

        // Bandwidth limit active (and not blocked)
        return when {
            bpfMappedActive && (counters.shapingDropPackets > 0L || counters.shapedPackets > 0L || counters.shapedBytes > 0L) && postNatBypassObserved ->
                EnforcementState.PARTIAL_BPF_ENFORCEMENT
            postNatBypassObserved -> EnforcementState.DEGRADED_MULTI_CLIENT
            counters.shapingDropPackets > 0L || counters.shapedPackets > 0L || counters.shapedBytes > 0L -> EnforcementState.THROTTLING_OBSERVED
            counters.matchedPackets > 0L -> EnforcementState.PACKETS_MATCHED
            kernelAvailable -> EnforcementState.POLICY_INSTALLED
            counters.policyInstalled -> EnforcementState.POLICY_INSTALLED
            userspaceActive -> EnforcementState.DATAPATH_ACTIVE
            else -> EnforcementState.CONFIGURED
        }
    }

    @Synchronized
    fun enforce(
        rules: List<ClientRule>,
        connectedHosts: List<DiscoveredHost>,
        logSummary: Boolean = false,
    ): EnforcementSummary {
        ensureKernelCapabilityChecked()

        val nowMillis = System.currentTimeMillis()
        val currentHour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY)

        val activeHostMacs = connectedHosts.map { it.mac.uppercase().trim() }.toSet()

        for (mac in activeHostMacs) {
            clientConnectTimes.putIfAbsent(mac, nowMillis)
        }
        clientConnectTimes.keys.retainAll(activeHostMacs)

        val rulesByMac = rules
            .filter { it.mac.isNotBlank() }
            .associateBy { it.mac.uppercase().trim() }

        val targetBlockMacs = mutableSetOf<String>()
        val targetBlockIps = mutableSetOf<String>()
        val targetThrottleIps = mutableMapOf<String, Int>()

        val userspacePolicies = mutableMapOf<String, TunTrafficEngine.EnforcedClientPolicy>()

        var policyInstalledCount = 0
        var verifiedEnforcedCount = 0
        var blockedConnected = 0
        var throttledConnected = 0

        for (host in connectedHosts) {
            val upperMac = host.mac.uppercase().trim()
            val rule = rulesByMac[upperMac] ?: continue

            val hostIps = buildList {
                if (isValidIp(host.ip)) add(host.ip.trim())
                host.allIps.forEach { ip ->
                    if (isValidIp(ip)) add(ip.trim())
                }
            }.distinct()

            var shouldBlock = rule.isBlocked
            var blockReason: String? = if (rule.isBlocked) "manual block" else null

            if (!shouldBlock && rule.scheduleEnabled) {
                val allowed = if (rule.scheduleStartHour <= rule.scheduleEndHour) {
                    currentHour in rule.scheduleStartHour until rule.scheduleEndHour
                } else {
                    currentHour >= rule.scheduleStartHour || currentHour < rule.scheduleEndHour
                }
                if (!allowed) {
                    shouldBlock = true
                    blockReason = "schedule (${rule.scheduleStartHour}:00-${rule.scheduleEndHour}:00)"
                }
            }

            if (!shouldBlock && rule.connectionTimeLimitMinutes > 0) {
                val connectTime = clientConnectTimes[upperMac] ?: nowMillis
                val elapsedMinutes = (nowMillis - connectTime) / 60_000
                if (elapsedMinutes >= rule.connectionTimeLimitMinutes) {
                    shouldBlock = true
                    blockReason = "time limit (${elapsedMinutes}m >= ${rule.connectionTimeLimitMinutes}m)"
                }
            }

            if (shouldBlock) {
                blockedConnected++
                targetBlockMacs.add(upperMac)
                for (ip in hostIps) {
                    targetBlockIps.add(ip)
                }
            } else if (rule.bandwidthLimitKbps > 0) {
                throttledConnected++
                for (ip in hostIps) {
                    targetThrottleIps[ip] = rule.bandwidthLimitKbps
                }
            }

            userspacePolicies[upperMac] = TunTrafficEngine.EnforcedClientPolicy(
                mac = upperMac,
                isBlocked = shouldBlock,
                blockReason = blockReason,
                bandwidthLimitKbps = if (shouldBlock) 0 else rule.bandwidthLimitKbps,
            )
        }

        for ((mac, rule) in rulesByMac) {
            if (!userspacePolicies.containsKey(mac)) {
                if (rule.isBlocked || rule.bandwidthLimitKbps > 0) {
                    userspacePolicies[mac] = TunTrafficEngine.EnforcedClientPolicy(
                        mac = mac,
                        isBlocked = rule.isBlocked,
                        blockReason = if (rule.isBlocked) "pre-configured block" else null,
                        bandwidthLimitKbps = if (rule.isBlocked) 0 else rule.bandwidthLimitKbps,
                    )
                }
                if (rule.isBlocked) {
                    targetBlockMacs.add(mac)
                }
            }
        }

        TunTrafficEngine.updatePolicies(userspacePolicies, connectedHosts)

        if (isKernelNetfilterAvailable &&
            (capabilityMatrix.canWriteBothFamiliesNetfilter || capabilityMatrix.canWriteBothFamiliesIpRule)
        ) {
            syncKernelRules(targetBlockIps, targetBlockMacs, targetThrottleIps)
        }

        for (host in connectedHosts) {
            val upperMac = host.mac.uppercase().trim()
            val policy = userspacePolicies[upperMac] ?: continue
            val hasActiveRestriction = policy.isBlocked || policy.bandwidthLimitKbps > 0
            val counters = TunTrafficEngine.getCounterSnapshot(upperMac)
            val enforcementState = computeClientEnforcementState(
                isRestricted = policy.isBlocked,
                bandwidthLimitKbps = policy.bandwidthLimitKbps,
                counters = counters,
            )

            if (hasActiveRestriction) {
                if (enforcementState == EnforcementState.POLICY_INSTALLED ||
                    enforcementState == EnforcementState.PACKETS_MATCHED ||
                    enforcementState == EnforcementState.PACKETS_DROPPED ||
                    enforcementState == EnforcementState.PARTIAL_BPF_ENFORCEMENT ||
                    enforcementState == EnforcementState.THROTTLING_OBSERVED
                ) {
                    policyInstalledCount++
                }
                if (enforcementState == EnforcementState.PACKETS_DROPPED ||
                    enforcementState == EnforcementState.PARTIAL_BPF_ENFORCEMENT ||
                    enforcementState == EnforcementState.THROTTLING_OBSERVED
                ) {
                    verifiedEnforcedCount++
                }
            }

            val stateKey = "${policy.isBlocked}:${policy.blockReason}:${policy.bandwidthLimitKbps}:${enforcementState.name}:${counters.policyVersion}"
            if (lastLoggedStateByMac[upperMac] != stateKey) {
                lastLoggedStateByMac[upperMac] = stateKey
                val ipLabel = host.ip.ifBlank { "pending-ip" }
                when {
                    enforcementState == EnforcementState.ENFORCEMENT_UNAVAILABLE -> SessionLog.warn(
                        "TrafficControl: mac=$upperMac ($ipLabel) state=ENFORCEMENT_UNAVAILABLE " +
                            "reason=${TunTrafficEngine.fallbackReason ?: "datapath proxy inactive and kernel netfilter unavailable"}",
                    )
                    enforcementState == EnforcementState.DEGRADED_MULTI_CLIENT -> SessionLog.warn(
                        "TrafficControl: mac=$upperMac ($ipLabel) state=DEGRADED_MULTI_CLIENT " +
                            "policyVersion=${counters.policyVersion} policyBlockedDrops=${counters.policyVersionBlockedDrops} " +
                            "unattributedPostNat=true (post-NAT traffic observed without selective attribution)",
                    )
                    policy.isBlocked -> SessionLog.info(
                        "TrafficControl: mac=$upperMac ($ipLabel) policy=BLOCK(${policy.blockReason}) " +
                            "state=${enforcementState.name} policyVersion=${counters.policyVersion} " +
                            "policyBlockedDrops=${counters.policyVersionBlockedDrops} totalBlockedDrops=${counters.blockedDropPackets}",
                    )
                    policy.bandwidthLimitKbps > 0 -> SessionLog.info(
                        "TrafficControl: mac=$upperMac ($ipLabel) policy=RATE_LIMIT(${policy.bandwidthLimitKbps}kbps) " +
                            "state=${enforcementState.name} matchedPackets=${counters.matchedPackets} " +
                            "shapeDrops=${counters.shapingDropPackets} shapedBytes=${counters.shapedBytes}",
                    )
                    else -> SessionLog.info(
                        "TrafficControl: mac=$upperMac ($ipLabel) policy=UNRESTRICTED state=${enforcementState.name}",
                    )
                }
            }
        }

        lastLoggedStateByMac.keys.retainAll(activeHostMacs intersect rulesByMac.keys)

        val activeRulesCount = rules.count {
            it.isBlocked || it.bandwidthLimitKbps > 0 || it.connectionTimeLimitMinutes > 0 || it.scheduleEnabled
        }

        val backend = currentBackend()
        val summary = EnforcementSummary(
            configuredRulesCount = rules.size,
            activeRulesCount = activeRulesCount,
            connectedClientsCount = connectedHosts.size,
            policyInstalledOnConnectedCount = policyInstalledCount,
            verifiedEnforcedOnConnectedCount = verifiedEnforcedCount,
            blockedConnectedCount = blockedConnected,
            throttledConnectedCount = throttledConnected,
            datapathMode = TunTrafficEngine.datapathMode,
            firewallBackend = backend,
            kernelNetfilterAvailable = isKernelNetfilterAvailable,
        )

        if (logSummary) {
            SessionLog.info(
                "Rules sync: configured=${summary.activeRulesCount}/${summary.configuredRulesCount} " +
                    "connectedClients=${summary.connectedClientsCount} " +
                    "policyInstalled=${summary.policyInstalledOnConnectedCount} " +
                    "verifiedEnforced=${summary.verifiedEnforcedOnConnectedCount} " +
                    "backend=${summary.firewallBackend.name} datapath=${summary.datapathMode.name}",
            )
        }

        return summary
    }

    private fun syncKernelRules(
        targetBlockIps: Set<String>,
        targetBlockMacs: Set<String>,
        targetThrottleIps: Map<String, Int>,
    ) {
        val ipsToUnblock = currentlyBlockedIps - targetBlockIps
        for (ip in ipsToUnblock) {
            removeIpBlock(ip)
            currentlyBlockedIps.remove(ip)
        }

        val macsToUnblock = currentlyBlockedMacs - targetBlockMacs
        for (mac in macsToUnblock) {
            removeMacBlock(mac)
            currentlyBlockedMacs.remove(mac)
        }

        for ((ip, oldLimitPkt) in currentlyThrottledIps.toMap()) {
            val newKbps = targetThrottleIps[ip]
            val newLimitPkt = if (newKbps != null && newKbps > 0) kbpsToPktPerSec(newKbps) else null
            if (newLimitPkt == null || newLimitPkt != oldLimitPkt) {
                removeThrottle(ip, oldLimitPkt)
                currentlyThrottledIps.remove(ip)
            }
        }

        val ipsToBlock = targetBlockIps - currentlyBlockedIps
        for (ip in ipsToBlock) {
            if (applyIpBlock(ip)) {
                currentlyBlockedIps.add(ip)
            }
        }

        val macsToBlock = targetBlockMacs - currentlyBlockedMacs
        for (mac in macsToBlock) {
            if (applyMacBlock(mac)) {
                currentlyBlockedMacs.add(mac)
            }
        }

        for ((ip, limitKbps) in targetThrottleIps) {
            val limitPkt = kbpsToPktPerSec(limitKbps)
            if (currentlyThrottledIps[ip] != limitPkt) {
                if (applyThrottle(ip, limitPkt)) {
                    currentlyThrottledIps[ip] = limitPkt
                }
            }
        }
    }

    @Synchronized
    fun clearAll() {
        TunTrafficEngine.clearAll()
        if (isKernelNetfilterAvailable) {
            for (ip in currentlyBlockedIps.toList()) {
                removeIpBlock(ip)
            }
            for (mac in currentlyBlockedMacs.toList()) {
                removeMacBlock(mac)
            }
            for ((ip, limitPkt) in currentlyThrottledIps.toMap()) {
                removeThrottle(ip, limitPkt)
            }
        }
        currentlyBlockedIps.clear()
        currentlyBlockedMacs.clear()
        currentlyThrottledIps.clear()
        clientConnectTimes.clear()
        lastLoggedStateByMac.clear()
        lastLoggedBackendSignature = ""
    }

    private fun kbpsToPktPerSec(limitKbps: Int): Int =
        maxOf(2, (limitKbps * 1000) / (1400 * 8))

    private fun applyIpBlock(ip: String): Boolean {
        if (!isValidIp(ip)) return false
        val isIpv6 = ip.contains(':')
        var blocked = false
        if (isIpv6) {
            if (capabilityMatrix.canWriteNetfilterV6) {
                val r1 = executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-s", ip, "-j", "DROP")
                val r2 = executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-d", ip, "-j", "DROP")
                if (r1.isSuccess && r2.isSuccess) blocked = true
            }
            if (capabilityMatrix.canWriteIpRuleV6) {
                val r3 = executePrivilegedCommand("ip", "-6", "rule", "add", "from", "$ip/128", "unreachable", "priority", "100")
                if (r3.isSuccess) blocked = true
            }
        } else {
            if (capabilityMatrix.canWriteNetfilterV4) {
                val r1 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP")
                val r2 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP")
                if (r1.isSuccess && r2.isSuccess) blocked = true
            }
            if (capabilityMatrix.canWriteIpRuleV4) {
                val r3 = executePrivilegedCommand("ip", "rule", "add", "from", "$ip/32", "unreachable", "priority", "100")
                if (r3.isSuccess) blocked = true
            }
        }
        return blocked
    }

    private fun removeIpBlock(ip: String) {
        val isIpv6 = ip.contains(':')
        if (isIpv6) {
            if (capabilityMatrix.canWriteNetfilterV6) {
                executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
                executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-d", ip, "-j", "DROP")
            }
            if (capabilityMatrix.canWriteIpRuleV6) {
                executePrivilegedCommand("ip", "-6", "rule", "del", "from", "$ip/128", "unreachable", "priority", "100")
            }
        } else {
            if (capabilityMatrix.canWriteNetfilterV4) {
                executePrivilegedCommand("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
                executePrivilegedCommand("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP")
            }
            if (capabilityMatrix.canWriteIpRuleV4) {
                executePrivilegedCommand("ip", "rule", "del", "from", "$ip/32", "unreachable", "priority", "100")
            }
        }
    }

    private fun applyMacBlock(mac: String): Boolean {
        if (!capabilityMatrix.canWriteNetfilterV4) return false
        val r1 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        if (capabilityMatrix.canWriteNetfilterV6) {
            executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        }
        return r1.isSuccess
    }

    private fun removeMacBlock(mac: String) {
        if (capabilityMatrix.canWriteNetfilterV4) {
            executePrivilegedCommand("iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        }
        if (capabilityMatrix.canWriteNetfilterV6) {
            executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        }
    }

    private fun applyThrottle(ip: String, limitPkt: Int): Boolean {
        if (!isValidIp(ip)) return false
        val isV6 = ip.contains(':')
        if (isV6 && !capabilityMatrix.canWriteNetfilterV6) return false
        if (!isV6 && !capabilityMatrix.canWriteNetfilterV4) return false
        val burst = maxOf(4, limitPkt * 2)
        val cmdBin = if (isV6) "ip6tables" else "iptables"
        val r1 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-s", ip, "-j", "DROP")
        val r2 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-s", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        val r3 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-d", ip, "-j", "DROP")
        val r4 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-d", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        return r1.isSuccess && r2.isSuccess && r3.isSuccess && r4.isSuccess
    }

    private fun removeThrottle(ip: String, limitPkt: Int) {
        val isV6 = ip.contains(':')
        if (isV6 && !capabilityMatrix.canWriteNetfilterV6) return
        if (!isV6 && !capabilityMatrix.canWriteNetfilterV4) return
        val burst = maxOf(4, limitPkt * 2)
        val cmdBin = if (isV6) "ip6tables" else "iptables"
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-s", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-s", ip, "-j", "DROP")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-d", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-d", ip, "-j", "DROP")
    }

    /**
     * Executes a command directly in the current Shizuku UserService identity without invoking `su`.
     */
    internal fun executePrivilegedCommand(vararg cmd: String): CommandResult = executeCommand(*cmd)

    /**
     * Validates a per-client IP address.
     * NEVER accepts shared NAT tunnel addresses (`192.0.2.2` / `2001:db8::2`), preventing any
     * accidental global DROP or throttle rule from affecting other connected hotspot clients.
     */
    internal fun isValidIp(ip: String): Boolean {
        val clean = ip.trim()
        if (clean.isBlank()) return false
        if (clean == TunTrafficEngine.TUN_LOCAL_V4 ||
            clean == TunTrafficEngine.TUN_LOCAL_V6 ||
            TunTrafficEngine.normalizeIp(clean) == TunTrafficEngine.TUN_LOCAL_V6_NORMALIZED
        ) {
            return false
        }
        return clean != "Dynamic IP" &&
            !clean.startsWith("Assigning") &&
            !clean.startsWith("HOTSPOT") &&
            !clean.startsWith("DHCP") &&
            !clean.startsWith("Offline")
    }

    internal fun readBoundedStream(stream: InputStream, maxBytes: Int = MAX_CAPTURED_BYTES): String {
        return runCatching {
            val buffer = ByteArray(1024)
            val out = java.io.ByteArrayOutputStream()
            var total = 0
            while (total < maxBytes) {
                val toRead = minOf(buffer.size, maxBytes - total)
                val read = stream.read(buffer, 0, toRead)
                if (read <= 0) break
                out.write(buffer, 0, read)
                total += read
            }
            // Drain any remaining bytes without storing so the child process never blocks on pipe buffer
            while (stream.read(buffer) > 0) {
                // discard beyond limit
            }
            out.toString(Charsets.UTF_8.name()).trim()
        }.getOrDefault("")
    }

    internal fun executeCommand(
        vararg cmd: String,
        timeoutMs: Long = CMD_TIMEOUT_MS,
        maxBytes: Int = MAX_CAPTURED_BYTES,
    ): CommandResult {
        val joined = cmd.joinToString(" ")
        return runCatching {
            val process = ProcessBuilder(*cmd).start()
            var stdoutText = ""
            var stderrText = ""
            val outReader = thread(start = true, isDaemon = true, name = "cmd-stdout") {
                stdoutText = readBoundedStream(process.inputStream, maxBytes)
            }
            val errReader = thread(start = true, isDaemon = true, name = "cmd-stderr") {
                stderrText = readBoundedStream(process.errorStream, maxBytes)
            }

            val finished = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!finished) {
                process.destroyForcibly()
                outReader.join(200)
                errReader.join(200)
                return CommandResult(
                    command = joined,
                    exitCode = -1,
                    stdout = stdoutText,
                    stderr = stderrText.ifBlank { "Command timed out after ${timeoutMs}ms" },
                    timedOut = true,
                    errorKind = ProbeErrorKind.TIMEOUT,
                )
            }

            outReader.join(300)
            errReader.join(300)
            val code = process.exitValue()
            if (code != 0) {
                Log.d(TAG, "Command non-zero ($code): $joined -> $stderrText")
            }
            CommandResult(
                command = joined,
                exitCode = code,
                stdout = stdoutText,
                stderr = stderrText,
                timedOut = false,
            )
        }.getOrElse { err ->
            val msg = err.message ?: err.javaClass.simpleName
            CommandResult(
                command = joined,
                exitCode = -1,
                stdout = "",
                stderr = msg,
                timedOut = false,
            )
        }
    }
}
