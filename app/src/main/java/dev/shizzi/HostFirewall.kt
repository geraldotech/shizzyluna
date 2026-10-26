package dev.shizzi

import android.system.Os
import android.util.Log
import java.util.Calendar
import java.util.concurrent.TimeUnit

enum class EnforcementState {
    UNRESTRICTED,
    CONFIGURED,
    DATAPATH_ACTIVE,
    POLICY_INSTALLED,
    PACKETS_MATCHED,
    PACKETS_DROPPED,
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

object HostFirewall {

    private const val TAG = "HostFirewall"
    private const val CMD_TIMEOUT_MS = 1_500L

    data class CommandResult(
        val command: String,
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val timedOut: Boolean,
    ) {
        val isSuccess: Boolean get() = !timedOut && exitCode == 0
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

    private fun resolveUid(): Int {
        if (processUid >= 0) return processUid
        processUid = runCatching { Os.getuid() }.getOrDefault(2000)
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
        return suPaths.any { java.io.File(it).exists() } || runCatching {
            val p = ProcessBuilder("which", "su").start()
            val finished = p.waitFor(500, TimeUnit.MILLISECONDS)
            finished && p.exitValue() == 0
        }.getOrDefault(false)
    }

    private fun ensureKernelCapabilityChecked() {
        val uid = resolveUid()
        if (!kernelCapabilityChecked) {
            kernelCapabilityChecked = true
            isSuAvailable = checkSuPresence()

            // 1. Probe iptables (direct and via su if available)
            val iptablesProbe = executePrivilegedCommand("iptables", "-L", "FORWARD", "-n")

            // 2. Probe ip rule policy routing (direct and via su if available)
            val ipRuleProbe = executePrivilegedCommand("ip", "rule", "show")
            isIpRuleAvailable = ipRuleProbe.isSuccess

            isKernelNetfilterAvailable = iptablesProbe.isSuccess || isIpRuleAvailable

            if (!isKernelNetfilterAvailable && uid == 0) {
                SessionLog.warn(
                    "Firewall: root uid=0 iptables/ip-rule probe failed: ${iptablesProbe.stderr} | ${ipRuleProbe.stderr}",
                )
            }
        }

        val userspaceActive = TunTrafficEngine.isAttached
        val backend = currentBackend(userspaceActive, isKernelNetfilterAvailable)
        val sig = "${backend.name}:$isKernelNetfilterAvailable:$isIpRuleAvailable:$isSuAvailable:$uid:${TunTrafficEngine.datapathMode.name}"
        if (lastLoggedBackendSignature != sig) {
            lastLoggedBackendSignature = sig
            SessionLog.info(
                "Firewall: backend=${backend.name} kernelNetfilterAvailable=$isKernelNetfilterAvailable ipRuleAvailable=$isIpRuleAvailable suAvailable=$isSuAvailable uid=$uid datapath=${TunTrafficEngine.datapathMode.name}",
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

        if (isRestricted) {
            return when {
                counters.droppedPackets > 0 -> EnforcementState.PACKETS_DROPPED
                counters.matchedPackets > 0 -> EnforcementState.PACKETS_MATCHED
                kernelAvailable -> EnforcementState.POLICY_INSTALLED
                isDegradedMultiClient -> EnforcementState.DEGRADED_MULTI_CLIENT
                counters.policyInstalled -> EnforcementState.POLICY_INSTALLED
                userspaceActive -> EnforcementState.DATAPATH_ACTIVE
                else -> EnforcementState.CONFIGURED
            }
        }

        // Bandwidth limit active (and not blocked)
        return when {
            counters.shapedPackets > 0 || counters.shapedBytes > 0 -> EnforcementState.THROTTLING_OBSERVED
            counters.matchedPackets > 0 -> EnforcementState.PACKETS_MATCHED
            kernelAvailable -> EnforcementState.POLICY_INSTALLED
            isDegradedMultiClient -> EnforcementState.DEGRADED_MULTI_CLIENT
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

        // Track first-seen times for currently connected hosts; prune disconnected hosts
        for (mac in activeHostMacs) {
            clientConnectTimes.putIfAbsent(mac, nowMillis)
        }
        clientConnectTimes.keys.retainAll(activeHostMacs)

        val rulesByMac = rules
            .filter { it.mac.isNotBlank() }
            .associateBy { it.mac.uppercase().trim() }

        val targetBlockMacs = mutableSetOf<String>()
        val targetBlockIps = mutableSetOf<String>()
        val targetThrottleIps = mutableMapOf<String, Int>() // IP -> kbps

        val userspacePolicies = mutableMapOf<String, TunTrafficEngine.EnforcedClientPolicy>()

        var policyInstalledCount = 0
        var verifiedEnforcedCount = 0
        var blockedConnected = 0
        var throttledConnected = 0

        // 1. Evaluate rules for all verified connected clients
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

            // Schedule check
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

            // Connection time limit check
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

        // 2. Also register pre-configured rules for offline MACs in TunTrafficEngine
        // so if they connect, their first packet is immediately subject to the policy
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

        // 3. Push policies and verified connected hosts to TunTrafficEngine FIRST
        TunTrafficEngine.updatePolicies(userspacePolicies, connectedHosts)

        // 4. If kernel netfilter is available (UID 0 / CAP_NET_ADMIN), synchronize kernel rules
        // and verify command exit codes before recording them as applied
        if (isKernelNetfilterAvailable) {
            syncKernelRules(targetBlockIps, targetBlockMacs, targetThrottleIps)
        }

        // 5. Compute honest per-client enforcement states from actual datapath & packet counters
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
                    enforcementState == EnforcementState.THROTTLING_OBSERVED
                ) {
                    policyInstalledCount++
                }
                if (enforcementState == EnforcementState.PACKETS_DROPPED ||
                    enforcementState == EnforcementState.THROTTLING_OBSERVED ||
                    enforcementState == EnforcementState.PACKETS_MATCHED
                ) {
                    verifiedEnforcedCount++
                }
            }

            val stateKey = "${policy.isBlocked}:${policy.blockReason}:${policy.bandwidthLimitKbps}:${enforcementState.name}"
            if (lastLoggedStateByMac[upperMac] != stateKey) {
                lastLoggedStateByMac[upperMac] = stateKey
                val ipLabel = host.ip.ifBlank { "pending-ip" }
                when {
                    enforcementState == EnforcementState.ENFORCEMENT_UNAVAILABLE -> SessionLog.warn(
                        "TrafficControl: mac=$upperMac ($ipLabel) state=ENFORCEMENT_UNAVAILABLE " +
                            "reason=${TunTrafficEngine.fallbackReason ?: "datapath proxy inactive and kernel netfilter unavailable"}",
                    )
                    policy.isBlocked -> SessionLog.info(
                        "TrafficControl: mac=$upperMac ($ipLabel) policy=BLOCK(${policy.blockReason}) " +
                            "state=${enforcementState.name} droppedPackets=${counters.droppedPackets}",
                    )
                    policy.bandwidthLimitKbps > 0 -> SessionLog.info(
                        "TrafficControl: mac=$upperMac ($ipLabel) policy=RATE_LIMIT(${policy.bandwidthLimitKbps}kbps) " +
                            "state=${enforcementState.name} matchedPackets=${counters.matchedPackets} shapedBytes=${counters.shapedBytes}",
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
                    "verifiedPacketMatches=${summary.verifiedEnforcedOnConnectedCount} " +
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
        val isIpv6 = ip.contains(':')
        var blocked = false
        if (isIpv6) {
            val r1 = executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-s", ip, "-j", "DROP")
            val r2 = executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-d", ip, "-j", "DROP")
            if (r1.isSuccess || r2.isSuccess) blocked = true
            if (isIpRuleAvailable) {
                val r3 = executePrivilegedCommand("ip", "-6", "rule", "add", "from", "$ip/128", "unreachable", "priority", "100")
                if (r3.isSuccess) blocked = true
            }
        } else {
            val r1 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP")
            val r2 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP")
            if (r1.isSuccess || r2.isSuccess) blocked = true
            if (isIpRuleAvailable) {
                val r3 = executePrivilegedCommand("ip", "rule", "add", "from", "$ip/32", "unreachable", "priority", "100")
                if (r3.isSuccess) blocked = true
            }
        }
        return blocked
    }

    private fun removeIpBlock(ip: String) {
        val isIpv6 = ip.contains(':')
        if (isIpv6) {
            executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
            executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-d", ip, "-j", "DROP")
            if (isIpRuleAvailable) {
                executePrivilegedCommand("ip", "-6", "rule", "del", "from", "$ip/128", "unreachable", "priority", "100")
            }
        } else {
            executePrivilegedCommand("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
            executePrivilegedCommand("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP")
            if (isIpRuleAvailable) {
                executePrivilegedCommand("ip", "rule", "del", "from", "$ip/32", "unreachable", "priority", "100")
            }
        }
    }

    private fun applyMacBlock(mac: String): Boolean {
        val r1 = executePrivilegedCommand("iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        executePrivilegedCommand("ip6tables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        return r1.isSuccess
    }

    private fun removeMacBlock(mac: String) {
        executePrivilegedCommand("iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
        executePrivilegedCommand("ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP")
    }

    private fun applyThrottle(ip: String, limitPkt: Int): Boolean {
        val burst = maxOf(4, limitPkt * 2)
        val cmdBin = if (ip.contains(':')) "ip6tables" else "iptables"
        val r1 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-s", ip, "-j", "DROP")
        val r2 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-s", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        val r3 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-d", ip, "-j", "DROP")
        val r4 = executePrivilegedCommand(cmdBin, "-I", "FORWARD", "-d", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        return r1.isSuccess && r2.isSuccess && r3.isSuccess && r4.isSuccess
    }

    private fun removeThrottle(ip: String, limitPkt: Int) {
        val burst = maxOf(4, limitPkt * 2)
        val cmdBin = if (ip.contains(':')) "ip6tables" else "iptables"
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-s", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-s", ip, "-j", "DROP")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-d", ip, "-m", "limit", "--limit", "${limitPkt}/s", "--limit-burst", "$burst", "-j", "ACCEPT")
        executePrivilegedCommand(cmdBin, "-D", "FORWARD", "-d", ip, "-j", "DROP")
    }

    internal fun executePrivilegedCommand(vararg cmd: String): CommandResult {
        val direct = executeCommand(*cmd)
        if (direct.isSuccess) return direct
        if (isSuAvailable) {
            val suRes = executeCommand("su", "-c", cmd.joinToString(" "))
            if (suRes.isSuccess) return suRes
        }
        return direct
    }

    private fun isValidIp(ip: String): Boolean =
        ip.isNotBlank() &&
            ip != "Dynamic IP" &&
            !ip.startsWith("Assigning") &&
            !ip.startsWith("HOTSPOT") &&
            !ip.startsWith("DHCP") &&
            !ip.startsWith("Offline")

    internal fun executeCommand(vararg cmd: String): CommandResult {
        val joined = cmd.joinToString(" ")
        return runCatching {
            val process = ProcessBuilder(*cmd).start()
            val finished = process.waitFor(CMD_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            if (!finished) {
                process.destroyForcibly()
                return CommandResult(
                    command = joined,
                    exitCode = -1,
                    stdout = "",
                    stderr = "Command timed out after ${CMD_TIMEOUT_MS}ms",
                    timedOut = true,
                )
            }
            val stdout = runCatching { process.inputStream.bufferedReader().use { it.readText().trim() } }.getOrDefault("")
            val stderr = runCatching { process.errorStream.bufferedReader().use { it.readText().trim() } }.getOrDefault("")
            val code = process.exitValue()
            if (code != 0) {
                Log.d(TAG, "Kernel command non-zero ($code): $joined -> $stderr")
            }
            CommandResult(
                command = joined,
                exitCode = code,
                stdout = stdout,
                stderr = stderr,
                timedOut = false,
            )
        }.getOrElse { err ->
            CommandResult(
                command = joined,
                exitCode = -1,
                stdout = "",
                stderr = err.message ?: err.javaClass.simpleName,
                timedOut = false,
            )
        }
    }
}
