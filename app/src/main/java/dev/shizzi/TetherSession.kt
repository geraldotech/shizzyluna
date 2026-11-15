package dev.shizzi

import android.content.Context
import android.os.Build
import android.util.Log
import org.json.JSONObject

enum class SessionState { IDLE, STARTING, ACTIVE, ERROR }

class TetherSession(private val context: Context) {

    private val testNetworkApi = TestNetworkApi(context)
    private val inspector = UpstreamInspector()

    private var resources: SessionResources? = null
    private var state = SessionState.IDLE
    private var detail = "not started"
    private var interfaceName: String? = null

    private var activeSince: Long = 0
    private var vpnMode = VpnMode.AUTO
    private var watchdog: SessionWatchdog? = null
    private val teardown = SessionTeardown(context)
    private val downstream = DownstreamInspector(inspector = inspector, context = context)
    private val vpn = VpnUpstream(context) { problem -> tearDownAfter(problem) }
    private var activeRules = listOf<ClientRule>()

    val isActive: Boolean get() = state == SessionState.ACTIVE

    fun runFirewallDiagnostics(): String =
        FirewallDiagnosticRunner.runReadOnlyDiagnostic(
            context = context,
            downstreamInspector = downstream,
            upstreamInterfaceName = interfaceName,
            vpnActive = vpn.isBound || vpn.isVpnPresent(),
        ).toJsonString()

    fun runFirewallClientPoc(
        clientAMac: String,
        clientBMac: String,
        durationSec: Int,
    ): String =
        FirewallDiagnosticRunner.runTemporaryClientPoc(
            context = context,
            downstreamInspector = downstream,
            upstreamInterfaceName = interfaceName,
            vpnActive = vpn.isBound || vpn.isVpnPresent(),
            clientAMac = clientAMac,
            clientBMac = clientBMac,
            durationSec = durationSec,
        ).toJsonString()

    fun cleanupFirewallTestRules(): String =
        FirewallDiagnosticRunner.recoverOrphanedTestRules()

    fun setExperimentalBpfConfig(enabled: Boolean, pollIntervalMs: Int): String {
        val downIface = if (isActive) {
            downstream.inspectSnapshot(forceRefresh = false).apInterfaces.firstOrNull().orEmpty()
        } else {
            ""
        }
        TunTrafficEngine.configureExperimentalBpf(
            enabled = enabled,
            pollIntervalMs = pollIntervalMs.toLong(),
            downstreamIface = downIface,
            upstreamIface = interfaceName.orEmpty(),
        )
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun collectBpfSnapshotNow(): String {
        if (isActive) {
            val snapshot = downstream.inspectSnapshot(forceRefresh = true)
            HostFirewall.enforce(activeRules, snapshot.clients, logSummary = false)
            val downIface = snapshot.apInterfaces.firstOrNull().orEmpty()
            TunTrafficEngine.bpfAttributor.syncInterfaces(downIface, interfaceName.orEmpty())
        }
        return TunTrafficEngine.collectBpfSnapshotNow().toJson().toString()
    }

    fun setBpfRefreshOnMissConfig(enabled: Boolean, cooldownMs: Int): String {
        TunTrafficEngine.configureBpfRefreshOnMiss(
            enabled = enabled,
            cooldownMs = cooldownMs.toLong(),
        )
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun setDeepTupleDiagnosticsEnabled(enabled: Boolean): String {
        TunTrafficEngine.configureDeepTupleDiagnostics(enabled = enabled)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun resetBpfDiagnosticsCounters(): String {
        TunTrafficEngine.resetAttributionDiagnosticsCounters()
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun setPhaseDEnforcementMode(mode: String): String {
        val parsed = runCatching { PhaseDEnforcementMode.valueOf(mode.trim()) }
            .getOrDefault(PhaseDEnforcementMode.DIAGNOSTIC)
        TunTrafficEngine.configurePhaseDMode(parsed)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun recordPhaseDDeliveryTestMarker(markerType: String, note: String): String {
        TunTrafficEngine.recordDeliveryTestMarker(markerType = markerType, note = note)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun setStopHotspotOnVpnDisconnect(enabled: Boolean): String {
        vpn.updateStopHotspotOnVpnDisconnect(enabled)
        return status()
    }

    fun setDnsAttributionRetryConfig(enabled: Boolean, maxWaitMs: Int): String {
        TunTrafficEngine.configureDnsAttributionRetry(
            enabled = enabled,
            maxWaitMs = maxWaitMs.toLong(),
        )
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    private fun syncInterfacesIfActive() {
        if (isActive) {
            val snapshot = downstream.inspectSnapshot(forceRefresh = false)
            HostFirewall.enforce(activeRules, snapshot.clients, logSummary = false)
            val downIface = snapshot.apInterfaces.firstOrNull().orEmpty()
            TunTrafficEngine.bpfAttributor.syncInterfaces(downIface, interfaceName.orEmpty())
        }
    }

    fun selectBlockingMode(mode: String): String {
        syncInterfacesIfActive()
        val parsed = runCatching { BlockingMode.valueOf(mode.trim()) }
            .getOrDefault(BlockingMode.BPF_NAT_VPN)
        ExclusiveBlockingModeController.selectRequestedMode(parsed)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun checkPreNatCapability(): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.checkCapabilityReadOnly()
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun reviewPreNatScopedProbe(): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.reviewScopedProbePlan()
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun runPreNatScopedProbe(userConfirmed: Boolean): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.runUserApprovedScopedProbe(userConfirmed)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun activatePreNatBlockingMode(): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.activatePreNatMode()
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun restoreBpfBlockingMode(): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.restoreBpfNatVpnMode(reason = "User requested restore current engine")
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun checkSoftApCapability(): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.checkSoftApCapability()
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun runSoftApLiveProbe(
        clientAMac: String,
        clientBMac: String,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Int,
    ): String {
        syncInterfacesIfActive()
        ExclusiveBlockingModeController.runSoftApLiveProbe(
            clientAMac = clientAMac,
            clientBMac = clientBMac,
            userConfirmed = userConfirmed,
            disconnectTimeoutMs = disconnectTimeoutMs.coerceIn(500, 30_000).toLong(),
        )
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun activateSoftApBlockingMode(): String {
        syncInterfacesIfActive()
        val clients = if (isActive) downstream.listDiscoveredClients(forceRefresh = true) else emptyList()
        ExclusiveBlockingModeController.activateSoftApBlockingMode(
            rules = activeRules,
            discoveredHosts = clients,
        )
        HostFirewall.enforce(activeRules, clients, logSummary = true)
        return TunTrafficEngine.getBpfAttributionReport().toJson().toString()
    }

    fun updateRules(rulesJson: String) {
        val previousCount = activeRules.size
        activeRules = ClientRule.parseList(rulesJson)
        val clients = if (isActive) downstream.listDiscoveredClients(forceRefresh = true) else emptyList()
        val shouldLog = activeRules.isNotEmpty() || previousCount > 0
        val summary = HostFirewall.enforce(activeRules, clients, logSummary = shouldLog)
        if (shouldLog) {
            SessionLog.info(
                "Applying ${summary.activeRulesCount} client rule(s) in real time " +
                    "(policyInstalled=${summary.policyInstalledOnConnectedCount}/${summary.connectedClientsCount}, " +
                    "verifiedMatches=${summary.verifiedEnforcedOnConnectedCount}, " +
                    "backend=${summary.firewallBackend.name}, datapath=${summary.datapathMode.name})",
            )
        }
    }

    fun updateDomainRules(domainRulesJson: String) {
        val parsed = DomainRule.deserializeList(domainRulesJson)
        DomainFilterEngine.replaceAllRules(parsed)
        val globalCount = parsed.count { it.scope == DomainRuleScope.GLOBAL && it.enabled }
        val clientCount = parsed.count { it.scope == DomainRuleScope.CLIENT && it.enabled }
        SessionLog.info(
            "Domain filter rules updated: total=${parsed.size} (enabledGlobal=$globalCount, enabledPerHost=$clientCount, gen=${DomainFilterEngine.currentRuleGeneration()})",
        )
    }

    fun resetClientQuota(mac: String) {
        val cleanMac = mac.uppercase().trim()
        if (cleanMac.length != 17) return
        val resetRecord = TunTrafficEngine.resetClientQuota(cleanMac)
        activeRules = activeRules.map { rule ->
            if (rule.cleanMac == cleanMac) {
                val winStart = resetRecord?.windowStartEpochMs ?: System.currentTimeMillis()
                val winId = resetRecord?.windowId ?: rule.quotaWindowId
                val gen = resetRecord?.resetGeneration ?: (rule.quotaResetGeneration + 1L)
                rule.copy(
                    quotaUsedRxBytes = 0L,
                    quotaUsedTxBytes = 0L,
                    quotaWindowId = winId,
                    quotaWindowStartEpochMs = winStart,
                    quotaLastUpdatedEpochMs = System.currentTimeMillis(),
                    quotaResetGeneration = gen,
                )
            } else {
                rule
            }
        }
        val clients = if (isActive) downstream.listDiscoveredClients(forceRefresh = true) else emptyList()
        HostFirewall.enforce(activeRules, clients, logSummary = false)
    }

    fun start(
        mode: VpnMode = VpnMode.AUTO,
        customDnsList: List<String>? = null,
    ): String {
        if (isActive) return status()

        vpnMode = mode
        state = SessionState.STARTING
        SessionLog.info("session start requested (vpn mode ${mode.name.lowercase()})")

        SessionLog.info(
            "device: ${Build.MANUFACTURER} ${Build.MODEL}, " +
                "android ${Build.VERSION.RELEASE} (sdk ${Build.VERSION.SDK_INT}), " +
                "contract ${TetherService.CONTRACT_VERSION}",
        )

        val dnsServers = resolveDnsServers(customDnsList)
        SessionLog.info("configured dns servers: ${dnsServers.map { it.hostAddress }}")

        return runCatching { bringUp(dnsServers) }
            .getOrElse { failure ->
                Log.e(TAG, "start failed", failure)
                SessionLog.error(
                    "start failed: ${failure.javaClass.simpleName}: ${failure.message}",
                )
                stop()
                state = SessionState.ERROR
                detail = "${failure.javaClass.simpleName}: ${failure.message}"
                status()
            }
    }

    private fun resolveDnsServers(customDnsList: List<String>?): List<java.net.InetAddress> {
        if (customDnsList.isNullOrEmpty()) return TEST_NETWORK_DNS_SERVERS
        val parsed = customDnsList.mapNotNull {
            runCatching { java.net.InetAddress.getByName(it.trim()) }.getOrNull()
        }
        return parsed.ifEmpty { TEST_NETWORK_DNS_SERVERS }
    }

    private fun bringUp(dnsServers: List<java.net.InetAddress>): String {
        val group = SessionResources(testNetworkApi, context.connectivityManager())
        resources = group

        val name = group.acquire(tunAddresses(), dnsServers, AVAILABILITY_TIMEOUT_MS)
        interfaceName = name
        SessionLog.info("tun up: $name (mtu $TUN_MTU, $TUN_ADDRESS, $TUN_ADDRESS_V6)")

        group.startDatapath(TUN_MTU)
        SessionLog.info("datapath attached to $name")
        followVpn(group)

        preferTestNetworks()
        restartDownstream()

        verifyUpstream(name)
        SessionLog.info("upstream verified: $name is sole upstream")

        val initialSnapshot = downstream.inspectSnapshot(forceRefresh = true)
        val initialDownstream = initialSnapshot.apInterfaces.firstOrNull().orEmpty()
        TunTrafficEngine.bpfAttributor.syncInterfaces(initialDownstream, name)

        state = SessionState.ACTIVE
        activeSince = System.currentTimeMillis()
        detail = "tethered clients routing through $name"

        teardown.installShutdownHook()
        startWatchdog(name)
        return status()
    }

    private fun followVpn(group: SessionResources) {
        if (vpnMode == VpnMode.NEVER) {
            vpn.configureForSessionStart(VpnMode.NEVER)
            SessionLog.info("vpn mode never: datapath left unbound")
            return
        }

        check(vpnMode != VpnMode.ALWAYS || vpn.isVpnPresent()) {
            "followVpn: vpn mode always requires an active VPN, none is connected"
        }
        vpn.follow(group, vpnMode)
    }

    private fun startWatchdog(name: String) {
        val guard = SessionWatchdog(name) { problem ->
            SessionLog.warn("upstream drift: $problem")
            tearDownAfter(problem)
        }
        watchdog = guard
        guard.start()
    }

    private fun tearDownAfter(problem: String) {
        stop()

        val teardownProblem = detail.takeIf { state == SessionState.ERROR }
        state = SessionState.ERROR
        detail = when (teardownProblem) {
            null -> problem
            else -> "$problem; teardown incomplete: $teardownProblem"
        }
    }

    private fun preferTestNetworks() {
        val api = TetheringPreferenceApi(context)
        runCatching { api.setPreferTestNetworks(false) }
            .onFailure { SessionLog.warn("could not clear the stale test-network preference: ${it.message}") }
        api.setPreferTestNetworks(true)
    }

    private fun restartDownstream() {
        val control = DownstreamControl(context)
        control.stopWifiTethering()

        val (didStart, startDetail) = control.startWifiTethering()
        check(didStart) { "restartDownstream: hotspot did not start ($startDetail)" }

        awaitDownstreamTethered()
    }

    private fun awaitDownstreamTethered() {
        val deadline = System.currentTimeMillis() + DOWNSTREAM_SETTLE_MS
        val downstream = DownstreamInspector()

        while (System.currentTimeMillis() < deadline) {

            if (downstream.findTetheredDownstream() != null) {
                SessionLog.info("downstream tethered")
                return
            }
            Thread.sleep(DOWNSTREAM_POLL_MS)
        }

        SessionLog.warn("downstream not tethered after ${DOWNSTREAM_SETTLE_MS}ms; continuing")
    }

    private fun verifyUpstream(name: String) {
        val deadline = System.currentTimeMillis() + UPSTREAM_SETTLE_MS
        var observed = liveUpstreams(name)

        while (System.currentTimeMillis() < deadline) {
            if (observed.isNotEmpty() && observed.all { it == name }) return
            Thread.sleep(UPSTREAM_POLL_MS)
            observed = liveUpstreams(name)
        }
        error("verifyUpstream: expected only $name, tethering reports $observed")
    }

    private fun liveUpstreams(owned: String): List<String> =
        inspector.observe().liveInterfaceNames(owned)

    fun stop(): String {
        watchdog?.stop()
        watchdog = null
        vpn.stop()
        teardown.removeShutdownHook()
        HostFirewall.clearAll()
        ExclusiveBlockingModeController.onSessionOrInterfacesChanged(
            downstreamIface = "",
            upstreamIface = "",
            sessionGeneration = TunTrafficEngine.bpfAttributor.currentSessionGeneration,
        )

        val summary = if (activeSince == 0L) null else sessionSummary()

        val downstreamProblem = teardown.releaseDownstream()

        teardown.releaseUpstreamSelection(interfaceName)

        val releaseProblems = resources?.release().orEmpty()
        resources = null

        interfaceName = null
        activeSince = 0
        state = if (downstreamProblem == null) SessionState.IDLE else SessionState.ERROR
        detail = downstreamProblem ?: "stopped"

        when (downstreamProblem) {
            null -> SessionLog.info("session stopped; downstream confirmed down")
            else -> SessionLog.error("teardown: $downstreamProblem")
        }
        if (releaseProblems.isNotEmpty()) {
            SessionLog.warn("${releaseProblems.size} resource(s) not released cleanly")
        }
        summary?.let(SessionLog::info)
        return status()
    }

    private fun sessionSummary(): String {
        val traffic = interfaceName?.let(InterfaceCounters::read) ?: Traffic()
        val elapsed = when (activeSince) {
            0L -> 0L
            else -> System.currentTimeMillis() - activeSince
        }

        return "session summary: active ${formatDuration(elapsed)}, " +
            "${Traffic.format(traffic.up)} up, ${Traffic.format(traffic.down)} down"
    }

    private fun formatDuration(millis: Long): String {
        val totalSeconds = millis / 1000
        val hours = totalSeconds / 3600
        val minutes = (totalSeconds % 3600) / 60
        val seconds = totalSeconds % 60

        return when {
            hours > 0 -> "${hours}h ${minutes}m"
            minutes > 0 -> "${minutes}m ${seconds}s"
            else -> "${seconds}s"
        }
    }

    fun status(): String = JSONObject().apply {
        val bypassed = isVpnBypassed()
        val vpnDiag = vpn.buildDiagnostics(isSessionActive = isActive, isVpnBypassed = bypassed)
        val effectiveDetail = when {
            isActive && vpnDiag.vpnLifecycleState == VpnLifecycleState.VPN_WAITING_FOR_RECOVERY ->
                "VPN disconnected — waiting for reconnection"
            isActive && vpnDiag.vpnLifecycleState == VpnLifecycleState.VPN_REBINDING ->
                "VPN reconnecting — re-binding datapath"
            isActive && vpnDiag.vpnLifecycleState == VpnLifecycleState.VPN_RECOVERY_FAILED ->
                "VPN reconnect failed — retrying (traffic paused)"
            else -> detail
        }
        put("state", state.name)
        put("detail", effectiveDetail)
        put("interface", interfaceName ?: JSONObject.NULL)

        put("isVpnBound", vpn.isBound)
        put("isVpnBypassed", bypassed)
        put("vpnLifecycleState", vpnDiag.vpnLifecycleState.name)
        put("stopHotspotOnVpnDisconnect", vpnDiag.stopHotspotOnVpnDisconnect)
        put("vpnOutageCount", vpnDiag.vpnOutageCount)
        put("vpnRecoveryCount", vpnDiag.vpnRecoveryCount)
        put("vpnWaitingDurationMs", vpnDiag.vpnWaitingDurationMs)
        put("vpnForwardingGateClosed", vpnDiag.vpnForwardingGateClosed)
        put("vpnStatusLabel", vpnDiag.vpnStatusLabel)
        put("vpnRecoveryDiagnostics", vpnDiag.toJson())

        val traffic = interfaceName?.let(InterfaceCounters::read) ?: Traffic()
        put("bytesUp", traffic.up)
        put("bytesDown", traffic.down)

        val snapshot = if (isActive) {
            downstream.inspectSnapshot(forceRefresh = false)
        } else {
            DownstreamSnapshot(count = 0, clients = emptyList())
        }

        put("clientCount", snapshot.count)
        put("datapathMode", TunTrafficEngine.datapathMode.name)
        put("firewallBackend", HostFirewall.currentBackend().name)
        put("kernelNetfilterAvailable", HostFirewall.isKernelNetfilterAvailable)
        put("fallbackReason", TunTrafficEngine.fallbackReason ?: "")

        val clientsArray = org.json.JSONArray()
        if (isActive) {
            val downIface = snapshot.apInterfaces.firstOrNull().orEmpty()
            if (downIface.isNotBlank() || !interfaceName.isNullOrBlank()) {
                TunTrafficEngine.bpfAttributor.syncInterfaces(downIface, interfaceName.orEmpty())
            }
            val clients = snapshot.clients
            // Continuously enforce firewall and bandwidth rules on connected clients
            HostFirewall.enforce(activeRules, clients, logSummary = false)

            for (c in clients) {
                val counters = TunTrafficEngine.getCounterSnapshot(c.mac)
                clientsArray.put(org.json.JSONObject().apply {
                    put("mac", c.mac)
                    put("ip", c.ip)
                    put("interface", c.interfaceName)
                    put("rxBytes", counters.rxBytes)
                    put("txBytes", counters.txBytes)
                    put("seenPackets", counters.seenPackets)
                    put("matchedPackets", counters.matchedPackets)
                    put("droppedPackets", counters.droppedPackets)
                    put("blockedDropPackets", counters.blockedDropPackets)
                    put("shapingDropPackets", counters.shapingDropPackets)
                    put("policyVersionBlockedDrops", counters.policyVersionBlockedDrops)
                    put("shapedBytes", counters.shapedBytes)
                    put("policyInstalled", counters.policyInstalled)
                    put("unattributedPostNatObserved", counters.unattributedPostNatObserved)
                    put("mappingSource", c.mappingSource)
                    put("directAttributedPackets", counters.directAttributedPackets)
                    put("bpfAttributedPackets", counters.bpfAttributedPackets)
                    put("policyVersion", counters.policyVersion)
                    put("quotaUsedRxBytes", counters.quotaUsedRxBytes)
                    put("quotaUsedTxBytes", counters.quotaUsedTxBytes)
                    put("quotaWindowId", counters.quotaWindowId)
                    put("quotaWindowStartEpochMs", counters.quotaWindowStartEpochMs)
                    put("quotaLastUpdatedEpochMs", counters.quotaLastUpdatedEpochMs)
                    put("quotaResetGeneration", counters.quotaResetGeneration)
                    put("quotaDropPackets", counters.quotaDropPackets)
                    val ipsArr = org.json.JSONArray()
                    c.allIps.forEach { ipsArr.put(it) }
                    put("allIps", ipsArr)
                })
            }
        }
        put("connectedClients", clientsArray)
        put(
            "bpfAttribution",
            TunTrafficEngine.getBpfAttributionReport()
                .copy(vpnRecoveryDiagnostics = vpnDiag)
                .toJson(),
        )
    }.toString()

    private fun isVpnBypassed(): Boolean {
        if (vpnMode != VpnMode.NEVER) return false
        if (!isActive) return false

        return vpn.isVpnPresent()
    }

    private fun tunAddresses() = listOf(
        buildLinkAddress(java.net.InetAddress.getByName(TUN_ADDRESS), TUN_PREFIX_LENGTH),
        buildLinkAddress(java.net.InetAddress.getByName(TUN_ADDRESS_V6), TUN_PREFIX_LENGTH_V6),
    )

    private companion object {
        const val TAG = "TetherSession"
        const val TUN_ADDRESS = "192.0.2.2"
        const val TUN_PREFIX_LENGTH = 24

        const val TUN_ADDRESS_V6 = "2001:db8::2"
        const val TUN_PREFIX_LENGTH_V6 = 64

        const val TUN_MTU = 1500
        const val AVAILABILITY_TIMEOUT_MS = 10_000
        const val UPSTREAM_SETTLE_MS = 8_000L
        const val UPSTREAM_POLL_MS = 500L

        const val DOWNSTREAM_SETTLE_MS = 10_000L
        const val DOWNSTREAM_POLL_MS = 500L
    }
}
