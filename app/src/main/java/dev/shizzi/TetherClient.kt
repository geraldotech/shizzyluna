package dev.shizzi

import android.content.ComponentName
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import rikka.shizuku.Shizuku

enum class UiStatus { READY, LOADING, CONNECTED, ERROR }

data class SessionUiState(
    val shizukuState: ShizukuState = ShizukuState.NotRunning,
    val status: UiStatus = UiStatus.READY,
    val isBusy: Boolean = false,
    val detail: String = "",
    val interfaceName: String = "",
    val lastError: String = "",
    val isVpnBound: Boolean = false,
    val isVpnBypassed: Boolean = false,
    val vpnLifecycleState: VpnLifecycleState = VpnLifecycleState.VPN_UNBOUND_ALLOWED,
    val stopHotspotOnVpnDisconnect: Boolean = true,
    val vpnOutageCount: Long = 0L,
    val vpnRecoveryCount: Long = 0L,
    val vpnWaitingDurationMs: Long = 0L,
    val vpnForwardingGateClosed: Boolean = false,
    val vpnStatusLabel: String = "No VPN",
    val vpnRecoveryDiagnostics: VpnRecoveryDiagnostics = VpnRecoveryDiagnostics(),

    val clientCount: Int = 0,
    val connectedClients: List<DiscoveredHost> = emptyList(),
    val datapathMode: DatapathMode = DatapathMode.INACTIVE,
    val firewallBackend: FirewallBackend = FirewallBackend.NONE,
    val kernelNetfilterAvailable: Boolean = false,
    val fallbackReason: String = "",
    val bpfAttribution: BpfAttributionStatusReport = BpfAttributionStatusReport(),

    val traffic: Traffic = Traffic(),
) {

    val canStart: Boolean get() = shizukuState is ShizukuState.Ready && !isBusy
}

fun SessionUiState.asStopped(): SessionUiState = copy(
    isBusy = false,
    status = UiStatus.READY,
    lastError = "",
    detail = "Stopped",
    interfaceName = "",
    isVpnBound = false,
    isVpnBypassed = false,
    vpnLifecycleState = VpnLifecycleState.SESSION_STOPPED,
    vpnWaitingDurationMs = 0L,
    vpnForwardingGateClosed = false,
    vpnStatusLabel = "No VPN",
    vpnRecoveryDiagnostics = VpnRecoveryDiagnostics(),
    clientCount = 0,
    connectedClients = emptyList(),
    datapathMode = DatapathMode.INACTIVE,
    firewallBackend = FirewallBackend.NONE,
    kernelNetfilterAvailable = false,
    fallbackReason = "",
    bpfAttribution = BpfAttributionStatusReport(),
    traffic = Traffic(),
)

fun SessionUiState.applyOutcome(outcome: Result<String>): SessionUiState {
    val failure = outcome.exceptionOrNull()
    if (failure != null) {
        return copy(
            isBusy = false,
            status = UiStatus.ERROR,
            lastError = "${failure.javaClass.simpleName}: ${failure.message}",

            interfaceName = "",
            isVpnBound = false,
            isVpnBypassed = false,
            clientCount = 0,
            connectedClients = emptyList(),
            datapathMode = DatapathMode.INACTIVE,
            firewallBackend = FirewallBackend.NONE,
            kernelNetfilterAvailable = false,
            fallbackReason = "",
            traffic = Traffic(),
        )
    }

    val parsed = runCatching { JSONObject(outcome.getOrDefault("{}")) }.getOrNull()
    val sessionState = parsed?.optString("state").orEmpty()
    val sessionDetail = parsed?.optString("detail").orEmpty()

    val clientsList = mutableListOf<DiscoveredHost>()
    val clientsArr = parsed?.optJSONArray("connectedClients")
    if (clientsArr != null) {
        for (i in 0 until clientsArr.length()) {
            val obj = clientsArr.optJSONObject(i)
            if (obj != null) {
                val ipsArr = obj.optJSONArray("allIps")
                val allIps = mutableListOf<String>()
                if (ipsArr != null) {
                    for (j in 0 until ipsArr.length()) {
                        val ipItem = ipsArr.optString(j)
                        if (ipItem.isNotBlank()) allIps.add(ipItem)
                    }
                }
                clientsList.add(
                    DiscoveredHost(
                        mac = obj.optString("mac"),
                        ip = obj.optString("ip"),
                        allIps = allIps,
                        interfaceName = obj.optString("interface", "wlan0"),
                        rxBytes = obj.optLong("rxBytes", 0L),
                        txBytes = obj.optLong("txBytes", 0L),
                        seenPackets = obj.optLong("seenPackets", 0L),
                        matchedPackets = obj.optLong("matchedPackets", 0L),
                        droppedPackets = obj.optLong("droppedPackets", 0L),
                        blockedDropPackets = obj.optLong("blockedDropPackets", 0L),
                        shapingDropPackets = obj.optLong("shapingDropPackets", 0L),
                        policyVersionBlockedDrops = obj.optLong("policyVersionBlockedDrops", 0L),
                        shapedBytes = obj.optLong("shapedBytes", 0L),
                        policyInstalled = obj.optBoolean("policyInstalled", false),
                        unattributedPostNatObserved = obj.optBoolean("unattributedPostNatObserved", false),
                        mappingSource = obj.optString("mappingSource", "softap_dump+downstream_neigh"),
                        directAttributedPackets = obj.optLong("directAttributedPackets", 0L),
                        bpfAttributedPackets = obj.optLong("bpfAttributedPackets", 0L),
                        policyVersion = obj.optLong("policyVersion", 1L),
                        quotaUsedRxBytes = obj.optLong("quotaUsedRxBytes", 0L),
                        quotaUsedTxBytes = obj.optLong("quotaUsedTxBytes", 0L),
                        quotaWindowId = obj.optString("quotaWindowId", ""),
                        quotaWindowStartEpochMs = obj.optLong("quotaWindowStartEpochMs", 0L),
                        quotaLastUpdatedEpochMs = obj.optLong("quotaLastUpdatedEpochMs", 0L),
                        quotaResetGeneration = obj.optLong("quotaResetGeneration", 0L),
                        quotaDropPackets = obj.optLong("quotaDropPackets", 0L),
                    ),
                )
            }
        }
    }

    val dpMode = runCatching {
        DatapathMode.valueOf(parsed?.optString("datapathMode", DatapathMode.INACTIVE.name).orEmpty())
    }.getOrDefault(DatapathMode.INACTIVE)

    val fwBackend = runCatching {
        FirewallBackend.valueOf(parsed?.optString("firewallBackend", FirewallBackend.NONE.name).orEmpty())
    }.getOrDefault(FirewallBackend.NONE)

    val bpfReport = BpfAttributionStatusReport.fromJson(parsed?.optJSONObject("bpfAttribution"))
    val vpnDiag = VpnRecoveryDiagnostics.fromJson(parsed?.optJSONObject("vpnRecoveryDiagnostics"))
    val vpnLifecycle = runCatching {
        VpnLifecycleState.valueOf(
            parsed?.optString("vpnLifecycleState", vpnDiag.vpnLifecycleState.name).orEmpty(),
        )
    }.getOrDefault(vpnDiag.vpnLifecycleState)

    return copy(
        isBusy = false,
        status = statusFor(sessionState),
        detail = sessionDetail,
        interfaceName = parsed?.optString("interface").orEmpty().takeIf { it != "null" }.orEmpty(),
        lastError = if (sessionState == "ERROR") sessionDetail else "",

        isVpnBound = parsed?.optBoolean("isVpnBound") == true,
        isVpnBypassed = parsed?.optBoolean("isVpnBypassed") == true,
        vpnLifecycleState = vpnLifecycle,
        stopHotspotOnVpnDisconnect = parsed?.optBoolean(
            "stopHotspotOnVpnDisconnect",
            vpnDiag.stopHotspotOnVpnDisconnect,
        ) ?: true,
        vpnOutageCount = parsed?.optLong("vpnOutageCount", vpnDiag.vpnOutageCount) ?: 0L,
        vpnRecoveryCount = parsed?.optLong("vpnRecoveryCount", vpnDiag.vpnRecoveryCount) ?: 0L,
        vpnWaitingDurationMs = parsed?.optLong("vpnWaitingDurationMs", vpnDiag.vpnWaitingDurationMs) ?: 0L,
        vpnForwardingGateClosed = parsed?.optBoolean(
            "vpnForwardingGateClosed",
            vpnDiag.vpnForwardingGateClosed,
        ) ?: false,
        vpnStatusLabel = parsed?.optString("vpnStatusLabel", vpnDiag.vpnStatusLabel)
            ?.ifBlank { vpnDiag.vpnStatusLabel }
            ?: "No VPN",
        vpnRecoveryDiagnostics = vpnDiag,
        clientCount = parsed?.optInt("clientCount") ?: 0,
        connectedClients = clientsList,
        datapathMode = dpMode,
        firewallBackend = fwBackend,
        kernelNetfilterAvailable = parsed?.optBoolean("kernelNetfilterAvailable", false) == true,
        fallbackReason = parsed?.optString("fallbackReason").orEmpty(),
        bpfAttribution = bpfReport,
        traffic = Traffic(
            up = parsed?.optLong("bytesUp") ?: 0,
            down = parsed?.optLong("bytesDown") ?: 0,
        ),
    )
}

private fun statusFor(sessionState: String): UiStatus = when (sessionState) {
    "ACTIVE" -> UiStatus.CONNECTED
    "ERROR" -> UiStatus.ERROR
    "STARTING" -> UiStatus.LOADING
    else -> UiStatus.READY
}

class TetherClient {

    private var boundService: ITetherService? = null
    private var pendingBind: CompletableDeferred<ITetherService>? = null

    var onSessionLost: (() -> Unit)? = null

    private var deathRecipient: IBinder.DeathRecipient? = null

    private val userServiceArgs = Shizuku.UserServiceArgs(
        ComponentName(BuildConfig.APPLICATION_ID, TetherService::class.java.name),
    )
        .daemon(true)
        .tag(SERVICE_TAG)
        .processNameSuffix("probe")
        .debuggable(BuildConfig.DEBUG)
        .version(TetherService.CONTRACT_VERSION)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val service = binder?.let { ITetherService.Stub.asInterface(it) }
            when (service) {
                null -> pendingBind?.completeExceptionally(
                    IllegalStateException("bindUserService: Shizuku returned a null binder"),
                )

                else -> {
                    boundService = service
                    pendingBind?.complete(service)
                }
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            boundService = null
        }
    }

    /**
     * Binds to the Shizuku UserService and ensures that a stale daemon from a previous APK
     * build (`remoteContract != CONTRACT_VERSION`) is automatically terminated and restarted.
     */
    private suspend fun service(): ITetherService {
        boundService?.let { existing ->
            if (existing.asBinder().pingBinder()) {
                val remoteVer = runCatching { existing.contractVersion }.getOrDefault(-1)
                if (remoteVer == TetherService.CONTRACT_VERSION) {
                    return existing
                }
                SessionLog.warn(
                    "UserService contract mismatch (remote=$remoteVer, expected=${TetherService.CONTRACT_VERSION}); terminating stale daemon",
                )
                releaseBinding(shouldTerminate = true)
                delay(350)
            } else {
                boundService = null
            }
        }

        var bound = bindOnce()
        val remoteVer = runCatching { bound.contractVersion }.getOrDefault(-1)
        if (remoteVer != TetherService.CONTRACT_VERSION) {
            SessionLog.warn(
                "Restarting stale Shizuku UserService (remote=$remoteVer != expected=${TetherService.CONTRACT_VERSION})",
            )
            releaseBinding(shouldTerminate = true)
            delay(450)
            bound = bindOnce()
        }
        return bound
    }

    private suspend fun bindOnce(): ITetherService {
        val deferred = CompletableDeferred<ITetherService>()
        pendingBind = deferred
        Shizuku.bindUserService(userServiceArgs, connection)

        val bound = awaitBind(deferred)
        observeDeath(bound)
        return bound
    }

    private suspend fun awaitBind(deferred: CompletableDeferred<ITetherService>): ITetherService =
        try {
            withTimeout(BIND_TIMEOUT_MS) { deferred.await() }
        } catch (timeout: TimeoutCancellationException) {
            pendingBind = null
            throw IllegalStateException(
                "bindUserService: Shizuku returned no binder for the privileged " +
                    "helper within ${BIND_TIMEOUT_MS}ms. The shell process either " +
                    "never started or exited before handing one back; " +
                    "`adb logcat -s ShizukuServiceStarter:*` carries the reason.",
                timeout,
            )
        }

    private fun observeDeath(bound: ITetherService) {
        deathRecipient = null

        val binder = bound.asBinder()
        val recipient = IBinder.DeathRecipient {
            boundService = null
            onSessionLost?.invoke()
        }

        runCatching { binder.linkToDeath(recipient, 0) }
            .onSuccess { deathRecipient = recipient }
            .onFailure {
                boundService = null
            }
    }

    suspend fun runProbes(attemptTethering: Boolean): String = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        bound.runProbes(attemptTethering, AVAILABILITY_TIMEOUT_MS)
    }

    suspend fun runFirewallDiagnostics(): FirewallDiagnosticReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val json = bound.runFirewallDiagnostics()
        FirewallDiagnosticReport.fromJsonString(json)
    }

    suspend fun runFirewallClientPoc(
        clientAMac: String,
        clientBMac: String,
        durationSec: Int = 5,
    ): FirewallDiagnosticReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val json = bound.runFirewallClientPoc(clientAMac, clientBMac, durationSec)
        FirewallDiagnosticReport.fromJsonString(json)
    }

    suspend fun cleanupFirewallTestRules(): String = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        bound.cleanupFirewallTestRules()
    }

    suspend fun setExperimentalBpfConfig(
        enabled: Boolean,
        pollIntervalMs: Int,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.setExperimentalBpfConfig(enabled, pollIntervalMs)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun collectBpfSnapshotNow(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.collectBpfSnapshotNow()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun setBpfRefreshOnMissConfig(
        enabled: Boolean,
        cooldownMs: Int = 500,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.setBpfRefreshOnMissConfig(enabled, cooldownMs)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun setDeepTupleDiagnosticsEnabled(
        enabled: Boolean,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.setDeepTupleDiagnosticsEnabled(enabled)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun resetBpfDiagnosticsCounters(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.resetBpfDiagnosticsCounters()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun setPhaseDEnforcementMode(
        mode: PhaseDEnforcementMode,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.setPhaseDEnforcementMode(mode.name)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun recordPhaseDDeliveryTestMarker(
        markerType: String,
        note: String = "",
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.recordPhaseDDeliveryTestMarker(markerType, note)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun selectBlockingMode(
        mode: BlockingMode,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.selectBlockingMode(mode.name)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun checkPreNatCapability(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.checkPreNatCapability()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun reviewPreNatScopedProbe(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.reviewPreNatScopedProbe()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun runPreNatScopedProbe(
        userConfirmed: Boolean,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.runPreNatScopedProbe(userConfirmed)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun activatePreNatBlockingMode(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.activatePreNatBlockingMode()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun restoreBpfBlockingMode(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.restoreBpfBlockingMode()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun checkSoftApCapability(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.checkSoftApCapability()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun runSoftApLiveProbe(
        clientAMac: String,
        clientBMac: String,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Int = 5_000,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.runSoftApLiveProbe(clientAMac, clientBMac, userConfirmed, disconnectTimeoutMs)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun activateSoftApBlockingMode(): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.activateSoftApBlockingMode()
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun checkCompatibility(): List<CapabilityResult> = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        parseCapabilities(bound.checkCompatibility())
    }

    suspend fun installTetheringApex(path: String): StagingOutcome =
        withContext(Dispatchers.IO) {
            val bound = service()
            verifyContract(bound)

            ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY)
                .use { apex -> parseStagingOutcome(bound.installTetheringApex(apex)) }
        }

    suspend fun rebootDevice(): String = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        bound.rebootDevice()
    }

    suspend fun start(
        logging: Boolean,
        vpnMode: VpnMode,
        dnsServers: List<String> = emptyList(),
    ): String = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        if (dnsServers.isNotEmpty()) {
            bound.startWithDns(logging, vpnMode.name, dnsServers.toTypedArray())
        } else {
            bound.start(logging, vpnMode.name)
        }
    }

    fun setLogging(enabled: Boolean) {
        runCatching { boundService?.setLogging(enabled) }
    }

    suspend fun updateRules(rulesJson: String) = withContext(Dispatchers.IO) {
        runCatching {
            val bound = service()
            bound.updateRules(rulesJson)
        }
    }

    suspend fun updateDomainRules(domainRulesJson: String) = withContext(Dispatchers.IO) {
        runCatching {
            val bound = service()
            bound.updateDomainRules(domainRulesJson)
        }
    }

    suspend fun resetClientQuota(mac: String) = withContext(Dispatchers.IO) {
        runCatching {
            val bound = service()
            bound.resetClientQuota(mac)
        }
    }

    suspend fun setStopHotspotOnVpnDisconnect(enabled: Boolean): String = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        bound.setStopHotspotOnVpnDisconnect(enabled)
    }

    suspend fun setDnsAttributionRetryConfig(
        enabled: Boolean,
        maxWaitMs: Int = 200,
    ): BpfAttributionStatusReport = withContext(Dispatchers.IO) {
        val bound = service()
        verifyContract(bound)
        val raw = bound.setDnsAttributionRetryConfig(enabled, maxWaitMs)
        BpfAttributionStatusReport.fromJson(runCatching { JSONObject(raw) }.getOrNull())
    }

    suspend fun stop(): String = withContext(Dispatchers.IO) {
        service().stop()
    }

    suspend fun clearLog(): String? = withContext(Dispatchers.IO) {
        runCatching {
            val bound = service()

            verifyContract(bound)
            bound.clearLog()
        }.fold(
            onSuccess = { null },
            onFailure = { failure -> failure.message ?: "could not reach Shizuku" },
        )
    }

    suspend fun releaseOrphanedDownstream(): String? = withContext(Dispatchers.IO) {
        runCatching { service().stop() }
            .fold(
                onSuccess = { null },
                onFailure = { failure ->
                    "could not reach Shizuku to drop the hotspot: ${failure.message}"
                },
            )
    }

    suspend fun status(): String = withContext(Dispatchers.IO) {
        service().status
    }

    private fun verifyContract(bound: ITetherService) {
        val remote = bound.contractVersion
        check(remote == TetherService.CONTRACT_VERSION) {
            "UserService is stale: app is build ${TetherService.CONTRACT_VERSION}, " +
                "shell process reports $remote — press Stop then Start to reload it"
        }
    }

    fun unbind() = releaseBinding(shouldTerminate = false)

    fun unbindAndStopDaemon() = releaseBinding(shouldTerminate = true)

    private fun releaseBinding(shouldTerminate: Boolean) {
        deathRecipient?.let { recipient ->
            runCatching { boundService?.asBinder()?.unlinkToDeath(recipient, 0) }
        }
        deathRecipient = null

        runCatching { Shizuku.unbindUserService(userServiceArgs, connection, shouldTerminate) }
        boundService = null
    }

    private companion object {

        private val SERVICE_TAG =
            if (BuildConfig.APPLICATION_ID.endsWith(".debug")) "shizzi-session-debug" else "shizzi-session"

        const val BIND_TIMEOUT_MS = 35_000L

        const val AVAILABILITY_TIMEOUT_MS = 10_000
    }
}
