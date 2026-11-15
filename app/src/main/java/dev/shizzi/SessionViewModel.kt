package dev.shizzi

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.shizzi.ui.theme.AccentChoice
import dev.shizzi.ui.theme.DesignLanguage
import dev.shizzi.ui.theme.ThemeChoice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SessionViewModel(application: Application) : AndroidViewModel(application) {

    private val diagnostics = TetherClient()

    private val settingsStore = getApplication<App>().settingsStore

    val settings: StateFlow<Settings?> = settingsStore.settings.stateIn(
        scope = viewModelScope,
        started = SharingStarted.Eagerly,
        initialValue = null,
    )

    private val localState = MutableStateFlow(SessionUiState())
    val state: StateFlow<SessionUiState> = localState.asStateFlow()

    private val localDiagnostics = MutableStateFlow<DiagnosticsState>(DiagnosticsState.Idle)
    val diagnosticsState: StateFlow<DiagnosticsState> = localDiagnostics.asStateFlow()

    private val compatibility =
        CompatibilityController(getApplication(), diagnostics, viewModelScope)

    val compatibilityState: StateFlow<CompatibilityState> = compatibility.state

    private val permissions = PermissionInspector(application)

    private val permissionRequest = PermissionRequest(application)

    private val localPermissions = MutableStateFlow(emptyList<PermissionStatus>())
    val permissionState: StateFlow<List<PermissionStatus>> = localPermissions.asStateFlow()

    private val localClients = MutableStateFlow<List<ConnectedClient>>(emptyList())
    val clientsState: StateFlow<List<ConnectedClient>> = localClients.asStateFlow()

    private val localFirewallDiag = MutableStateFlow(FirewallDiagnosticUiState())
    val firewallDiagState: StateFlow<FirewallDiagnosticUiState> = localFirewallDiag.asStateFlow()

    private var sessionCollector: Job? = null
    private var clientsCollector: Job? = null
    private var settingsCollector: Job? = null

    init {
        refreshShizukuState()
        refreshPermissions()
        observeSession()
        observeSettings()
        observeClients()
    }

    private fun observeSettings() {
        if (settingsCollector?.isActive == true) return
        settingsCollector = viewModelScope.launch {
            runCatching { settingsStore.migrateLegacyBlockingModeIfNeeded() }
            settings.collect { current ->
                if (current != null) {
                    DomainFilterEngine.replaceAllRules(current.domainRules)
                    TunTrafficEngine.configureDnsAttributionRetry(
                        enabled = current.dnsAttributionRetryEnabled,
                        maxWaitMs = current.dnsRetryMaxWaitMs.toLong(),
                    )
                }
                refreshClients()
            }
        }
    }

    private fun observeClients() {
        if (clientsCollector?.isActive == true) return
        clientsCollector = viewModelScope.launch {
            while (true) {
                refreshClients()
                kotlinx.coroutines.delay(1500)
            }
        }
    }

    fun refreshClients() {
        val rules = settings.value?.clientRules.orEmpty()
        val session = localState.value
        val isSessionActive = session.status == UiStatus.CONNECTED
        val liveHosts = if (isSessionActive) session.connectedClients else emptyList()
        val clientCount = if (isSessionActive) session.clientCount else 0
        val clients = ClientDiscovery.discoverClients(
            savedRules = rules,
            discoveredHosts = liveHosts,
            activeClientCount = clientCount,
            includeSimulatedIfEmpty = false,
            datapathMode = if (isSessionActive) session.datapathMode else DatapathMode.INACTIVE,
            firewallBackend = if (isSessionActive) session.firewallBackend else FirewallBackend.NONE,
            kernelNetfilterAvailable = isSessionActive && session.kernelNetfilterAvailable,
        )
        localClients.value = clients
    }

    private fun observeSession() {
        if (sessionCollector?.isActive == true) return

        sessionCollector = viewModelScope.launch {
            SessionService.liveState.collect { session ->
                localState.update { local -> session.copy(shizukuState = local.shizukuState) }
                refreshClients()
            }
        }
    }

    fun refreshShizukuState() {
        localState.update { it.copy(shizukuState = ShizukuGate.currentState()) }
    }

    fun requestPermission() {
        ShizukuGate.requestPermission()
    }

    fun actOnShizuku() {
        ShizukuGate.remedy(localState.value.shizukuState)
    }

    fun refreshPermissions() {
        localPermissions.value = permissions.observe()
    }

    fun isPermissionGranted(permission: AppPermission): Boolean =
        permissions.isGranted(permission)

    fun openPermissionSettings(permission: AppPermission) {
        permissionRequest.open(permission)
    }

    fun setAutomation(isEnabled: Boolean) {
        viewModelScope.launch { settingsStore.setAutomationEnabled(isEnabled) }
    }

    fun regenerateAutomationToken() {
        viewModelScope.launch { settingsStore.setAutomationToken(AutomationToken.generate()) }
    }

    fun setLogging(enabled: Boolean) {
        SessionLog.setEnabled(enabled)
        diagnostics.setLogging(enabled)
        viewModelScope.launch { settingsStore.setLogging(enabled) }
    }

    fun setVpnMode(mode: VpnMode) {
        viewModelScope.launch { settingsStore.setVpnMode(mode) }
    }

    fun setStopHotspotOnVpnDisconnect(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setStopHotspotOnVpnDisconnect(enabled)
            SessionService.updateStopHotspotOnVpnDisconnect(enabled)
            runCatching {
                val statusJson = diagnostics.setStopHotspotOnVpnDisconnect(enabled)
                localState.update { current -> current.applyOutcome(Result.success(statusJson)) }
            }
            SessionLog.info("Stop hotspot when VPN disconnects set to $enabled")
        }
    }

    fun setDnsAttributionRetryEnabled(enabled: Boolean) {
        viewModelScope.launch {
            val maxWaitMs = settings.value?.dnsRetryMaxWaitMs ?: 200
            settingsStore.setDnsAttributionRetryEnabled(enabled)
            TunTrafficEngine.configureDnsAttributionRetry(enabled = enabled, maxWaitMs = maxWaitMs.toLong())
            SessionService.updateDnsAttributionRetryConfig(enabled, maxWaitMs)
            runCatching {
                val report = diagnostics.setDnsAttributionRetryConfig(enabled, maxWaitMs)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("Bounded DNS Attribution Retry Queue (v0.10.9-debug) ${if (enabled) "ENABLED" else "DISABLED"}")
            refreshClients()
        }
    }

    fun setTheme(choice: ThemeChoice) {
        viewModelScope.launch { settingsStore.setTheme(choice) }
    }

    fun setDesign(design: DesignLanguage) {
        viewModelScope.launch { settingsStore.setDesign(design) }
    }

    fun setAccent(accent: AccentChoice) {
        viewModelScope.launch { settingsStore.setAccent(accent) }
    }

    fun addCustomAccent(argb: Int) {
        viewModelScope.launch { settingsStore.addCustomAccent(argb) }
    }

    fun setDnsPreset(preset: DnsPreset) {
        viewModelScope.launch {
            settingsStore.setDnsPreset(preset)
            SessionLog.info("DNS preset updated to ${preset.title}")
        }
    }

    fun setCustomDns(primary: String, secondary: String) {
        viewModelScope.launch {
            settingsStore.setCustomDns(primary, secondary)
            SessionLog.info("Custom DNS set to $primary, $secondary")
        }
    }

    fun setExperimentalBpfEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setExperimentalBpfEnabled(enabled)
            val interval = settings.value?.bpfPollIntervalMs ?: 1000
            SessionService.updateExperimentalBpfConfig(enabled, interval)
            runCatching {
                val report = diagnostics.setExperimentalBpfConfig(enabled, interval)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }
            refreshClients()
        }
    }

    fun setBpfPollIntervalMs(intervalMs: Int) {
        viewModelScope.launch {
            val clamped = intervalMs.coerceIn(500, 5000)
            settingsStore.setBpfPollIntervalMs(clamped)
            val enabled = settings.value?.experimentalBpfEnabled ?: false
            SessionService.updateExperimentalBpfConfig(enabled, clamped)
            runCatching {
                val report = diagnostics.setExperimentalBpfConfig(enabled, clamped)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }
        }
    }

    fun collectBpfSnapshotNow() {
        if (localFirewallDiag.value.isCollectingBpf) return
        localFirewallDiag.update { it.copy(isCollectingBpf = true, error = "") }
        viewModelScope.launch {
            runCatching { diagnostics.collectBpfSnapshotNow() }
                .fold(
                    onSuccess = { report ->
                        localState.update { it.copy(bpfAttribution = report) }
                        localFirewallDiag.update {
                            it.copy(isCollectingBpf = false, bpfReport = report, error = "")
                        }
                    },
                    onFailure = { err ->
                        val localReport = TunTrafficEngine.collectBpfSnapshotNow()
                        localState.update { it.copy(bpfAttribution = localReport) }
                        localFirewallDiag.update {
                            it.copy(
                                isCollectingBpf = false,
                                bpfReport = localReport,
                                error = "${err.javaClass.simpleName}: ${err.message}",
                            )
                        }
                    },
                )
            refreshClients()
        }
    }

    fun setBpfRefreshOnMissEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setBpfRefreshOnMissEnabled(enabled)
            TunTrafficEngine.configureBpfRefreshOnMiss(enabled = enabled)
            SessionService.updateBpfRefreshOnMissConfig(enabled)
            runCatching {
                val report = diagnostics.setBpfRefreshOnMissConfig(enabled)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("BPF Refresh-on-Miss (Phase B experiment) ${if (enabled) "ENABLED" else "DISABLED"}")
            refreshClients()
        }
    }

    fun setBpfDeepTupleDiagnosticsEnabled(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setBpfDeepTupleDiagnosticsEnabled(enabled)
            TunTrafficEngine.configureDeepTupleDiagnostics(enabled = enabled)
            SessionService.updateDeepTupleDiagnosticsEnabled(enabled)
            runCatching {
                val report = diagnostics.setDeepTupleDiagnosticsEnabled(enabled)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("BPF Deep Tuple Diagnostics (Phase C) ${if (enabled) "ENABLED" else "DISABLED"}")
            refreshClients()
        }
    }

    fun setBpfExportPseudonymousIds(enabled: Boolean) {
        viewModelScope.launch {
            settingsStore.setBpfExportPseudonymousIds(enabled)
        }
    }

    fun resetBpfDiagnosticsCounters() {
        viewModelScope.launch {
            TunTrafficEngine.resetAttributionDiagnosticsCounters()
            SessionService.resetBpfDiagnosticsCounters()
            runCatching {
                val report = diagnostics.resetBpfDiagnosticsCounters()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("BPF Attribution diagnostic counters reset to 0 (policies and quotas preserved)")
            refreshClients()
        }
    }

    fun setPhaseDEnforcementMode(mode: PhaseDEnforcementMode) {
        viewModelScope.launch {
            settingsStore.setPhaseDEnforcementMode(mode)
            TunTrafficEngine.configurePhaseDMode(mode)
            SessionService.updatePhaseDEnforcementMode(mode)
            runCatching {
                val report = diagnostics.setPhaseDEnforcementMode(mode)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("Phase D mode set to ${mode.name}")
            refreshClients()
        }
    }

    fun recordPhaseDDeliveryTestMarker(markerType: String, note: String = "") {
        viewModelScope.launch {
            TunTrafficEngine.recordDeliveryTestMarker(markerType = markerType, note = note)
            SessionService.recordPhaseDDeliveryTestMarker(markerType, note)
            runCatching {
                val report = diagnostics.recordPhaseDDeliveryTestMarker(markerType, note)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("Phase D delivery test marker recorded: $markerType")
            refreshClients()
        }
    }

    fun selectBlockingMode(mode: BlockingMode) {
        viewModelScope.launch {
            settingsStore.setRequestedBlockingMode(mode)
            ExclusiveBlockingModeController.selectRequestedMode(mode)
            SessionService.updateBlockingMode(mode)
            runCatching {
                val report = diagnostics.selectBlockingMode(mode)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            SessionLog.info("Blocking mode requested: ${mode.name} (effective=${ExclusiveBlockingModeController.effectiveMode.name})")
            refreshClients()
        }
    }

    fun checkPreNatCapability() {
        viewModelScope.launch {
            runCatching {
                val report = diagnostics.checkPreNatCapability()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.checkCapabilityReadOnly()
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun reviewPreNatScopedProbe() {
        viewModelScope.launch {
            runCatching {
                val report = diagnostics.reviewPreNatScopedProbe()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.reviewScopedProbePlan()
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun runPreNatScopedProbe(userConfirmed: Boolean) {
        viewModelScope.launch {
            runCatching {
                val report = diagnostics.runPreNatScopedProbe(userConfirmed)
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.runUserApprovedScopedProbe(userConfirmed)
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun activatePreNatBlockingMode() {
        viewModelScope.launch {
            settingsStore.setRequestedBlockingMode(BlockingMode.BPF_NAT_VPN)
            runCatching {
                val report = diagnostics.activatePreNatBlockingMode()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.activatePreNatMode()
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun restoreBpfBlockingMode() {
        viewModelScope.launch {
            settingsStore.setRequestedBlockingMode(BlockingMode.BPF_NAT_VPN)
            runCatching {
                val report = diagnostics.restoreBpfBlockingMode()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.restoreBpfNatVpnMode(reason = "User requested restore current engine")
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun checkSoftApCapability() {
        viewModelScope.launch {
            runCatching {
                val report = diagnostics.checkSoftApCapability()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.checkSoftApCapability()
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun runSoftApLiveProbe(
        clientAMac: String,
        clientBMac: String,
        userConfirmed: Boolean,
        disconnectTimeoutMs: Int = 5_000,
    ) {
        viewModelScope.launch {
            runCatching {
                val report = diagnostics.runSoftApLiveProbe(
                    clientAMac = clientAMac,
                    clientBMac = clientBMac,
                    userConfirmed = userConfirmed,
                    disconnectTimeoutMs = disconnectTimeoutMs,
                )
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.runSoftApLiveProbe(
                    clientAMac = clientAMac,
                    clientBMac = clientBMac,
                    userConfirmed = userConfirmed,
                    disconnectTimeoutMs = disconnectTimeoutMs.toLong().coerceIn(500L, 15_000L),
                )
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }

    fun activateSoftApBlockingMode() {
        viewModelScope.launch {
            settingsStore.setRequestedBlockingMode(BlockingMode.SOFTAP_MAC_BLOCK)
            val currentRules = settings.value?.clientRules.orEmpty()
            runCatching {
                val report = diagnostics.activateSoftApBlockingMode()
                localState.update { it.copy(bpfAttribution = report) }
                localFirewallDiag.update { it.copy(bpfReport = report) }
            }.onFailure {
                ExclusiveBlockingModeController.activateSoftApBlockingMode(rules = currentRules)
                val localReport = TunTrafficEngine.getBpfAttributionReport()
                localState.update { it.copy(bpfAttribution = localReport) }
                localFirewallDiag.update { it.copy(bpfReport = localReport) }
            }
            refreshClients()
        }
    }


    fun saveClientRule(rule: ClientRule) {
        viewModelScope.launch {
            settingsStore.saveClientRule(rule)
            val updatedRules = settingsStore.settings.first().clientRules
            TunTrafficEngine.syncQuotaRules(updatedRules)
            SessionService.updateRules(updatedRules)
            val name = rule.alias.ifBlank { "Host ${rule.mac.takeLast(5)}" }
            SessionLog.info(
                "Rule updated for $name (${rule.mac}): blocked=${rule.isBlocked}, " +
                    "limit=${rule.bandwidthLimitKbps}kbps, quota=${rule.formattedDataLimit()}(${rule.quotaResetPeriod.displayName}), " +
                    "timeLimit=${rule.connectionTimeLimitMinutes}m",
            )
            refreshClients()
        }
    }

    fun resetClientQuotaUsage(mac: String) {
        viewModelScope.launch {
            val cleanMac = mac.uppercase().trim()
            TunTrafficEngine.resetClientQuota(cleanMac)
            val updatedRule = settingsStore.resetClientQuotaUsage(cleanMac)
            val updatedRules = settingsStore.settings.first().clientRules
            SessionService.resetClientQuota(cleanMac)
            SessionService.updateRules(updatedRules)
            runCatching { diagnostics.resetClientQuota(cleanMac) }
            localState.update { current ->
                current.copy(
                    connectedClients = current.connectedClients.map { host ->
                        if (host.mac.equals(cleanMac, ignoreCase = true)) {
                            host.copy(
                                rxBytes = 0L,
                                txBytes = 0L,
                                quotaUsedRxBytes = 0L,
                                quotaUsedTxBytes = 0L,
                                quotaWindowId = updatedRule.quotaWindowId,
                                quotaWindowStartEpochMs = updatedRule.quotaWindowStartEpochMs,
                                quotaLastUpdatedEpochMs = updatedRule.quotaLastUpdatedEpochMs,
                                quotaResetGeneration = updatedRule.quotaResetGeneration,
                                quotaDropPackets = 0L,
                            )
                        } else {
                            host
                        }
                    },
                )
            }
            SessionLog.info("Quota usage reset to 0 B for ${updatedRule.displayName} ($cleanMac)")
            refreshClients()
        }
    }

    fun toggleBlockClient(mac: String, shouldBlock: Boolean) {
        val currentRule = settings.value?.clientRules?.firstOrNull { it.mac.equals(mac, ignoreCase = true) }
            ?: ClientRule(mac = mac)
        saveClientRule(currentRule.copy(isBlocked = shouldBlock))
    }

    fun setClientBandwidthLimit(mac: String, limitKbps: Int) {
        val currentRule = settings.value?.clientRules?.firstOrNull { it.mac.equals(mac, ignoreCase = true) }
            ?: ClientRule(mac = mac)
        saveClientRule(currentRule.copy(bandwidthLimitKbps = limitKbps))
    }

    fun setClientTimeLimit(mac: String, durationMinutes: Int) {
        val currentRule = settings.value?.clientRules?.firstOrNull { it.mac.equals(mac, ignoreCase = true) }
            ?: ClientRule(mac = mac)
        saveClientRule(currentRule.copy(connectionTimeLimitMinutes = durationMinutes))
    }

    fun setClientSchedule(mac: String, enabled: Boolean, startHour: Int, endHour: Int) {
        val currentRule = settings.value?.clientRules?.firstOrNull { it.mac.equals(mac, ignoreCase = true) }
            ?: ClientRule(mac = mac)
        saveClientRule(currentRule.copy(scheduleEnabled = enabled, scheduleStartHour = startHour, scheduleEndHour = endHour))
    }

    fun setClientAlias(mac: String, alias: String) {
        val currentRule = settings.value?.clientRules?.firstOrNull { it.mac.equals(mac, ignoreCase = true) }
            ?: ClientRule(mac = mac)
        saveClientRule(currentRule.copy(alias = alias))
    }

    fun removeClientRule(mac: String) {
        viewModelScope.launch {
            settingsStore.removeClientRule(mac)
            val updatedRules = settingsStore.settings.first().clientRules
            SessionService.updateRules(updatedRules)
            SessionLog.info("Rule removed for $mac")
            refreshClients()
        }
    }

    fun upsertDomainRule(
        existingRuleId: String? = null,
        rawDomain: String,
        scope: DomainRuleScope,
        clientMac: String? = null,
        matchMode: DomainMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS,
        enabled: Boolean = true,
    ): DomainValidationResult {
        val check = DomainNormalizer.validateAndNormalize(rawDomain, matchMode)
        if (!check.isValid) {
            return check
        }
        if (!existingRuleId.isNullOrBlank()) {
            DomainFilterEngine.removeRuleById(existingRuleId)
        }
        val (validation, savedRule) = DomainFilterEngine.upsertRule(
            rawDomain = rawDomain,
            scope = scope,
            clientMac = clientMac,
            matchMode = matchMode,
            enabled = enabled,
        )
        if (!validation.isValid || savedRule == null) {
            return validation
        }
        val allRules = DomainFilterEngine.getAllRules()
        viewModelScope.launch {
            settingsStore.saveDomainRules(allRules)
            SessionService.updateDomainRules(allRules)
            runCatching { diagnostics.updateDomainRules(DomainRule.serializeList(allRules)) }
            val localReport = TunTrafficEngine.getBpfAttributionReport()
            localState.update { it.copy(bpfAttribution = localReport) }
            localFirewallDiag.update { it.copy(bpfReport = localReport) }
            refreshClients()
        }
        return validation
    }

    fun toggleDomainRuleEnabled(ruleId: String, enabled: Boolean) {
        DomainFilterEngine.setRuleEnabled(ruleId, enabled) ?: return
        val allRules = DomainFilterEngine.getAllRules()
        viewModelScope.launch {
            settingsStore.saveDomainRules(allRules)
            SessionService.updateDomainRules(allRules)
            runCatching { diagnostics.updateDomainRules(DomainRule.serializeList(allRules)) }
            val localReport = TunTrafficEngine.getBpfAttributionReport()
            localState.update { it.copy(bpfAttribution = localReport) }
            localFirewallDiag.update { it.copy(bpfReport = localReport) }
            refreshClients()
        }
    }

    fun removeDomainRule(ruleId: String) {
        if (!DomainFilterEngine.removeRuleById(ruleId)) return
        val allRules = DomainFilterEngine.getAllRules()
        viewModelScope.launch {
            settingsStore.saveDomainRules(allRules)
            SessionService.updateDomainRules(allRules)
            runCatching { diagnostics.updateDomainRules(DomainRule.serializeList(allRules)) }
            val localReport = TunTrafficEngine.getBpfAttributionReport()
            localState.update { it.copy(bpfAttribution = localReport) }
            localFirewallDiag.update { it.copy(bpfReport = localReport) }
            refreshClients()
        }
    }

    fun clearGlobalDomainRules() {
        DomainFilterEngine.clearGlobalRules()
        val allRules = DomainFilterEngine.getAllRules()
        viewModelScope.launch {
            settingsStore.saveDomainRules(allRules)
            SessionService.updateDomainRules(allRules)
            runCatching { diagnostics.updateDomainRules(DomainRule.serializeList(allRules)) }
            val localReport = TunTrafficEngine.getBpfAttributionReport()
            localState.update { it.copy(bpfAttribution = localReport) }
            localFirewallDiag.update { it.copy(bpfReport = localReport) }
            refreshClients()
        }
    }

    fun clearClientDomainRules(clientMac: String? = null) {
        DomainFilterEngine.clearClientRules(clientMac)
        val allRules = DomainFilterEngine.getAllRules()
        viewModelScope.launch {
            settingsStore.saveDomainRules(allRules)
            SessionService.updateDomainRules(allRules)
            runCatching { diagnostics.updateDomainRules(DomainRule.serializeList(allRules)) }
            val localReport = TunTrafficEngine.getBpfAttributionReport()
            localState.update { it.copy(bpfAttribution = localReport) }
            localFirewallDiag.update { it.copy(bpfReport = localReport) }
            refreshClients()
        }
    }

    fun toggle() {
        val context = getApplication<Application>()

        when {
            SessionService.isSessionUp -> SessionService.stop(context)
            else -> SessionService.start(context)
        }
    }

    fun cancel() {
        localState.update {
            it.asStopped()
        }
        SessionService.stop(getApplication())
    }

    fun runProbes() {
        if (localDiagnostics.value is DiagnosticsState.Running) return
        localDiagnostics.value = DiagnosticsState.Running

        viewModelScope.launch {
            localDiagnostics.value = runCatching { diagnostics.runProbes(true) }
                .fold(
                    onSuccess = { report ->
                        DiagnosticsState.Complete(report, TetherService.REPORT_PATH)
                    },
                    onFailure = { failure ->

                        SessionLog.error(
                            "diagnostics failed in the app process: " +
                                "${failure.javaClass.name}: ${failure.message}",
                        )
                        DiagnosticsState.Failed(
                            "${failure.javaClass.simpleName}: ${failure.message}",
                        )
                    },
                )
            refreshShizukuState()
        }
    }

    fun runFirewallReadOnlyProbes() {
        if (localFirewallDiag.value.isRunningProbes || localFirewallDiag.value.isRunningClientPoc) return
        localFirewallDiag.update { it.copy(isRunningProbes = true, error = "") }
        viewModelScope.launch {
            runCatching { diagnostics.runFirewallDiagnostics() }
                .fold(
                    onSuccess = { report ->
                        localFirewallDiag.update {
                            it.copy(isRunningProbes = false, report = report, error = "")
                        }
                    },
                    onFailure = { err ->
                        localFirewallDiag.update {
                            it.copy(
                                isRunningProbes = false,
                                error = "${err.javaClass.simpleName}: ${err.message}",
                            )
                        }
                    },
                )
            refreshShizukuState()
            refreshClients()
        }
    }

    fun runFirewallClientPoc(clientAMac: String, clientBMac: String, durationSec: Int = 5) {
        if (localFirewallDiag.value.isRunningProbes || localFirewallDiag.value.isRunningClientPoc) return
        localFirewallDiag.update { it.copy(isRunningClientPoc = true, error = "") }
        viewModelScope.launch {
            runCatching { diagnostics.runFirewallClientPoc(clientAMac, clientBMac, durationSec) }
                .fold(
                    onSuccess = { report ->
                        localFirewallDiag.update {
                            it.copy(
                                isRunningClientPoc = false,
                                report = report,
                                lastCleanupResult = report.temporaryRuleTest.cleanupStatus,
                                error = "",
                            )
                        }
                    },
                    onFailure = { err ->
                        localFirewallDiag.update {
                            it.copy(
                                isRunningClientPoc = false,
                                error = "${err.javaClass.simpleName}: ${err.message}",
                            )
                        }
                    },
                )
            refreshShizukuState()
            refreshClients()
        }
    }

    fun cleanupFirewallTestRules() {
        viewModelScope.launch {
            val res = runCatching { diagnostics.cleanupFirewallTestRules() }
                .getOrElse { err -> "ERROR: ${err.javaClass.simpleName}: ${err.message}" }
            localFirewallDiag.update { it.copy(lastCleanupResult = res) }
        }
    }

    fun checkCompatibility() = compatibility.check()

    fun downloadTetheringApex() = compatibility.downloadApex()

    fun installTetheringApex() = compatibility.installApex()

    fun rebootDevice() = compatibility.rebootDevice()

    fun completeOnboarding() {
        viewModelScope.launch { settingsStore.setOnboardingComplete(true) }
    }

    fun restartOnboarding() {
        compatibility.reset()
        viewModelScope.launch { settingsStore.setOnboardingComplete(false) }
    }

    fun dismissDiagnostics() {
        if (localDiagnostics.value is DiagnosticsState.Running) return
        localDiagnostics.value = DiagnosticsState.Idle
    }

    fun clearLog(onCleared: (String?) -> Unit) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { SessionLog.clear() }
            onCleared(diagnostics.clearLog())
        }
    }

    override fun onCleared() {

        diagnostics.unbind()
        super.onCleared()
    }
}

data class FirewallDiagnosticUiState(
    val isRunningProbes: Boolean = false,
    val isRunningClientPoc: Boolean = false,
    val isCollectingBpf: Boolean = false,
    val report: FirewallDiagnosticReport? = null,
    val bpfReport: BpfAttributionStatusReport? = null,
    val lastCleanupResult: String = "",
    val error: String = "",
)
