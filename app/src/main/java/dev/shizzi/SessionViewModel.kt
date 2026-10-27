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
            settings.collect {
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
                        localFirewallDiag.update {
                            it.copy(
                                isCollectingBpf = false,
                                error = "${err.javaClass.simpleName}: ${err.message}",
                            )
                        }
                    },
                )
            refreshClients()
        }
    }

    fun saveClientRule(rule: ClientRule) {
        viewModelScope.launch {
            settingsStore.saveClientRule(rule)
            val updatedRules = settingsStore.settings.first().clientRules
            SessionService.updateRules(updatedRules)
            val name = rule.alias.ifBlank { "Host ${rule.mac.takeLast(5)}" }
            SessionLog.info("Rule updated for $name (${rule.mac}): blocked=${rule.isBlocked}, limit=${rule.bandwidthLimitKbps}kbps, timeLimit=${rule.connectionTimeLimitMinutes}m")
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
