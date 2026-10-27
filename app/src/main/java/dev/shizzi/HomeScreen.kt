package dev.shizzi

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import dev.shizzi.ui.AutomationActions
import dev.shizzi.ui.AutomationState
import dev.shizzi.ui.DiagnosticsToast
import dev.shizzi.ui.EasterEggPage
import dev.shizzi.ui.FirewallDiagnosticActions
import dev.shizzi.ui.FirewallDiagnosticPage
import dev.shizzi.ui.HandleBack
import dev.shizzi.ui.HomeActions
import dev.shizzi.ui.HomePage
import dev.shizzi.ui.LogActions
import dev.shizzi.ui.LogPage
import dev.shizzi.ui.Screen
import dev.shizzi.ui.ScreenHost
import dev.shizzi.ui.SessionToasts
import dev.shizzi.ui.SettingsActions
import dev.shizzi.ui.SettingsPage
import dev.shizzi.ui.SettingsState
import dev.shizzi.ui.ToastHost
import dev.shizzi.ui.ToastState
import dev.shizzi.ui.rememberLogEntries
import dev.shizzi.ui.rememberNavigator
import dev.shizzi.ui.rememberToastState
import dev.shizzi.ui.theme.AccentChoice
import dev.shizzi.ui.theme.DesignLanguage
import dev.shizzi.ui.theme.ThemeChoice

data class AppActions(
    val onToggle: () -> Unit,
    val onCancel: () -> Unit,
    val onRequestPermission: () -> Unit,
    val onRequestAllPermissions: () -> Unit,
    val onGrantPermission: (AppPermission) -> Unit,
    val onShizukuAction: () -> Unit,
    val onSetTheme: (ThemeChoice) -> Unit,
    val onSetDesign: (DesignLanguage) -> Unit,
    val onSetAccent: (AccentChoice) -> Unit,
    val onAddCustomAccent: (Int) -> Unit,
    val onSetLogging: (Boolean) -> Unit,
    val onSetVpnMode: (VpnMode) -> Unit,
    val onRunProbes: () -> Unit,
    val onDismissDiagnostics: () -> Unit,
    val onClearLog: (onCleared: (String?) -> Unit) -> Unit,
    val onRestartOnboarding: () -> Unit,
    val onSetAutomation: (Boolean) -> Unit,
    val onRegenerateAutomationToken: () -> Unit,
    val onSetDnsPreset: (DnsPreset) -> Unit,
    val onSetCustomDns: (String, String) -> Unit,
    val onToggleBlockClient: (String, Boolean) -> Unit,
    val onSaveClientRule: (ClientRule) -> Unit,
    val onRemoveClientRule: (String) -> Unit,
    val onRefreshClients: () -> Unit,
    val onRunFirewallReadOnlyProbes: () -> Unit = {},
    val onRunFirewallClientPoc: (String, String, Int) -> Unit = { _, _, _ -> },
    val onCleanupFirewallRules: () -> Unit = {},
    val onSetExperimentalBpfEnabled: (Boolean) -> Unit = {},
    val onSetBpfPollIntervalMs: (Int) -> Unit = {},
    val onCollectBpfSnapshotNow: () -> Unit = {},
)

/** Routes the navigator's current screen and hosts the toast overlay. */
@Composable
fun HomeScreen(state: AppState, actions: AppActions) {
    val current = rememberNavigator()
    val goHome = { current.value = Screen.HOME }

    val goBack = {
        current.value = when (current.value) {
            Screen.LOG -> Screen.SETTINGS
            Screen.FIREWALL_DIAGNOSTIC -> Screen.CLIENTS
            Screen.CLIENTS -> Screen.HOME
            else -> Screen.HOME
        }
    }
    HandleBack(current.value, goBack)

    val toasts = rememberToastState()
    val navigation = Navigation(goHome = goHome, goBack = goBack, open = { current.value = it })

    SessionToasts(
        state = state.session,
        toasts = toasts,
        onRequestPermission = actions.onRequestPermission,
    )

    DiagnosticsToast(
        state = state.diagnostics,
        toasts = toasts,
        onDismiss = actions.onDismissDiagnostics,
    )

    Box(modifier = Modifier.fillMaxSize()) {
        ScreenHost(current = current.value) { screen ->
            ScreenBody(
                screen = screen,
                context = ScreenContext(state, actions, toasts, navigation),
            )
        }

        ToastHost(
            state = toasts,
            modifier = Modifier.align(Alignment.BottomCenter).systemBarsPadding(),
        )
    }
}

private data class Navigation(
    val goHome: () -> Unit,
    val goBack: () -> Unit,
    val open: (Screen) -> Unit,
)

private data class ScreenContext(
    val state: AppState,
    val actions: AppActions,
    val toasts: ToastState,
    val navigation: Navigation,
)

@Composable
private fun ScreenBody(screen: Screen, context: ScreenContext) {
    when (screen) {
        Screen.HOME -> HomeRoute(context)
        Screen.SETTINGS -> SettingsRoute(context)
        Screen.CLIENTS -> ClientsRoute(context)
        Screen.LOG -> LogRoute(context)
        Screen.FIREWALL_DIAGNOSTIC -> FirewallDiagnosticRoute(context)
        Screen.EASTER_EGG -> EasterEggPage(onDismiss = context.navigation.goHome)
    }
}

@Composable
private fun HomeRoute(context: ScreenContext) {
    val actions = context.actions

    HomePage(
        state = context.state.session,
        actions = HomeActions(
            onToggle = actions.onToggle,
            onCancel = actions.onCancel,
            onOpenSettings = { context.navigation.open(Screen.SETTINGS) },
            onOpenClients = { context.navigation.open(Screen.CLIENTS) },
            onOpenEasterEgg = { context.navigation.open(Screen.EASTER_EGG) },
        ),
    )
}

@Composable
private fun ClientsRoute(context: ScreenContext) {
    val actions = context.actions
    val navigation = context.navigation

    dev.shizzi.ui.ClientsPage(
        clients = context.state.clients,
        savedRules = context.state.settings.clientRules,
        sessionState = context.state.session,
        experimentalBpfEnabled = context.state.settings.experimentalBpfEnabled,
        bpfPollIntervalMs = context.state.settings.bpfPollIntervalMs,
        actions = dev.shizzi.ui.ClientActions(
            onToggleBlock = actions.onToggleBlockClient,
            onSaveRule = actions.onSaveClientRule,
            onRemoveRule = actions.onRemoveClientRule,
            onRefresh = actions.onRefreshClients,
            onOpenFirewallDiagnostic = { navigation.open(Screen.FIREWALL_DIAGNOSTIC) },
            onSetExperimentalBpfEnabled = actions.onSetExperimentalBpfEnabled,
            onCollectBpfSnapshotNow = actions.onCollectBpfSnapshotNow,
        ),
        onBack = navigation.goBack,
    )
}

@Composable
private fun FirewallDiagnosticRoute(context: ScreenContext) {
    val actions = context.actions
    FirewallDiagnosticPage(
        diagState = context.state.firewallDiag,
        connectedClients = context.state.clients,
        sessionBpfReport = context.state.session.bpfAttribution,
        experimentalBpfEnabled = context.state.settings.experimentalBpfEnabled,
        bpfPollIntervalMs = context.state.settings.bpfPollIntervalMs,
        actions = FirewallDiagnosticActions(
            onRunReadOnlyProbes = actions.onRunFirewallReadOnlyProbes,
            onRunTemporaryClientPoc = actions.onRunFirewallClientPoc,
            onCleanupOrphanRules = actions.onCleanupFirewallRules,
            onSetExperimentalBpfEnabled = actions.onSetExperimentalBpfEnabled,
            onSetBpfPollIntervalMs = actions.onSetBpfPollIntervalMs,
            onCollectBpfSnapshotNow = actions.onCollectBpfSnapshotNow,
        ),
        toasts = context.toasts,
        onBack = context.navigation.goBack,
    )
}

@Composable
private fun SettingsRoute(context: ScreenContext) {
    SettingsPage(
        state = settingsState(context.state),
        actions = settingsActions(context),
        toasts = context.toasts,
        onBack = context.navigation.goHome,
    )
}

private fun settingsState(state: AppState): SettingsState {
    val settings = state.settings

    return SettingsState(
        shizuku = state.session.shizukuState,
        permissions = state.permissions,
        theme = settings.theme,
        design = settings.design,
        accent = settings.accent,
        customAccents = settings.customAccents,
        isLogging = settings.isLogging,
        vpnMode = settings.vpnMode,
        isRunningDiagnostics = state.diagnostics is DiagnosticsState.Running,
        automation = AutomationState(
            isEnabled = settings.isAutomationEnabled,
            token = settings.automationToken,
        ),
        dnsSettings = settings.dnsSettings,
        experimentalBpfEnabled = settings.experimentalBpfEnabled,
    )
}

private fun settingsActions(context: ScreenContext): SettingsActions {
    val actions = context.actions

    return SettingsActions(
        onSetTheme = actions.onSetTheme,
        onSetDesign = actions.onSetDesign,
        onSetAccent = actions.onSetAccent,
        onAddCustomAccent = actions.onAddCustomAccent,
        onSetLogging = actions.onSetLogging,
        onSetVpnMode = actions.onSetVpnMode,
        onSetDnsPreset = actions.onSetDnsPreset,
        onSetCustomDns = actions.onSetCustomDns,
        onOpenClients = { context.navigation.open(Screen.CLIENTS) },
        onOpenLog = { context.navigation.open(Screen.LOG) },
        onOpenFirewallDiagnostic = { context.navigation.open(Screen.FIREWALL_DIAGNOSTIC) },
        onSetExperimentalBpfEnabled = actions.onSetExperimentalBpfEnabled,
        onRunProbes = actions.onRunProbes,
        onGrantPermission = actions.onGrantPermission,
        onShizukuAction = actions.onShizukuAction,
        onRestartOnboarding = actions.onRestartOnboarding,
        automation = AutomationActions(
            onSetEnabled = actions.onSetAutomation,
            onRegenerateToken = actions.onRegenerateAutomationToken,
        ),
    )
}

@Composable
private fun LogRoute(context: ScreenContext) {
    val actions = context.actions
    val navigation = context.navigation

    LogPage(
        log = rememberLogEntries(),
        toasts = context.toasts,
        isLogging = context.state.settings.isLogging,
        actions = LogActions(
            onClear = actions.onClearLog,
            onEnableLogging = { actions.onSetLogging(true) },
            onStartSession = actions.onToggle,
            onBack = navigation.goBack,
        ),
    )
}
