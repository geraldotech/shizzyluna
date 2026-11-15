package dev.shizzi.ui

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.window.Dialog
import dev.shizzi.AppPermission
import dev.shizzi.BuildConfig
import dev.shizzi.PermissionStatus
import dev.shizzi.ShizukuState
import dev.shizzi.VpnMode
import dev.shizzi.ui.theme.AccentChoice
import dev.shizzi.ui.theme.DesignLanguage
import dev.shizzi.ui.theme.ScreenPadding
import dev.shizzi.ui.theme.ShizziTheme
import dev.shizzi.ui.theme.ThemeChoice
import dev.shizzi.ui.theme.standardTween
import dev.shizzi.ui.theme.themedSurface

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import dev.shizzi.BlockingMode
import dev.shizzi.BpfAttributionStatusReport
import dev.shizzi.BpfSnapshotHealth
import dev.shizzi.ClientRule
import dev.shizzi.ConnectedClient
import dev.shizzi.PhaseDEnforcementMode
import dev.shizzi.PreNatCapabilityStatus
import dev.shizzi.PreNatRuntimeState
import dev.shizzi.SoftApEngineState
import dev.shizzi.Traffic
import java.io.File

internal const val ABOUT_GITHUB_URL = "https://github.com/geraldotech/"

private const val BusyAlpha = 0.4f

private const val SectionStaggerMillis = 45

private val SectionRise = 12.dp

data class SettingsState(
    val shizuku: ShizukuState,
    val permissions: List<PermissionStatus>,
    val theme: ThemeChoice,
    val design: DesignLanguage,
    val accent: AccentChoice,
    val customAccents: List<Int>,
    val isLogging: Boolean,
    val vpnMode: VpnMode,
    val stopHotspotOnVpnDisconnect: Boolean = true,
    val isRunningDiagnostics: Boolean,
    val automation: AutomationState,
    val dnsSettings: dev.shizzi.DnsSettings,
    val experimentalBpfEnabled: Boolean = false,
    val bpfRefreshOnMissEnabled: Boolean = false,
    val bpfDeepTupleDiagnosticsEnabled: Boolean = false,
    val bpfExportPseudonymousIds: Boolean = false,
    val phaseDEnforcementMode: PhaseDEnforcementMode = PhaseDEnforcementMode.DIAGNOSTIC,
    val requestedBlockingMode: BlockingMode = BlockingMode.BPF_NAT_VPN,
    val bpfReport: BpfAttributionStatusReport = BpfAttributionStatusReport(),
    val isCollectingBpf: Boolean = false,
    val connectedClients: List<ConnectedClient> = emptyList(),
    val clientRules: List<ClientRule> = emptyList(),
    val domainRules: List<dev.shizzi.DomainRule> = emptyList(),
)

data class SettingsActions(
    val onSetTheme: (ThemeChoice) -> Unit,
    val onSetDesign: (DesignLanguage) -> Unit,
    val onSetAccent: (AccentChoice) -> Unit,
    val onAddCustomAccent: (Int) -> Unit,
    val onSetLogging: (Boolean) -> Unit,
    val onSetVpnMode: (VpnMode) -> Unit,
    val onSetStopHotspotOnVpnDisconnect: (Boolean) -> Unit = {},
    val onSetDnsPreset: (dev.shizzi.DnsPreset) -> Unit,
    val onSetCustomDns: (String, String) -> Unit,
    val onOpenClients: () -> Unit,
    val onOpenDomainBlocking: () -> Unit = {},
    val onOpenLog: () -> Unit,
    val onOpenFirewallDiagnostic: () -> Unit = {},
    val onSetExperimentalBpfEnabled: (Boolean) -> Unit = {},
    val onSetBpfRefreshOnMissEnabled: (Boolean) -> Unit = {},
    val onSetBpfDeepTupleDiagnosticsEnabled: (Boolean) -> Unit = {},
    val onSetBpfExportPseudonymousIds: (Boolean) -> Unit = {},
    val onSetPhaseDEnforcementMode: (PhaseDEnforcementMode) -> Unit = {},
    val onRecordPhaseDDeliveryTestMarker: (String, String) -> Unit = { _, _ -> },
    val onSelectBlockingMode: (BlockingMode) -> Unit = {},
    val onCheckPreNatCapability: () -> Unit = {},
    val onReviewPreNatScopedProbe: () -> Unit = {},
    val onRunPreNatScopedProbe: (Boolean) -> Unit = {},
    val onActivatePreNatMode: () -> Unit = {},
    val onRestoreBpfMode: () -> Unit = {},
    val onCheckSoftApCapability: () -> Unit = {},
    val onRunSoftApLiveProbe: (String, String, Boolean, Int) -> Unit = { _, _, _, _ -> },
    val onActivateSoftApMode: () -> Unit = {},
    val onCollectBpfSnapshotNow: () -> Unit = {},
    val onResetBpfDiagnosticsCounters: () -> Unit = {},
    val onRunProbes: () -> Unit,
    val onGrantPermission: (AppPermission) -> Unit,
    val onShizukuAction: () -> Unit,
    val onRestartOnboarding: () -> Unit,
    val automation: AutomationActions,
)

@Composable
fun SettingsPage(
    state: SettingsState,
    actions: SettingsActions,
    toasts: ToastState,
    onBack: () -> Unit,
) {
    val isBusy = state.isRunningDiagnostics

    val busyAlpha by animateFloatAsState(
        targetValue = if (isBusy) BusyAlpha else 1f,
        animationSpec = standardTween(),
        label = "settingsBusy",
    )

    Column(modifier = Modifier.fillMaxSize().systemBarsPadding()) {

        ScreenHeader(title = "Settings", onBack = onBack)

        Column(
            modifier = Modifier
                .verticalScroll(rememberScrollState(), enabled = !isBusy)
                .alpha(busyAlpha)
                .inert(isBusy)
                .padding(horizontal = ScreenPadding),
        ) {
            settingsSections(state, actions, toasts).forEachIndexed { index, section ->
                SettingsSection(index = index, label = section.label, content = section.content)
            }

            Spacer(Modifier.height(ShizziTheme.spacing.xxl))
        }
    }
}

@Immutable
private data class SettingsSectionSpec(
    val label: String,
    val content: @Composable () -> Unit,
)

private fun settingsSections(
    state: SettingsState,
    actions: SettingsActions,
    toasts: ToastState,
): List<SettingsSectionSpec> = listOf(
    SettingsSectionSpec("Appearance") {
        AppearanceSection(
            state = AppearanceState(
                theme = state.theme,
                design = state.design,
                accent = state.accent,
                customAccents = state.customAccents,
            ),
            actions = AppearanceActions(
                onSetTheme = actions.onSetTheme,
                onSetDesign = actions.onSetDesign,
                onSetAccent = actions.onSetAccent,
                onAddCustomAccent = actions.onAddCustomAccent,
            ),
        )
    },

    SettingsSectionSpec("Permissions") {
        PermissionsSection(
            state = PermissionsSectionState(
                shizuku = state.shizuku,
                permissions = state.permissions,
            ),
            onGrantPermission = actions.onGrantPermission,
            onShizukuAction = actions.onShizukuAction,
        )
    },

    SettingsSectionSpec("Network & DNS") {
        DnsSection(
            settings = state.dnsSettings,
            onSetPreset = actions.onSetDnsPreset,
            onSetCustomDns = actions.onSetCustomDns,
        )

        Spacer(Modifier.height(12.dp))

        SettingsAction(
            label = SettingsText(
                title = "Connected Hosts & Bandwidth",
                subtitle = "Manage devices, MAC blocking, speed limits, schedule",
            ),
            onClick = actions.onOpenClients,
        )

        Spacer(Modifier.height(10.dp))

        val globalDomainCount = state.domainRules.count { it.scope == dev.shizzi.DomainRuleScope.GLOBAL && it.enabled }
        val clientDomainCount = state.domainRules.count { it.scope == dev.shizzi.DomainRuleScope.CLIENT && it.enabled }
        SettingsAction(
            label = SettingsText(
                title = "Domain Blocking (Global & Per-Host)",
                subtitle = "$globalDomainCount global • $clientDomainCount per-host active rules",
            ),
            onClick = actions.onOpenDomainBlocking,
        )
    },

    SettingsSectionSpec("Advanced") {
        VpnSection(
            selected = state.vpnMode,
            onSelect = actions.onSetVpnMode,
            stopHotspotOnVpnDisconnect = state.stopHotspotOnVpnDisconnect,
            onSetStopHotspotOnVpnDisconnect = actions.onSetStopHotspotOnVpnDisconnect,
        )

        AutomationSection(
            state = state.automation,
            actions = actions.automation,
            toasts = toasts,
        )
    },

    SettingsSectionSpec("Blocking Mode") {
        BlockingModeSection(
            state = state,
            actions = actions,
            toasts = toasts,
        )
    },

    SettingsSectionSpec("Developer") {
        DeveloperSection(
            state = state,
            actions = actions,
            toasts = toasts,
        )
    },

    SettingsSectionSpec("About") { AboutSection() },
)

/** Staggers each section in on first composition so the page assembles itself. */
@Composable
private fun SettingsSection(index: Int, label: String, content: @Composable () -> Unit) {
    var hasEntered by remember { mutableStateOf(false) }

    val progress by animateFloatAsState(
        targetValue = if (hasEntered) 1f else 0f,
        animationSpec = tween(
            durationMillis = ShizziTheme.motion.standardMillis,
            delayMillis = index * SectionStaggerMillis,
            easing = ShizziTheme.motion.easing,
        ),
        label = "sectionEntrance",
    )

    LaunchedEffect(Unit) { hasEntered = true }

    val shift = with(LocalDensity.current) { SectionRise.toPx() }

    Column(
        modifier = Modifier.graphicsLayer {
            alpha = progress
            translationY = (1f - progress) * shift
        },
    ) {
        SectionLabel(label)
        content()
    }
}

private fun Modifier.inert(isBusy: Boolean): Modifier = when {
    !isBusy -> this
    else -> this.pointerInput(Unit) {
        awaitPointerEventScope {
            while (true) {
                awaitPointerEvent(PointerEventPass.Initial)
                    .changes
                    .forEach { it.consume() }
            }
        }
    }
}

@Composable
internal fun BlockingModeSection(
    state: SettingsState,
    actions: SettingsActions,
    @Suppress("UNUSED_PARAMETER") toasts: ToastState,
) {
    val preNat = state.bpfReport.preNatDiagnostics
    val softAp = state.bpfReport.softApDiagnostics

    val activeModeLabel = when (preNat.effectiveModeNullable ?: preNat.requestedMode) {
        BlockingMode.SOFTAP_MAC_BLOCK -> "SoftAP MAC Block"
        BlockingMode.BPF_NAT_VPN -> "BPF/NAT + VPN"
    }

    val isSoftApUnavailable = preNat.requestedMode == BlockingMode.SOFTAP_MAC_BLOCK &&
        (softAp.engineState.isTerminalUnsupported ||
            softAp.engineState == SoftApEngineState.SHIZUKU_NOT_RUNNING ||
            softAp.engineState == SoftApEngineState.SHIZUKU_PERMISSION_REQUIRED ||
            softAp.engineState == SoftApEngineState.BLOCK_FAILED ||
            softAp.engineState == SoftApEngineState.ROLLBACK_REQUIRED)

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.primary.copy(alpha = 0.4f)),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("blocking_mode_card"),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "Blocking Mode",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )

            Text(
                text = "Choose how blocked devices are restricted on your hotspot.",
                fontSize = 11.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
            )

            // Radio 1: BPF/NAT + VPN (Default)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .clickable { actions.onSelectBlockingMode(BlockingMode.BPF_NAT_VPN) }
                    .padding(vertical = 4.dp)
                    .testTag("blocking_mode_radio_bpf_row"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = preNat.requestedMode == BlockingMode.BPF_NAT_VPN,
                    onClick = { actions.onSelectBlockingMode(BlockingMode.BPF_NAT_VPN) },
                    modifier = Modifier.testTag("blocking_mode_radio_bpf"),
                )
                Column(modifier = Modifier.padding(start = 6.dp)) {
                    Text(
                        text = BlockingMode.BPF_NAT_VPN.displayTitle,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Text(
                        text = "Userspace VPN mode with internet blocking, data limits, bandwidth limits, and domain rules.",
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
            }

            // Radio 2: SoftAP MAC Block (Experimental)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .clickable { actions.onSelectBlockingMode(BlockingMode.SOFTAP_MAC_BLOCK) }
                    .padding(vertical = 4.dp)
                    .testTag("blocking_mode_radio_softap_row"),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = preNat.requestedMode == BlockingMode.SOFTAP_MAC_BLOCK,
                    onClick = { actions.onSelectBlockingMode(BlockingMode.SOFTAP_MAC_BLOCK) },
                    modifier = Modifier.testTag("blocking_mode_radio_softap"),
                )
                Column(modifier = Modifier.padding(start = 6.dp)) {
                    Text(
                        text = BlockingMode.SOFTAP_MAC_BLOCK.displayTitle,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Text(
                        text = "Uses hotspot-level MAC blocking to disconnect blocked clients. Bandwidth throttling is not supported in this mode.",
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
            }

            HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("blocking_mode_status_summary"),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    text = "Current mode: $activeModeLabel",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.primary,
                    modifier = Modifier.testTag("blocking_mode_active_modes"),
                )
                if (isSoftApUnavailable) {
                    Text(
                        text = "SoftAP MAC Block is unavailable on this device.",
                        fontSize = 11.sp,
                        color = Color(0xFFE57373),
                        modifier = Modifier.testTag("softap_unavailable_notice"),
                    )
                }
            }
        }
    }
}

@Composable
private fun DeveloperSection(
    state: SettingsState,
    actions: SettingsActions,
    toasts: ToastState,
) {
    val context = LocalContext.current

    SettingsToggle(
        label = SettingsText(title = "Logging"),
        isChecked = state.isLogging,
        onCheckedChange = actions.onSetLogging,
    )

    SettingsToggle(
        label = SettingsText(
            title = "Experimental BPF NAT Attribution",
            subtitle = "Improves per-device traffic and domain attribution on hotspot connections",
        ),
        isChecked = state.experimentalBpfEnabled,
        onCheckedChange = actions.onSetExperimentalBpfEnabled,
    )

    Spacer(Modifier.height(10.dp))

    SettingsAction(
        label = SettingsText(title = "View logs"),
        onClick = actions.onOpenLog,
    )

    SettingsAction(
        label = SettingsText(title = "Run diagnostics"),
        onClick = actions.onRunProbes,
    )

    SettingsAction(
        label = SettingsText(
            title = "Export diagnostics",
            subtitle = "Share or copy a support report",
        ),
        modifier = Modifier.testTag("export_diagnostics_action"),
        onClick = {
            exportAndShareBpfDiagnostics(
                context = context,
                report = state.bpfReport,
                includePseudonymousIds = state.bpfExportPseudonymousIds,
                toasts = toasts,
            )
        },
    )

    SettingsAction(
        label = SettingsText(title = "Restart onboarding"),
        onClick = actions.onRestartOnboarding,
    )
}

@Composable
internal fun BpfAttributionDiagnosticsDebugPanel(
    report: BpfAttributionStatusReport,
    refreshOnMissEnabled: Boolean,
    deepTupleDiagnosticsEnabled: Boolean = false,
    exportPseudonymousIds: Boolean,
    phaseDEnforcementMode: PhaseDEnforcementMode = PhaseDEnforcementMode.DIAGNOSTIC,
    isCollectingBpf: Boolean,
    onSetRefreshOnMissEnabled: (Boolean) -> Unit,
    onSetDeepTupleDiagnosticsEnabled: (Boolean) -> Unit = {},
    onSetExportPseudonymousIds: (Boolean) -> Unit,
    onSetPhaseDEnforcementMode: (PhaseDEnforcementMode) -> Unit = {},
    onRecordPhaseDDeliveryTestMarker: (String, String) -> Unit = { _, _ -> },
    onCaptureSnapshot: () -> Unit,
    onResetCounters: () -> Unit,
    toasts: ToastState,
) {
    val context = LocalContext.current
    var showResetConfirmation by rememberSaveable { mutableStateOf(false) }

    val healthColor = when (report.snapshotHealth) {
        BpfSnapshotHealth.OK -> Color(0xFF4CAF50)
        BpfSnapshotHealth.STALE -> Color(0xFFFFA000)
        BpfSnapshotHealth.UNAVAILABLE -> Color(0xFF90A4AE)
        BpfSnapshotHealth.PARSE_FAILURE -> Color(0xFFE57373)
    }

    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.primary.copy(alpha = 0.4f)),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("bpf_diagnostics_debug_card"),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "BPF Attribution Diagnostics (Debug)",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = ShizziTheme.colors.onSurface,
                )
                Text(
                    text = report.snapshotHealth.name,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    color = healthColor,
                    modifier = Modifier.testTag("bpf_diag_snapshot_health"),
                )
            }

            val refreshLabel = if (report.lastSuccessfulRefreshEpochMs > 0L) {
                "age=${report.snapshotAgeMs}ms (dur=${report.lastCollectionDurationMs}ms)"
            } else {
                "never refreshed"
            }
            Text(
                text = "Snapshot: $refreshLabel • flows=${report.activeMappedFlows} • " +
                    "collections=${report.totalCollectionsSucceeded}/${report.totalCollectionsAttempted} ok (fail=${report.totalCollectionsFailed})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_diag_snapshot_stats"),
            )

            Text(
                text = "Coverage: pkts=${report.formattedPacketCoverage()} (${report.totalAttributedPackets}/${report.totalEligiblePackets}) • " +
                    "bytes=${report.formattedByteCoverage()} (${Traffic.format(report.totalAttributedBytes)}/${Traffic.format(report.totalEligibleBytes)})",
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                fontSize = 11.sp,
                color = ShizziTheme.colors.primary,
                modifier = Modifier.testTag("bpf_diag_coverage_summary"),
            )

            Text(
                text = "Attributed: DIRECT_IP=${report.directAttributedPackets}p (${Traffic.format(report.directAttributedBytes)}) • " +
                    "BPF_NAT=${report.bpfAttributedPackets}p (${Traffic.format(report.bpfAttributedBytes)}) • " +
                    "CONNTRACK=${report.conntrackAttributedPackets}p (${Traffic.format(report.conntrackAttributedBytes)})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_diag_source_breakdown"),
            )

            Text(
                text = "Unattributed Forwarded: ${report.unknownForwardedPackets}p (${Traffic.format(report.unknownForwardedBytes)}) • " +
                    "Conntrack Fallbacks: ${report.conntrackFallbackSucceededCount}/${report.conntrackFallbackAttemptedCount} (fail=${report.conntrackFallbackFailedCount})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = if (report.unknownForwardedPackets > 0L) Color(0xFFFFA000) else ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_diag_unattributed_summary"),
            )

            val topReasons = report.unattributedPacketsByReason.entries
                .filter { it.value > 0L }
                .sortedByDescending { it.value }
                .take(4)
            val reasonsText = if (topReasons.isEmpty()) {
                "Top Failure Reasons: none"
            } else {
                "Top Failure Reasons: " + topReasons.joinToString(", ") { (reason, pkts) ->
                    val bytes = report.unattributedBytesByReason[reason] ?: 0L
                    "$reason=${pkts}p (${Traffic.format(bytes)})"
                }
            }
            Text(
                text = reasonsText,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_diag_top_reasons"),
            )

            val v4Pkts = report.ipv4EligiblePackets
            val v6Pkts = report.ipv6EligiblePackets
            val tcpPkts = report.tcpEligiblePackets
            val udpPkts = report.udpEligiblePackets
            val icmpPkts = report.icmpEligiblePackets
            val upPkts = report.uploadEligiblePackets
            val downPkts = report.downloadEligiblePackets
            Text(
                text = "Split: IPv4=${v4Pkts}p IPv6=${v6Pkts}p • TCP=${tcpPkts}p UDP=${udpPkts}p ICMP=${icmpPkts}p • UP=${upPkts}p DOWN=${downPkts}p",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
            )

            Text(
                text = "Policies: blocked=${report.blockedClientsCount} quotaExceeded=${report.quotaExhaustedClientsCount} " +
                    "rateLimited=${report.throttledClientsCount} (blockDrops=${report.blockedDropPackets}, shapeDrops=${report.shapingDropPackets})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
            )

            HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Phase B: Async BPF Refresh-on-Miss",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Text(
                        text = "Single-flight non-blocking refresh on TUPLE_NOT_PRESENT / SNAPSHOT_STALE (${report.refreshOnMissCooldownMs}ms cooldown, OFF by default)",
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
                Switch(
                    checked = refreshOnMissEnabled,
                    onCheckedChange = onSetRefreshOnMissEnabled,
                    modifier = Modifier.testTag("bpf_refresh_on_miss_switch"),
                )
            }

            Text(
                text = "Phase B Stats: trig=${report.refreshOnMissTriggeredCount} coal=${report.refreshOnMissCoalescedInFlightCount} " +
                    "cool=${report.refreshOnMissSuppressedCooldownCount} brk=${report.missRefreshSuppressedBreakerCount} " +
                    "ok=${report.refreshOnMissCompletedCount} fail=${report.missRefreshFailedCount} " +
                    "postHits=${report.postRefreshAttributedPackets}p (${Traffic.format(report.postRefreshAttributedBytes)})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_phase_b_stats"),
            )

            Text(
                text = "Phase B Latency/Breaker: state=${report.refreshCircuitBreakerState} • " +
                    "p50=${report.missRefreshLatencyP50Ms}ms p95=${report.missRefreshLatencyP95Ms}ms p99=${report.missRefreshLatencyP99Ms}ms max=${report.missRefreshLatencyMaxMs}ms • " +
                    "resolvedKeys=${report.postRefreshFlowKeysResolved} firstSubseq=${report.postRefreshFirstSubsequentAttributedPackets}p",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_phase_b_latency_breaker"),
            )

            if (report.refreshOnMissAutoDisabled) {
                Text(
                    text = "Circuit Breaker: Refresh-on-miss is ${report.refreshCircuitBreakerState} after repeated collection failures (30s cooldown probe).",
                    fontSize = 10.sp,
                    color = Color(0xFFE57373),
                    modifier = Modifier.testTag("bpf_phase_b_autodisabled_warning"),
                )
            }

            HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Phase C: Deep Tuple & Survival Diagnostics",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 12.sp,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Text(
                        text = "Bounded LRU flow miss tracker (2048 max flows, 60s TTL, OFF by default)",
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
                Switch(
                    checked = deepTupleDiagnosticsEnabled,
                    onCheckedChange = onSetDeepTupleDiagnosticsEnabled,
                    modifier = Modifier.testTag("bpf_deep_tuple_diag_switch"),
                )
            }

            Text(
                text = "Phase C Flows: active=${report.activeTrackedFlowsCount} resolved=${report.resolvedAfterRefreshFlowsCount} " +
                    "persist=${report.persistentAfterRefreshFlowsCount} notOffloaded=${report.notOffloadedOrNotObservableFlowsCount} " +
                    "keyMismatch=${report.keyMismatchSuspectedFlowsCount}",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_phase_c_stats"),
            )

            Text(
                text = "Survival: 0snap=${report.survived0SnapshotsCount} 1snap=${report.survived1SnapshotCount} " +
                    "2snap=${report.survived2SnapshotsCount} 3+snap=${report.survived3PlusSnapshotsCount} • " +
                    "UDP/443=${report.udp443MissingPacketsCount}p UDP/53=${report.udp53MissingPacketsCount}p",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("bpf_phase_c_survival_stats"),
            )

            HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))

            Text(
                text = "Phase D: Persistent Connection Leak & Enforcement Mode",
                fontWeight = FontWeight.SemiBold,
                fontSize = 12.sp,
                color = ShizziTheme.colors.onSurface,
            )
            Text(
                text = "DIAGNOSTIC preserves 0.10.4-debug forwarding; EXPERIMENTAL_ENFORCEMENT re-evaluates verified flows & pins across snapshots while keeping UNKNOWN_OWNER => ALLOW.",
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                val isDiag = phaseDEnforcementMode == PhaseDEnforcementMode.DIAGNOSTIC
                if (isDiag) {
                    Button(
                        onClick = { onSetPhaseDEnforcementMode(PhaseDEnforcementMode.DIAGNOSTIC) },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ShizziTheme.colors.primary,
                            contentColor = ShizziTheme.colors.onPrimary,
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("phase_d_mode_diagnostic_button"),
                    ) {
                        Text("DIAGNOSTIC (Default)", fontSize = 10.sp)
                    }
                    OutlinedButton(
                        onClick = { onSetPhaseDEnforcementMode(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) },
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("phase_d_mode_enforcement_button"),
                    ) {
                        Text("EXPERIMENTAL_ENF", fontSize = 10.sp)
                    }
                } else {
                    OutlinedButton(
                        onClick = { onSetPhaseDEnforcementMode(PhaseDEnforcementMode.DIAGNOSTIC) },
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("phase_d_mode_diagnostic_button"),
                    ) {
                        Text("DIAGNOSTIC (Default)", fontSize = 10.sp)
                    }
                    Button(
                        onClick = { onSetPhaseDEnforcementMode(PhaseDEnforcementMode.EXPERIMENTAL_ENFORCEMENT) },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ShizziTheme.colors.primary,
                            contentColor = ShizziTheme.colors.onPrimary,
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("phase_d_mode_enforcement_button"),
                    ) {
                        Text("EXPERIMENTAL_ENF", fontSize = 10.sp)
                    }
                }
            }

            Text(
                text = "Phase D: mode=${report.phaseDMode} • lifecycle=${report.interfaceLifecycleState} • " +
                    "pins=${report.activePinnedVerifiedFlowsCount} (hits=${report.pinnedVerifiedFlowHitsPackets}p, diagHits=${report.pinnedFlowHitsInDiagnosticMode}p) • " +
                    "recomputed=${report.decisionsRecomputed} stalePrev=${report.staleAllowCacheHitsPrevented}",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("phase_d_stats"),
            )

            Text(
                text = "Post-Block: verDrop=${report.verifiedDroppedAfterBlockPackets}p (${Traffic.format(report.verifiedDroppedAfterBlockBytes)}) • " +
                    "verAllow=${report.verifiedAllowedAfterBlockPackets}p • " +
                    "unkFwdAfterBlock=${report.unknownForwardedAfterBlockPackets}p (${Traffic.format(report.unknownForwardedAfterBlockBytes)})",
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("phase_d_post_block_stats"),
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = {
                        onRecordPhaseDDeliveryTestMarker("TEST_SESSION_START", "UI test start marker")
                    },
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("phase_d_mark_test_start_button"),
                ) {
                    Text("Mark Test Start", fontSize = 10.sp)
                }
                OutlinedButton(
                    onClick = {
                        onRecordPhaseDDeliveryTestMarker("TEST_SESSION_STOP", "UI test stop marker")
                    },
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("phase_d_mark_test_stop_button"),
                ) {
                    Text("Mark Test Stop", fontSize = 10.sp)
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Include pseudonymous client/IP hashes (SHA-256)",
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Switch(
                    checked = exportPseudonymousIds,
                    onCheckedChange = onSetExportPseudonymousIds,
                    modifier = Modifier.testTag("bpf_export_pseudonymous_switch"),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { showResetConfirmation = true },
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("bpf_reset_counters_button"),
                ) {
                    Text("Reset counters", fontSize = 11.sp)
                }

                Button(
                    onClick = onCaptureSnapshot,
                    enabled = !isCollectingBpf,
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = ShizziTheme.colors.primary,
                        contentColor = ShizziTheme.colors.onPrimary,
                    ),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("bpf_capture_snapshot_button"),
                ) {
                    Text(if (isCollectingBpf) "Capturing…" else "Capture snapshot", fontSize = 11.sp)
                }

                OutlinedButton(
                    onClick = {
                        exportAndShareBpfDiagnostics(
                            context = context,
                            report = report,
                            includePseudonymousIds = exportPseudonymousIds,
                            toasts = toasts,
                        )
                    },
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("bpf_export_diagnostics_button"),
                ) {
                    Text("Export diagnostics", fontSize = 11.sp)
                }
            }
        }
    }

    if (showResetConfirmation) {
        Dialog(onDismissRequest = { showResetConfirmation = false }) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .themedSurface(fill = ShizziTheme.colors.surface)
                    .padding(ShizziTheme.spacing.lg)
                    .testTag("bpf_reset_counters_dialog"),
                verticalArrangement = Arrangement.spacedBy(ShizziTheme.spacing.md),
            ) {
                Text(
                    text = "Reset Diagnostic Counters?",
                    style = ShizziTheme.typography.heading,
                    color = ShizziTheme.colors.onSurface,
                )
                Text(
                    text = "This zeroes BPF attribution and packet diagnostic counters for a clean test window. Client rules, blocks, bandwidth limits, and data quotas are preserved.",
                    style = ShizziTheme.typography.body,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(
                        onClick = { showResetConfirmation = false },
                        modifier = Modifier.testTag("bpf_reset_counters_cancel_button"),
                    ) {
                        Text("Cancel", color = ShizziTheme.colors.onSurfaceMuted)
                    }
                    Spacer(Modifier.width(8.dp))
                    Button(
                        onClick = {
                            showResetConfirmation = false
                            onResetCounters()
                        },
                        modifier = Modifier.testTag("bpf_reset_counters_confirm_button"),
                    ) {
                        Text("Reset Counters")
                    }
                }
            }
        }
    }
}

internal data class ExportedDiagnosticsFiles(
    val markdownFile: File,
    val jsonFile: File,
    val authority: String,
)

internal fun writeBpfDiagnosticsExportFiles(
    context: Context,
    report: BpfAttributionStatusReport,
    includePseudonymousIds: Boolean,
    timestampMs: Long = System.currentTimeMillis(),
): ExportedDiagnosticsFiles {
    val exportDir = File(context.filesDir, "exports").apply { mkdirs() }
    val markdownFile = File(exportDir, "shizzyluna-bpf-diagnostics-$timestampMs.md")
    val jsonFile = File(exportDir, "shizzyluna-bpf-diagnostics-$timestampMs.json")

    val markdownText = report.toMarkdownReport(
        apkVersion = BuildConfig.VERSION_NAME,
        sourceCommit = BuildConfig.SOURCE_COMMIT,
        serviceBuildId = BuildConfig.SERVICE_BUILD_ID,
        includeSensitiveEndpoints = false,
        includePseudonymousIds = includePseudonymousIds,
    )
    val jsonText = report.toJson(
        includeSensitiveEndpoints = false,
        includePseudonymousIds = includePseudonymousIds,
    ).toString(2)

    markdownFile.writeText(markdownText)
    jsonFile.writeText(jsonText)

    return ExportedDiagnosticsFiles(
        markdownFile = markdownFile,
        jsonFile = jsonFile,
        authority = "${BuildConfig.APPLICATION_ID}.exports",
    )
}

private fun exportAndShareBpfDiagnostics(
    context: Context,
    report: BpfAttributionStatusReport,
    includePseudonymousIds: Boolean,
    toasts: ToastState,
) {
    runCatching {
        val exported = writeBpfDiagnosticsExportFiles(
            context = context,
            report = report,
            includePseudonymousIds = includePseudonymousIds,
        )
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        cm?.setPrimaryClip(ClipData.newPlainText("shizzyluna-bpf-diagnostics", exported.markdownFile.readText()))

        val uri = FileProvider.getUriForFile(context, exported.authority, exported.markdownFile)
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/markdown"
            putExtra(Intent.EXTRA_SUBJECT, "Shizzy Luna ${BuildConfig.VERSION_NAME} Diagnostics Report")
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_TEXT, exported.markdownFile.readText())
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(Intent.createChooser(shareIntent, "Export Diagnostics"))
        toasts.show(copiedToast("Diagnostics Export"))
    }.onFailure {
        val fallbackMd = report.toMarkdownReport(
            apkVersion = BuildConfig.VERSION_NAME,
            sourceCommit = BuildConfig.SOURCE_COMMIT,
            serviceBuildId = BuildConfig.SERVICE_BUILD_ID,
            includeSensitiveEndpoints = false,
            includePseudonymousIds = includePseudonymousIds,
        )
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        cm?.setPrimaryClip(ClipData.newPlainText("shizzyluna-bpf-diagnostics", fallbackMd))
        toasts.show(copiedToast("BPF Diagnostics Markdown"))
    }
}

@Composable
internal fun AboutSection(
    onOpenGitHubUrl: ((String) -> Unit)? = null,
) {
    val context = LocalContext.current
    var showAboutModal by rememberSaveable { mutableStateOf(false) }

    SettingsAction(
        label = SettingsText(
            title = "About",
            subtitle = "Version, author, and source repository",
        ),
        modifier = Modifier.testTag("about_settings_action"),
        onClick = { showAboutModal = true },
    )

    if (showAboutModal) {
        val versionName = remember(context) {
            runCatching {
                context.packageManager.getPackageInfo(context.packageName, 0).versionName
            }.getOrNull()?.takeIf { it.isNotBlank() } ?: BuildConfig.VERSION_NAME
        }
        AboutDialog(
            versionName = versionName,
            onOpenGitHub = {
                if (onOpenGitHubUrl != null) {
                    onOpenGitHubUrl(ABOUT_GITHUB_URL)
                } else {
                    context.openUrl(ABOUT_GITHUB_URL)
                }
            },
            onDismiss = { showAboutModal = false },
        )
    }
}

@Composable
internal fun AboutDialog(
    versionName: String = BuildConfig.VERSION_NAME,
    onOpenGitHub: () -> Unit,
    onDismiss: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .themedSurface(fill = ShizziTheme.colors.surface)
                .padding(ShizziTheme.spacing.lg)
                .testTag("about_modal_dialog"),
            verticalArrangement = Arrangement.spacedBy(ShizziTheme.spacing.md),
        ) {
            Text(
                text = "Shizzy Luna",
                style = ShizziTheme.typography.heading,
                color = ShizziTheme.colors.onSurface,
                modifier = Modifier.testTag("about_modal_title"),
            )

            Text(
                text = "Version $versionName",
                style = ShizziTheme.typography.body,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("about_modal_version"),
            )

            Text(
                text = "Author: GeraldoDev",
                style = ShizziTheme.typography.body.copy(fontWeight = FontWeight.Medium),
                color = ShizziTheme.colors.onSurface,
                modifier = Modifier.testTag("about_modal_author"),
            )

            Surface(
                shape = RoundedCornerShape(10.dp),
                color = ShizziTheme.colors.primary.copy(alpha = 0.12f),
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .clickable(onClick = onOpenGitHub)
                    .testTag("about_modal_github_button"),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "GitHub ↗",
                        style = ShizziTheme.typography.subheading,
                        color = ShizziTheme.colors.primary,
                    )
                    Text(
                        text = "github.com/geraldotech",
                        style = ShizziTheme.typography.caption,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(
                    onClick = onDismiss,
                    modifier = Modifier.testTag("about_modal_close_button"),
                ) {
                    Text(
                        text = "Close",
                        color = ShizziTheme.colors.primary,
                        style = ShizziTheme.typography.subheading,
                    )
                }
            }
        }
    }
}

