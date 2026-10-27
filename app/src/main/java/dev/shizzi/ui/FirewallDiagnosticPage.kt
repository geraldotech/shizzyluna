package dev.shizzi.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CleaningServices
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material3.Switch
import dev.shizzi.BpfAttributionStatusReport
import dev.shizzi.BuildConfig
import dev.shizzi.ConnectedClient
import dev.shizzi.FirewallDiagnosticReport
import dev.shizzi.FirewallDiagnosticStatus
import dev.shizzi.FirewallDiagnosticUiState
import dev.shizzi.Traffic
import dev.shizzi.ui.theme.ScreenPadding
import dev.shizzi.ui.theme.ShizziTheme

data class FirewallDiagnosticActions(
    val onRunReadOnlyProbes: () -> Unit,
    val onRunTemporaryClientPoc: (clientAMac: String, clientBMac: String, durationSec: Int) -> Unit,
    val onCleanupOrphanRules: () -> Unit,
    val onSetExperimentalBpfEnabled: (Boolean) -> Unit = {},
    val onSetBpfPollIntervalMs: (Int) -> Unit = {},
    val onCollectBpfSnapshotNow: () -> Unit = {},
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun FirewallDiagnosticPage(
    diagState: FirewallDiagnosticUiState,
    connectedClients: List<ConnectedClient>,
    actions: FirewallDiagnosticActions,
    toasts: ToastState,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    sessionBpfReport: BpfAttributionStatusReport = BpfAttributionStatusReport(),
    experimentalBpfEnabled: Boolean = false,
    bpfPollIntervalMs: Int = 1000,
) {
    val context = LocalContext.current
    var selectedClientAMac by remember(connectedClients) {
        mutableStateOf(connectedClients.firstOrNull()?.cleanMac.orEmpty())
    }
    var selectedClientBMac by remember(connectedClients) {
        mutableStateOf(connectedClients.drop(1).firstOrNull()?.cleanMac.orEmpty())
    }
    var durationSec by remember { mutableIntStateOf(5) }
    var showRawProbes by remember { mutableStateOf(false) }
    var includeDetailedEndpointsInExport by remember { mutableStateOf(true) }

    val report = diagState.report
    val bpfReport = diagState.bpfReport ?: sessionBpfReport
    val isBusy = diagState.isRunningProbes || diagState.isRunningClientPoc || diagState.isCollectingBpf

    Column(
        modifier = modifier
            .fillMaxSize()
            .systemBarsPadding(),
    ) {
        ScreenHeader(
            title = "Diagnóstico do firewall & BPF",
            onBack = onBack,
        )

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = ScreenPadding),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Experimental BPF NAT Flow Attribution Card
            item {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
                    border = BorderStroke(1.dp, ShizziTheme.colors.primary.copy(alpha = 0.45f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("diag_bpf_attribution_card"),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Experimental BPF NAT Flow Attribution",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp,
                                    color = ShizziTheme.colors.onSurface,
                                )
                                Text(
                                    text = "Lê dumpsys tethering bpf no Shizuku UserService (UID 2000) fora do caminho de pacotes.",
                                    fontSize = 11.sp,
                                    color = ShizziTheme.colors.onSurfaceMuted,
                                )
                            }
                            Switch(
                                checked = experimentalBpfEnabled,
                                onCheckedChange = actions.onSetExperimentalBpfEnabled,
                                modifier = Modifier.testTag("diag_bpf_enable_switch"),
                            )
                        }

                        Spacer(Modifier.height(8.dp))
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            listOf(500, 1000, 2000).forEach { interval ->
                                FilterChip(
                                    selected = bpfPollIntervalMs == interval,
                                    onClick = { actions.onSetBpfPollIntervalMs(interval) },
                                    label = { Text("Poll ${interval}ms", fontSize = 11.sp) },
                                )
                            }
                        }

                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "State: ${bpfReport.state.name} • Collection: ${bpfReport.collectionStatus.name} " +
                                "(age=${bpfReport.snapshotAgeMs}ms, dur=${bpfReport.lastCollectionDurationMs}ms, parser=v${bpfReport.parserVersion})",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = ShizziTheme.colors.primary,
                        )
                        Text(
                            text = "Gen: session=${bpfReport.sessionGeneration} binding=${bpfReport.bindingGeneration} • " +
                                "Ifaces: ${bpfReport.downstreamIface.ifBlank { "?" }}(${bpfReport.downstreamIfIndex}) -> ${bpfReport.upstreamIface.ifBlank { "?" }}(${bpfReport.upstreamIfIndex})",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Text(
                            text = "Flows: mapped=${bpfReport.activeMappedFlows} (up4=${bpfReport.totalUpstreamEntries}, down4=${bpfReport.totalDownstreamEntries}, revOk=${bpfReport.reverseMatchedCount}, ambig=${bpfReport.ambiguousTupleCount}, rejectedLines=${bpfReport.rejectedLineCount})",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Text(
                            text = "Packets: bpf=${bpfReport.bpfAttributedPackets} direct=${bpfReport.directAttributedPackets} " +
                                "unknownFwd=${bpfReport.unknownForwardedPackets} (${Traffic.format(bpfReport.unknownForwardedBytes)}) " +
                                "ambig/stale=${bpfReport.ambiguousOrStaleLookups} localCtrl=${bpfReport.localControlPackets} frag/unsup=${bpfReport.unsupportedOrFragmentPackets}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Text(
                            text = "Enforcement deltas: blockDrops=${bpfReport.blockedDropPackets} • shapeDrops=${bpfReport.shapingDropPackets} • shapedPkts=${bpfReport.shapedPackets} • synReuseGuards=${bpfReport.tupleReuseGuardTriggeredCount}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )

                        if (bpfReport.perClientCounts.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            HorizontalDivider(color = ShizziTheme.colors.border)
                            Spacer(Modifier.height(6.dp))
                            Text(
                                text = "Mapped BPF Flows per Client:",
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                            bpfReport.perClientCounts.forEach { c ->
                                Text(
                                    text = "• ${c.mac} (${c.originalIpv4}): TCP=${c.tcpFlows}, UDP=${c.udpFlows}, Total=${c.totalFlows}",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.sp,
                                    color = ShizziTheme.colors.onSurfaceMuted,
                                )
                            }
                        }

                        Spacer(Modifier.height(8.dp))
                        Text(
                            text = "Escopo experimental: entradas BPF offload surgem após o fluxo progredir. Pacotes iniciais antes da coleta permanecem unknownForwardedPackets (não são bloqueados globalmente para não afetar outros clientes).",
                            fontSize = 10.sp,
                            color = Color(0xFFFFA000),
                        )

                        Spacer(Modifier.height(8.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(
                                text = "Include full MAC/IP in BPF export",
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )
                            Switch(
                                checked = includeDetailedEndpointsInExport,
                                onCheckedChange = { includeDetailedEndpointsInExport = it },
                            )
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = actions.onCollectBpfSnapshotNow,
                                enabled = !isBusy,
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("collect_bpf_snapshot_now_button"),
                            ) {
                                Text("Collect BPF Now", fontSize = 11.sp)
                            }
                            OutlinedButton(
                                onClick = {
                                    val md = bpfReport.toMarkdownReport(
                                        apkVersion = BuildConfig.VERSION_NAME,
                                        sourceCommit = BuildConfig.SOURCE_COMMIT,
                                        serviceBuildId = BuildConfig.SERVICE_BUILD_ID,
                                        includeSensitiveEndpoints = includeDetailedEndpointsInExport,
                                    )
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    cm.setPrimaryClip(ClipData.newPlainText("shizzi-bpf-report", md))
                                    toasts.show(copiedToast("BPF Markdown"))
                                },
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.testTag("copy_bpf_markdown_button"),
                            ) {
                                Text("Copy BPF MD", fontSize = 11.sp)
                            }
                            OutlinedButton(
                                onClick = {
                                    val json = bpfReport.toJson(includeDetailedEndpointsInExport).toString(2)
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    cm.setPrimaryClip(ClipData.newPlainText("shizzi-bpf-json", json))
                                    toasts.show(copiedToast("BPF JSON"))
                                },
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.testTag("copy_bpf_json_button"),
                            ) {
                                Text("Copy JSON", fontSize = 11.sp)
                            }
                        }
                    }
                }
            }

            // Intro & Step 1: Read-Only Probes
            item {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
                    border = BorderStroke(1.dp, ShizziTheme.colors.border),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.Security,
                                contentDescription = null,
                                tint = ShizziTheme.colors.primary,
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = "Etapa 1 — Probes Somente de Leitura (Shizuku UserService)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Inspeciona UID/PID, SELinux, CapEff, callbacks SoftAP/Tethering, leitura vs escrita em netfilter/ip rule (Opção A) e acesso real a /proc/net/nf_conntrack (Opção B) sem alterar o tráfego dos clientes.",
                            fontSize = 12.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Spacer(Modifier.height(12.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Button(
                                onClick = actions.onRunReadOnlyProbes,
                                enabled = !isBusy,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = ShizziTheme.colors.primary,
                                    contentColor = ShizziTheme.colors.onPrimary,
                                ),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("run_firewall_readonly_probes_button"),
                            ) {
                                if (diagState.isRunningProbes) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = ShizziTheme.colors.onPrimary,
                                    )
                                } else {
                                    Icon(Icons.Filled.Science, contentDescription = null, modifier = Modifier.size(16.dp))
                                }
                                Spacer(Modifier.width(6.dp))
                                Text("Executar Probes de Leitura", fontSize = 12.sp)
                            }

                            OutlinedButton(
                                onClick = actions.onCleanupOrphanRules,
                                enabled = !isBusy,
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.testTag("cleanup_firewall_rules_button"),
                            ) {
                                Icon(Icons.Filled.CleaningServices, contentDescription = null, modifier = Modifier.size(16.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("Cleanup", fontSize = 12.sp)
                            }
                        }

                        if (diagState.lastCleanupResult.isNotBlank()) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                text = "Cleanup: ${diagState.lastCleanupResult}",
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )
                        }
                    }
                }
            }

            // Step 2: Controlled Temporary Client A PoC Test (Separate button)
            item {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
                    border = BorderStroke(1.dp, ShizziTheme.colors.border),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.Build,
                                contentDescription = null,
                                tint = Color(0xFFFFA000),
                                modifier = Modifier.size(20.dp),
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = "Etapa 2 — Teste Temporário Controlado (Cliente A vs Cliente B)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = "Testa a criação/remoção de chain própria (SHIZZI_TEST_<id>) apenas para os IPs verificados do Cliente A e mede a janela de primeiro pacote com cache vazio na Opção B. Regras temporárias são removidas automaticamente ao final.",
                            fontSize = 12.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Spacer(Modifier.height(10.dp))

                        if (connectedClients.isNotEmpty()) {
                            Text(
                                text = "Selecionar Cliente A (Alvo do Bloqueio):",
                                fontSize = 12.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = ShizziTheme.colors.onSurface,
                            )
                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.padding(vertical = 4.dp),
                            ) {
                                connectedClients.forEach { client ->
                                    FilterChip(
                                        selected = selectedClientAMac.equals(client.cleanMac, ignoreCase = true),
                                        onClick = {
                                            selectedClientAMac = client.cleanMac
                                            if (selectedClientBMac.equals(client.cleanMac, ignoreCase = true)) {
                                                selectedClientBMac = connectedClients
                                                    .firstOrNull { !it.cleanMac.equals(client.cleanMac, ignoreCase = true) }
                                                    ?.cleanMac.orEmpty()
                                            }
                                        },
                                        label = {
                                            Text("${client.displayName} (${client.ip})", fontSize = 11.sp)
                                        },
                                    )
                                }
                            }

                            if (connectedClients.size >= 2) {
                                Text(
                                    text = "Selecionar Cliente B (Controle — Deve Continuar Navegando):",
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = ShizziTheme.colors.onSurface,
                                )
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    modifier = Modifier.padding(vertical = 4.dp),
                                ) {
                                    connectedClients
                                        .filter { !it.cleanMac.equals(selectedClientAMac, ignoreCase = true) }
                                        .forEach { client ->
                                            FilterChip(
                                                selected = selectedClientBMac.equals(client.cleanMac, ignoreCase = true),
                                                onClick = { selectedClientBMac = client.cleanMac },
                                                label = {
                                                    Text("${client.displayName} (${client.ip})", fontSize = 11.sp)
                                                },
                                            )
                                        }
                                }
                            }
                        } else {
                            OutlinedTextField(
                                value = selectedClientAMac,
                                onValueChange = { selectedClientAMac = it.uppercase() },
                                label = { Text("MAC do Cliente A (ex.: E2:15:CD:54:E4:9B)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }

                        Spacer(Modifier.height(8.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Text("Janela:", fontSize = 12.sp, color = ShizziTheme.colors.onSurfaceMuted)
                            listOf(4, 6, 10).forEach { sec ->
                                FilterChip(
                                    selected = durationSec == sec,
                                    onClick = { durationSec = sec },
                                    label = { Text("${sec}s", fontSize = 11.sp) },
                                )
                            }
                        }

                        Spacer(Modifier.height(10.dp))
                        Button(
                            onClick = {
                                actions.onRunTemporaryClientPoc(
                                    selectedClientAMac.ifBlank { "E2:15:CD:54:E4:9B" },
                                    selectedClientBMac,
                                    durationSec,
                                )
                            },
                            enabled = !isBusy,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFFFFA000),
                                contentColor = Color.Black,
                            ),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("run_firewall_client_poc_button"),
                        ) {
                            if (diagState.isRunningClientPoc) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp,
                                    color = Color.Black,
                                )
                            } else {
                                Icon(Icons.Filled.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                            }
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = "Iniciar Teste Temporário no Cliente Escolhido (${durationSec}s)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            }

            if (diagState.error.isNotBlank()) {
                item {
                    Card(
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0xFFD32F2F).copy(alpha = 0.15f)),
                        border = BorderStroke(1.dp, Color(0xFFD32F2F)),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Filled.Warning, contentDescription = null, tint = Color(0xFFD32F2F))
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = diagState.error,
                                fontSize = 12.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                        }
                    }
                }
            }

            if (report != null) {
                // Overall Verdict & Export Card
                item {
                    VerdictAndExportCard(
                        report = report,
                        onCopyJson = {
                            copyToClipboard(context, "shizzi-firewall-diag.json", report.toJsonString())
                            toasts.show(copiedToast("JSON"))
                        },
                        onCopyMarkdown = {
                            copyToClipboard(context, "shizzi-firewall-diag.md", report.toMarkdownReport())
                            toasts.show(copiedToast("Markdown"))
                        },
                        onShare = {
                            shareTextReport(context, report.toMarkdownReport())
                        },
                    )
                }

                // Fase 1: Environment & Process Identity
                item {
                    Phase1IdentityCard(report)
                }

                // Fase 2: Mechanism Capabilities (Read vs Write vs Selective Enforcement)
                item {
                    Phase2CapabilitiesCard(report)
                }

                // Fase 3: Conntrack & TUN Flow Attribution
                item {
                    Phase3ConntrackCard(report)
                }

                // Temporary Client A PoC Result
                if (report.temporaryRuleTest.executed) {
                    item {
                        TemporaryTestResultCard(report)
                    }
                }

                // Confirmed Facts & Hypotheses
                item {
                    FactsAndHypothesesCard(report)
                }

                // Fase 4: 12-Scenario Physical Validation Matrix
                item {
                    Phase4ValidationMatrixCard(report)
                }

                // Raw Read-Only Probes Toggle
                item {
                    Card(
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
                        border = BorderStroke(1.dp, ShizziTheme.colors.border),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showRawProbes = !showRawProbes },
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(
                                    text = "Saída dos Probes Somente de Leitura (${report.probes.size})",
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = ShizziTheme.colors.onSurface,
                                )
                                Text(
                                    text = if (showRawProbes) "Ocultar" else "Expandir",
                                    fontSize = 12.sp,
                                    color = ShizziTheme.colors.primary,
                                )
                            }
                            if (showRawProbes) {
                                Spacer(Modifier.height(10.dp))
                                report.probes.forEach { probe ->
                                    HorizontalDivider(
                                        modifier = Modifier.padding(vertical = 6.dp),
                                        color = ShizziTheme.colors.border,
                                    )
                                    Text(
                                        text = "${probe.probeName} (${probe.command}) -> exit=${probe.exitCode} kind=${probe.errorKind.name}",
                                        fontFamily = FontFamily.Monospace,
                                        fontWeight = FontWeight.SemiBold,
                                        fontSize = 11.sp,
                                        color = ShizziTheme.colors.onSurface,
                                    )
                                    if (probe.boundedStderr.isNotBlank()) {
                                        Text(
                                            text = "stderr: ${probe.boundedStderr}",
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 10.sp,
                                            color = Color(0xFFE57373),
                                        )
                                    }
                                    if (probe.boundedStdout.isNotBlank()) {
                                        Text(
                                            text = probe.boundedStdout.take(500),
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 10.sp,
                                            color = ShizziTheme.colors.onSurfaceMuted,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }

            item {
                Spacer(Modifier.height(32.dp))
            }
        }
    }
}

@Composable
private fun VerdictAndExportCard(
    report: FirewallDiagnosticReport,
    onCopyJson: () -> Unit,
    onCopyMarkdown: () -> Unit,
    onShare: () -> Unit,
) {
    val badgeColor = statusColor(report.overallStatus)
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = badgeColor.copy(alpha = 0.12f)),
        border = BorderStroke(1.dp, badgeColor.copy(alpha = 0.5f)),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("firewall_diag_verdict_card"),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = "Resultado: ${report.overallStatus.name}",
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = badgeColor,
                    modifier = Modifier.testTag("firewall_diag_overall_status"),
                )
                Text(
                    text = report.testId,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(
                text = report.finalDecision,
                fontSize = 12.sp,
                color = ShizziTheme.colors.onSurface,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onCopyJson,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("copy_firewall_json_button"),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("JSON", fontSize = 11.sp)
                }
                OutlinedButton(
                    onClick = onCopyMarkdown,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("copy_firewall_markdown_button"),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Markdown", fontSize = 11.sp)
                }
                OutlinedButton(
                    onClick = onShare,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier
                        .weight(1f)
                        .testTag("share_firewall_report_button"),
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Exportar", fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
private fun Phase1IdentityCard(report: FirewallDiagnosticReport) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = "Fase 1 — Identidade do Processo & Ambiente",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            MonoRow("APK / Build / Commit", "${report.apkVersion} (vc=${report.versionCode}, svc=${report.serviceBuildId}) • ${report.sourceCommit}")
            MonoRow("Aparelho / API", "${report.device} • Android ${report.androidRelease} (API ${report.androidApi})")
            MonoRow("Módulo Tethering", report.tetheringModuleVersion)
            MonoRow("UID / PID / Shizuku", "uid=${report.uid} pid=${report.pid} shizukuUid=${report.shizukuUid} (${report.shizukuMode})")
            MonoRow("SELinux Context", report.selinuxContext)
            MonoRow("Capacidades (Proc)", report.effectiveCapabilitiesHex)
            MonoRow("Downstream / Upstream", "down=${report.downstreamInterface} • up=${report.upstreamInterface}")
            MonoRow("Datapath / VPN", "${report.datapathMode} • ${report.vpnState}")
            MonoRow("Callbacks Oficiais", "SoftAP=${report.softApCallbackStatus} • Tethering=${report.tetheringCallbackStatus}")
            if (report.clients.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Clientes Verificados (${report.clients.size}):",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurface,
                )
                report.clients.forEach { c ->
                    Text(
                        text = "• ${c.clientId} [${c.downstreamInterface}] (${c.mappingSource}) -> ${c.currentAddresses.joinToString(", ").ifBlank { "sem IP" }}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
            }
        }
    }
}

@Composable
private fun Phase2CapabilitiesCard(report: FirewallDiagnosticReport) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = "Fase 2 — Opção A: Leitura vs Escrita vs Bloqueio Seletivo",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            report.mechanismCapabilities.forEach { cap ->
                val color = statusColor(cap.status)
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = color.copy(alpha = 0.08f),
                    border = BorderStroke(1.dp, color.copy(alpha = 0.3f)),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = "${cap.mechanism} (${cap.family})",
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                            Text(
                                text = cap.status.name,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 10.sp,
                                color = color,
                            )
                        }
                        Text(
                            text = "canRead=${cap.canReadRules} • canWriteOwned=${cap.canWriteOwnedRules} • selectiveObserved=${cap.selectiveEnforcementObserved}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                        Text(
                            text = cap.detail,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun Phase3ConntrackCard(report: FirewallDiagnosticReport) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = "Fase 3 — Opção B: Conntrack & Atribuição Pós-NAT no TUN",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            MonoRow("Status Conntrack", report.conntrackReadStatus)
            MonoRow("Fluxos Parseados / Atribuídos", "parsed=${report.parsedFlows} • attributed=${report.attributedFlows} • unmatchedTotal=${report.unmatchedDelta}")
            Spacer(Modifier.height(4.dp))
            report.conntrackObservations.forEach { ct ->
                Text(
                    text = "• ${ct.path}: exists=${ct.existsObserved} status=${ct.openReadStatus} bytes=${ct.bytesRead} flows=${ct.relevantParsedFlows}" +
                        if (ct.rawError.isNotBlank()) " (${ct.rawError})" else "",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
            }
        }
    }
}

@Composable
private fun TemporaryTestResultCard(report: FirewallDiagnosticReport) {
    val t = report.temporaryRuleTest
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = "Resultado do Teste Temporário (${t.testId})",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            MonoRow("Cliente A (Alvo)", "${t.targetClientMac} -> ${t.targetAddresses.joinToString(", ")}")
            MonoRow("Cliente B (Controle)", t.controlClientMac.ifBlank { "Nenhum" })
            MonoRow("Chain Própria", "${t.ownedChainName} (${t.ruleInstallStatus})")
            MonoRow("Delta Contadores Opção A", "IPv4=${t.ruleCounterDeltaV4} pkts • IPv6=${t.ruleCounterDeltaV6} pkts")
            MonoRow("Cleanup Regras Próprias", t.cleanupStatus)
            MonoRow("Opção B (Cache Vazio)", "blockedDropsDelta=${t.optionBPolicyBlockedDropsDelta} • unmatchedDelta=${t.optionBUnmatchedDelta} • firstPacketLeak=${t.optionBFirstPacketLeakObserved}")
            MonoRow("Conectividade Cliente A", t.clientAConnectivity)
            MonoRow("Conectividade Cliente B", t.clientBConnectivity)
        }
    }
}

@Composable
private fun FactsAndHypothesesCard(report: FirewallDiagnosticReport) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = "Fatos Confirmados vs Hipóteses",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            report.factsConfirmed.forEach { fact ->
                Text(
                    text = "✓ $fact",
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurface,
                )
            }
            if (report.hypothesesToVerify.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                report.hypothesesToVerify.forEach { hyp ->
                    Text(
                        text = "• $hyp",
                        fontSize = 11.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                }
            }
        }
    }
}

@Composable
private fun Phase4ValidationMatrixCard(report: FirewallDiagnosticReport) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surface),
        border = BorderStroke(1.dp, ShizziTheme.colors.border),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = "Fase 4 — Matriz de Validação Física (12 Cenários)",
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            report.validationMatrix.forEach { row ->
                HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Text(
                        text = "${row.id}. ${row.scenario}",
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 11.sp,
                        color = ShizziTheme.colors.onSurface,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        text = row.status,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        color = ShizziTheme.colors.primary,
                    )
                }
                Text(
                    text = row.observedEvidence,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
            }
        }
    }
}

@Composable
private fun MonoRow(label: String, value: String) {
    Column(modifier = Modifier.padding(vertical = 2.dp)) {
        Text(
            text = label,
            fontSize = 10.sp,
            color = ShizziTheme.colors.onSurfaceMuted,
        )
        Text(
            text = value,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            color = ShizziTheme.colors.onSurface,
        )
    }
}

private fun statusColor(status: FirewallDiagnosticStatus): Color = when (status) {
    FirewallDiagnosticStatus.SELECTIVE_BLOCK_OBSERVED,
    FirewallDiagnosticStatus.WRITE_CONFIRMED,
    -> Color(0xFF4CAF50)
    FirewallDiagnosticStatus.PARTIAL_COVERAGE,
    FirewallDiagnosticStatus.READ_ONLY,
    -> Color(0xFFFFA000)
    FirewallDiagnosticStatus.PERMISSION_DENIED,
    FirewallDiagnosticStatus.ENFORCEMENT_UNAVAILABLE,
    FirewallDiagnosticStatus.UNSUPPORTED,
    -> Color(0xFFE57373)
    FirewallDiagnosticStatus.NOT_TESTED -> Color(0xFF90A4AE)
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
    cm.setPrimaryClip(ClipData.newPlainText(label, text))
}

private fun shareTextReport(context: Context, markdown: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_SUBJECT, "ShizziLuna Firewall Capability Report")
        putExtra(Intent.EXTRA_TEXT, markdown)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching {
        context.startActivity(Intent.createChooser(intent, "Exportar Relatório de Diagnóstico"))
    }
}
