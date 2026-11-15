package dev.shizzi.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.shizzi.BpfAttributionStatusReport
import dev.shizzi.ClientRule
import dev.shizzi.ConnectedClient
import dev.shizzi.DomainFilterCapabilityStatus
import dev.shizzi.DomainMatchMode
import dev.shizzi.DomainNormalizer
import dev.shizzi.DomainRule
import dev.shizzi.DomainRuleScope
import dev.shizzi.DomainValidationResult
import dev.shizzi.ui.theme.ScreenPadding
import dev.shizzi.ui.theme.ShizziTheme

data class DomainBlockingActions(
    val onUpsertRule: (
        existingRuleId: String?,
        rawDomain: String,
        scope: DomainRuleScope,
        clientMac: String?,
        matchMode: DomainMatchMode,
        enabled: Boolean,
    ) -> DomainValidationResult = { _, raw, _, _, _, _ -> DomainNormalizer.validateAndNormalize(raw) },
    val onToggleRuleEnabled: (ruleId: String, enabled: Boolean) -> Unit = { _, _ -> },
    val onRemoveRule: (ruleId: String) -> Unit = {},
    val onClearGlobalRules: () -> Unit = {},
    val onClearClientRules: (clientMac: String) -> Unit = {},
    val onSetExperimentalBpfEnabled: (Boolean) -> Unit = {},
    val onSetDnsAttributionRetryEnabled: (Boolean) -> Unit = {},
)

private data class SelectableClientTarget(
    val mac: String,
    val label: String,
    val isOnline: Boolean,
)

@Composable
fun DomainBlockingPage(
    domainRules: List<DomainRule>,
    connectedClients: List<ConnectedClient> = emptyList(),
    savedClientRules: List<ClientRule> = emptyList(),
    bpfReport: BpfAttributionStatusReport? = null,
    experimentalBpfEnabled: Boolean = bpfReport?.experimentalEnabled ?: true,
    dnsAttributionRetryEnabled: Boolean = bpfReport?.domainDiagnostics?.dnsAttributionRetryEnabled ?: false,
    initialScope: DomainRuleScope = DomainRuleScope.GLOBAL,
    initialClientMac: String? = null,
    actions: DomainBlockingActions = DomainBlockingActions(),
    onBack: () -> Unit = {},
) {
    var selectedScope by remember(initialScope, initialClientMac) {
        mutableStateOf(
            if (!initialClientMac.isNullOrBlank()) DomainRuleScope.CLIENT else initialScope,
        )
    }

    val selectableClients = remember(connectedClients, savedClientRules, domainRules) {
        val map = linkedMapOf<String, SelectableClientTarget>()
        val rulesByMac = savedClientRules.associateBy { it.cleanMac }
        connectedClients.forEach { client ->
            val mac = client.cleanMac
            if (mac.isNotBlank() && mac != "00:00:00:00:00:00") {
                val alias = client.alias.ifBlank {
                    rulesByMac[mac]?.alias?.ifBlank { null }
                        ?: client.displayName.ifBlank { mac }
                }
                map[mac] = SelectableClientTarget(
                    mac = mac,
                    label = if (alias != mac) "$alias ($mac)" else mac,
                    isOnline = true,
                )
            }
        }
        savedClientRules.forEach { rule ->
            val mac = rule.cleanMac
            if (mac.isNotBlank() && mac != "00:00:00:00:00:00" && !map.containsKey(mac)) {
                val alias = rule.alias.ifBlank { mac }
                map[mac] = SelectableClientTarget(
                    mac = mac,
                    label = if (alias != mac) "$alias ($mac)" else mac,
                    isOnline = false,
                )
            }
        }
        domainRules.forEach { rule ->
            val mac = rule.clientMac?.uppercase()
            if (rule.scope == DomainRuleScope.CLIENT && !mac.isNullOrBlank() && !map.containsKey(mac)) {
                map[mac] = SelectableClientTarget(
                    mac = mac,
                    label = mac,
                    isOnline = false,
                )
            }
        }
        map.values.toList()
    }

    var selectedClientMac by remember(initialClientMac, selectableClients) {
        mutableStateOf(
            initialClientMac?.uppercase()?.takeIf { it.isNotBlank() }
                ?: selectableClients.firstOrNull()?.mac,
        )
    }

    LaunchedEffect(initialClientMac) {
        if (!initialClientMac.isNullOrBlank()) {
            selectedScope = DomainRuleScope.CLIENT
            selectedClientMac = initialClientMac.uppercase()
        }
    }

    var editingRule by remember { mutableStateOf<DomainRule?>(null) }
    var showRuleDialog by remember { mutableStateOf(false) }
    var showClearGlobalConfirm by remember { mutableStateOf(false) }
    var showClearClientConfirm by remember { mutableStateOf(false) }

    val globalRules = remember(domainRules) {
        domainRules.filter { it.scope == DomainRuleScope.GLOBAL }
            .sortedBy { it.normalizedDomain }
    }
    val clientRules = remember(domainRules, selectedClientMac) {
        val target = selectedClientMac?.uppercase()
        if (target.isNullOrBlank()) {
            emptyList()
        } else {
            domainRules.filter {
                it.scope == DomainRuleScope.CLIENT && it.clientMac?.uppercase() == target
            }.sortedBy { it.normalizedDomain }
        }
    }

    val domainDiag = bpfReport?.domainDiagnostics
    val capStatus = domainDiag?.capabilityStatus
        ?: DomainFilterCapabilityStatus.DNS_FILTER_ACTIVE.name

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(ShizziTheme.colors.background)
            .systemBarsPadding()
            .testTag("domain_blocking_page"),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = ShizziTheme.spacing.sm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ScreenHeader(title = "Domain Blocking", onBack = onBack)
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .testTag("domain_lazy_column"),
            contentPadding = PaddingValues(horizontal = ScreenPadding, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(ShizziTheme.colors.surfaceVariant)
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                ) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = null,
                        tint = ShizziTheme.colors.primary,
                        modifier = Modifier.size(18.dp),
                    )
                    Text(
                        text = "Global rules work best with standard DNS. Per-host rules may be limited by traffic attribution.",
                        fontSize = 11.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                        modifier = Modifier.testTag("domain_info_note"),
                    )
                }
            }

            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = selectedScope == DomainRuleScope.GLOBAL,
                        onClick = { selectedScope = DomainRuleScope.GLOBAL },
                        label = {
                            Text("Global Rules (${globalRules.size})")
                        },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Public,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                        },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = ShizziTheme.colors.primary.copy(alpha = 0.2f),
                            selectedLabelColor = ShizziTheme.colors.primary,
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("domain_tab_global"),
                    )
                    FilterChip(
                        selected = selectedScope == DomainRuleScope.CLIENT,
                        onClick = { selectedScope = DomainRuleScope.CLIENT },
                        label = {
                            val totalPerHost = domainRules.count { it.scope == DomainRuleScope.CLIENT }
                            Text("Per Host ($totalPerHost)")
                        },
                        leadingIcon = {
                            Icon(
                                imageVector = Icons.Default.Computer,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                            )
                        },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = ShizziTheme.colors.primary.copy(alpha = 0.2f),
                            selectedLabelColor = ShizziTheme.colors.primary,
                        ),
                        modifier = Modifier
                            .weight(1f)
                            .testTag("domain_tab_client"),
                    )
                }
            }

            if (selectedScope == DomainRuleScope.GLOBAL) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surfaceVariant),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Text(
                                text = "Global Domain Rules",
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 13.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                            Text(
                                text = "Blocks matching domains for all connected hotspot devices.",
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Button(
                                    onClick = {
                                        editingRule = null
                                        showRuleDialog = true
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = ShizziTheme.colors.primary,
                                        contentColor = ShizziTheme.colors.onPrimary,
                                    ),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("domain_add_global_button"),
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Add,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp),
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text("Add Global Domain")
                                }
                                if (globalRules.isNotEmpty()) {
                                    OutlinedButton(
                                        onClick = { showClearGlobalConfirm = true },
                                        modifier = Modifier.testTag("domain_clear_global_button"),
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.DeleteSweep,
                                            contentDescription = "Clear Global Rules",
                                            modifier = Modifier.size(18.dp),
                                        )
                                        Spacer(Modifier.width(4.dp))
                                        Text("Clear")
                                    }
                                }
                            }
                        }
                    }
                }

                if (globalRules.isEmpty()) {
                    item {
                        EmptyDomainRulesCard(
                            title = "No global domain rules configured",
                            subtitle = "Tap \"Add Global Domain\" to block domains (e.g., tiktok.com, doubleclick.net) for every hotspot device.",
                        )
                    }
                } else {
                    items(globalRules, key = { it.id }) { rule ->
                        DomainRuleItemCard(
                            rule = rule,
                            onToggleEnabled = { enabled ->
                                actions.onToggleRuleEnabled(rule.id, enabled)
                            },
                            onEdit = {
                                editingRule = rule
                                showRuleDialog = true
                            },
                            onDelete = {
                                actions.onRemoveRule(rule.id)
                            },
                        )
                    }
                }
            } else {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surfaceVariant),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(8.dp))
                                    .background(ShizziTheme.colors.primary.copy(alpha = 0.12f))
                                    .padding(horizontal = 10.dp, vertical = 8.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Info,
                                    contentDescription = null,
                                    tint = ShizziTheme.colors.primary,
                                    modifier = Modifier.size(18.dp),
                                )
                                Text(
                                    text = "Global rules also apply (${globalRules.count { it.enabled }} active). Whole-device blocks take priority over domain rules.",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = ShizziTheme.colors.onSurface,
                                    modifier = Modifier.testTag("domain_global_also_applies_notice"),
                                )
                            }

                            if (!experimentalBpfEnabled) {
                                Card(
                                    colors = CardDefaults.cardColors(
                                        containerColor = Color(0xFFFFB300).copy(alpha = 0.14f),
                                    ),
                                    shape = RoundedCornerShape(10.dp),
                                    border = BorderStroke(1.dp, Color(0xFFFFB300).copy(alpha = 0.45f)),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .testTag("domain_bpf_disabled_warning_card"),
                                ) {
                                    Column(
                                        modifier = Modifier.padding(10.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp),
                                    ) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                                        ) {
                                            Icon(
                                                imageVector = Icons.Default.Warning,
                                                contentDescription = null,
                                                tint = Color(0xFFFFB300),
                                                modifier = Modifier.size(18.dp),
                                            )
                                            Text(
                                                text = "Per-host attribution is turned off",
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 11.sp,
                                                color = Color(0xFFFFB300),
                                            )
                                        }
                                        Text(
                                            text = "Enable Experimental BPF NAT Attribution so per-host domain rules can identify devices on hotspot connections.",
                                            fontSize = 10.sp,
                                            color = ShizziTheme.colors.onSurface,
                                        )
                                        Button(
                                            onClick = { actions.onSetExperimentalBpfEnabled(true) },
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = ShizziTheme.colors.primary,
                                                contentColor = ShizziTheme.colors.onPrimary,
                                            ),
                                            modifier = Modifier.testTag("domain_enable_bpf_button"),
                                        ) {
                                            Text("Enable BPF Attribution", fontSize = 11.sp)
                                        }
                                    }
                                }
                            }

                            Text(
                                text = "Select Host:",
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )

                            if (selectableClients.isEmpty()) {
                                Text(
                                    text = "No connected or saved hotspot devices yet. Connect a device or add a host rule from Connected Devices.",
                                    fontSize = 11.sp,
                                    color = ShizziTheme.colors.onSurfaceMuted,
                                    modifier = Modifier.testTag("domain_no_clients_message"),
                                )
                            } else {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .horizontalScroll(rememberScrollState()),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    selectableClients.forEach { target ->
                                        val isSelected = selectedClientMac?.uppercase() == target.mac
                                        FilterChip(
                                            selected = isSelected,
                                            onClick = { selectedClientMac = target.mac },
                                            label = {
                                                Text(
                                                    text = target.label,
                                                    maxLines = 1,
                                                    overflow = TextOverflow.Ellipsis,
                                                )
                                            },
                                            leadingIcon = {
                                                Box(
                                                    modifier = Modifier
                                                        .size(8.dp)
                                                        .clip(CircleShape)
                                                        .background(
                                                            if (target.isOnline) Color(0xFF4CAF50) else ShizziTheme.colors.onSurfaceMuted,
                                                        ),
                                                )
                                            },
                                            modifier = Modifier.testTag("domain_client_chip_${target.mac}"),
                                        )
                                    }
                                }
                            }

                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                Button(
                                    onClick = {
                                        editingRule = null
                                        showRuleDialog = true
                                    },
                                    enabled = !selectedClientMac.isNullOrBlank(),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = ShizziTheme.colors.primary,
                                        contentColor = ShizziTheme.colors.onPrimary,
                                    ),
                                    modifier = Modifier
                                        .weight(1f)
                                        .testTag("domain_add_client_button"),
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Add,
                                        contentDescription = null,
                                        modifier = Modifier.size(18.dp),
                                    )
                                    Spacer(Modifier.width(6.dp))
                                    Text("Add Host Rule")
                                }
                                if (clientRules.isNotEmpty() && !selectedClientMac.isNullOrBlank()) {
                                    OutlinedButton(
                                        onClick = { showClearClientConfirm = true },
                                        modifier = Modifier.testTag("domain_clear_client_button"),
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.DeleteSweep,
                                            contentDescription = "Clear Host Rules",
                                            modifier = Modifier.size(18.dp),
                                        )
                                        Spacer(Modifier.width(4.dp))
                                        Text("Clear")
                                    }
                                }
                            }
                        }
                    }
                }

                if (selectedClientMac.isNullOrBlank()) {
                    item {
                        EmptyDomainRulesCard(
                            title = "No host selected",
                            subtitle = "Select a hotspot client above to manage its per-host domain rules.",
                        )
                    }
                } else if (clientRules.isEmpty()) {
                    item {
                        EmptyDomainRulesCard(
                            title = "No per-host domain rules for $selectedClientMac",
                            subtitle = "Tap \"Add Host Domain\" to block domains specifically for this client. Global rules still apply.",
                        )
                    }
                } else {
                    items(clientRules, key = { it.id }) { rule ->
                        DomainRuleItemCard(
                            rule = rule,
                            onToggleEnabled = { enabled ->
                                actions.onToggleRuleEnabled(rule.id, enabled)
                            },
                            onEdit = {
                                editingRule = rule
                                showRuleDialog = true
                            },
                            onDelete = {
                                actions.onRemoveRule(rule.id)
                            },
                        )
                    }
                }
            }
        }
    }

    if (showRuleDialog) {
        val ruleToEdit = editingRule
        val dialogScope = ruleToEdit?.scope ?: selectedScope
        val dialogClientMac = if (dialogScope == DomainRuleScope.CLIENT) {
            ruleToEdit?.clientMac ?: selectedClientMac
        } else {
            null
        }
        DomainRuleEditDialog(
            initialRule = ruleToEdit,
            scope = dialogScope,
            clientMac = dialogClientMac,
            onDismiss = {
                showRuleDialog = false
                editingRule = null
            },
            onSave = { rawDomain, matchMode, enabled ->
                val result = actions.onUpsertRule(
                    ruleToEdit?.id,
                    rawDomain,
                    dialogScope,
                    dialogClientMac,
                    matchMode,
                    enabled,
                )
                if (result.isValid) {
                    showRuleDialog = false
                    editingRule = null
                }
                result
            },
        )
    }

    if (showClearGlobalConfirm) {
        AlertDialog(
            onDismissRequest = { showClearGlobalConfirm = false },
            title = { Text("Clear Global Domain Rules?") },
            text = {
                Text("Remove all ${globalRules.size} global domain rules? Per-host rules will be preserved.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        actions.onClearGlobalRules()
                        showClearGlobalConfirm = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935)),
                    modifier = Modifier.testTag("domain_confirm_clear_global_button"),
                ) {
                    Text("Clear All Global")
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearGlobalConfirm = false }) {
                    Text("Cancel")
                }
            },
        )
    }

    if (showClearClientConfirm && !selectedClientMac.isNullOrBlank()) {
        val targetMac = selectedClientMac!!
        AlertDialog(
            onDismissRequest = { showClearClientConfirm = false },
            title = { Text("Clear Host Domain Rules?") },
            text = {
                Text("Remove all ${clientRules.size} domain rules for $targetMac? Global domain rules will remain active.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        actions.onClearClientRules(targetMac)
                        showClearClientConfirm = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFE53935)),
                    modifier = Modifier.testTag("domain_confirm_clear_client_button"),
                ) {
                    Text("Clear Host Rules")
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearClientConfirm = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@Composable
private fun DomainCapabilityBanner(
    capabilityStatus: String,
    globalEnabledCount: Int,
    clientEnabledCount: Int,
    dnsInspected: Long,
    dnsBlockedGlobal: Long,
    dnsBlockedClient: Long,
    sniHostBlocked: Long,
    unknownOwnerSkips: Long,
    dnsDirectIp: Long = 0L,
    dnsBpfNat: Long = 0L,
    dnsUnknownOwner: Long = 0L,
    clientRuleMatched: Long = 0L,
    clientRuleOwnerMismatch: Long = 0L,
    dnsRetryQueued: Long = 0L,
    dnsRetryResolved: Long = 0L,
    dnsRetryTimeout: Long = 0L,
) {
    val isPartialOrUnavailable = capabilityStatus == DomainFilterCapabilityStatus.PARTIAL_DOMAIN_ENFORCEMENT.name ||
        capabilityStatus == DomainFilterCapabilityStatus.DNS_FILTER_UNAVAILABLE.name
    val statusColor = if (isPartialOrUnavailable) Color(0xFFFFB300) else Color(0xFF4CAF50)

    Card(
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surfaceVariant),
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, statusColor.copy(alpha = 0.35f)),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("domain_capability_banner"),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    imageVector = if (isPartialOrUnavailable) Icons.Default.Warning else Icons.Default.Shield,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = "Status: $capabilityStatus",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = ShizziTheme.colors.onSurface,
                    modifier = Modifier.testTag("domain_capability_status_text"),
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "Active Rules: $globalEnabledCount Global • $clientEnabledCount Per-Host",
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Text(
                    text = "DNS Inspected: $dnsInspected",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "DNS Blocked: ${dnsBlockedGlobal + dnsBlockedClient} (G:$dnsBlockedGlobal / C:$dnsBlockedClient)",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = ShizziTheme.colors.onSurface,
                )
                Text(
                    text = "SNI/Host Drops: $sniHostBlocked",
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = ShizziTheme.colors.onSurface,
                )
            }

            Text(
                text = "DNS Owner: Direct=$dnsDirectIp • BPF=$dnsBpfNat • Unk=$dnsUnknownOwner | HostMatch=$clientRuleMatched • Mismatch=$clientRuleOwnerMismatch",
                fontSize = 10.sp,
                fontFamily = FontFamily.Monospace,
                color = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.testTag("domain_dns_attribution_breakdown_text"),
            )

            if (dnsRetryQueued > 0L || dnsRetryResolved > 0L || dnsRetryTimeout > 0L) {
                Text(
                    text = "DNS Retry Queue: queued=$dnsRetryQueued • resolved=$dnsRetryResolved • timeout=$dnsRetryTimeout",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = ShizziTheme.colors.primary,
                    modifier = Modifier.testTag("domain_dns_retry_stats_text"),
                )
            }

            if (unknownOwnerSkips > 0L) {
                Text(
                    text = "Unknown-owner per-host skips (DOMAIN_CLIENT_OWNER_UNKNOWN): $unknownOwnerSkips",
                    fontSize = 10.sp,
                    fontFamily = FontFamily.Monospace,
                    color = Color(0xFFFFB300),
                )
            }

            HorizontalDivider(color = ShizziTheme.colors.border.copy(alpha = 0.5f))

            Text(
                text = "Note: Enforces plaintext DNS (UDP/TCP 53 RCODE=REFUSED) and initial TLS SNI / HTTP Host on TUN traffic. Encrypted DNS (DoH/DoT/QUIC), pre-cached IPs without SNI, or unattributed packets (for Per-Host rules) cannot be matched by domain.",
                fontSize = 10.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
                lineHeight = 14.sp,
            )
        }
    }
}

@Composable
private fun EmptyDomainRulesCard(
    title: String,
    subtitle: String,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surfaceVariant),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("domain_empty_state_card"),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = Icons.Default.Dns,
                contentDescription = null,
                tint = ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.size(32.dp),
            )
            Text(
                text = title,
                fontWeight = FontWeight.SemiBold,
                fontSize = 13.sp,
                color = ShizziTheme.colors.onSurface,
            )
            Text(
                text = subtitle,
                fontSize = 11.sp,
                color = ShizziTheme.colors.onSurfaceMuted,
            )
        }
    }
}

@Composable
private fun DomainRuleItemCard(
    rule: DomainRule,
    onToggleEnabled: (Boolean) -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = ShizziTheme.colors.surfaceVariant),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("domain_rule_card_${rule.normalizedDomain}"),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(
                imageVector = if (rule.enabled) Icons.Default.Block else Icons.Default.CheckCircle,
                contentDescription = null,
                tint = if (rule.enabled) Color(0xFFE53935) else ShizziTheme.colors.onSurfaceMuted,
                modifier = Modifier.size(20.dp),
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = rule.normalizedDomain,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = if (rule.enabled) ShizziTheme.colors.onSurface else ShizziTheme.colors.onSurfaceMuted,
                )
                val modeBadge = when (rule.matchMode) {
                    DomainMatchMode.INCLUDE_SUBDOMAINS -> "Root + Subdomains (*.${rule.normalizedDomain})"
                    DomainMatchMode.EXACT_HOSTNAME -> "Exact Hostname Only"
                }
                Text(
                    text = modeBadge,
                    fontSize = 10.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
            }
            Switch(
                checked = rule.enabled,
                onCheckedChange = onToggleEnabled,
                modifier = Modifier.testTag("domain_rule_switch_${rule.normalizedDomain}"),
            )
            IconButton(
                onClick = onEdit,
                modifier = Modifier
                    .size(36.dp)
                    .testTag("domain_rule_edit_${rule.normalizedDomain}"),
            ) {
                Icon(
                    imageVector = Icons.Default.Edit,
                    contentDescription = "Edit domain rule",
                    tint = ShizziTheme.colors.onSurfaceMuted,
                    modifier = Modifier.size(18.dp),
                )
            }
            IconButton(
                onClick = onDelete,
                modifier = Modifier
                    .size(36.dp)
                    .testTag("domain_rule_delete_${rule.normalizedDomain}"),
            ) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = "Delete domain rule",
                    tint = Color(0xFFE53935),
                    modifier = Modifier.size(18.dp),
                )
            }
        }
    }
}

@Composable
private fun DomainRuleEditDialog(
    initialRule: DomainRule?,
    scope: DomainRuleScope,
    clientMac: String?,
    onDismiss: () -> Unit,
    onSave: (rawDomain: String, matchMode: DomainMatchMode, enabled: Boolean) -> DomainValidationResult,
) {
    var rawDomainInput by remember(initialRule) {
        mutableStateOf(initialRule?.normalizedDomain ?: "")
    }
    var selectedMatchMode by remember(initialRule) {
        mutableStateOf(initialRule?.matchMode ?: DomainMatchMode.INCLUDE_SUBDOMAINS)
    }
    var validationError by remember(initialRule) {
        mutableStateOf<String?>(null)
    }

    val titleText = if (initialRule == null) {
        if (scope == DomainRuleScope.GLOBAL) "Add Global Domain Rule" else "Add Host Domain Rule"
    } else {
        "Edit Domain Rule"
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("domain_rule_dialog"),
        title = {
            Text(text = titleText, fontWeight = FontWeight.Bold)
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (scope == DomainRuleScope.CLIENT && !clientMac.isNullOrBlank()) {
                    Text(
                        text = "Target Client MAC: $clientMac",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                    )
                } else {
                    Text(
                        text = "Scope: All Hotspot Clients (GLOBAL)",
                        fontSize = 11.sp,
                    )
                }

                OutlinedTextField(
                    value = rawDomainInput,
                    onValueChange = {
                        rawDomainInput = it
                        validationError = null
                    },
                    label = { Text("Domain or *.domain (e.g. example.com)") },
                    singleLine = true,
                    isError = validationError != null,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("domain_input_field"),
                )

                if (validationError != null) {
                    Text(
                        text = validationError!!,
                        color = Color(0xFFE53935),
                        fontSize = 11.sp,
                        modifier = Modifier.testTag("domain_input_error"),
                    )
                }

                Text(
                    text = "Match Mode:",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS }
                        .testTag("domain_match_mode_subdomains"),
                ) {
                    RadioButton(
                        selected = selectedMatchMode == DomainMatchMode.INCLUDE_SUBDOMAINS,
                        onClick = { selectedMatchMode = DomainMatchMode.INCLUDE_SUBDOMAINS },
                    )
                    Column {
                        Text(
                            text = DomainMatchMode.INCLUDE_SUBDOMAINS.displayName,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = "Matches root domain and all subdomains (default)",
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedMatchMode = DomainMatchMode.EXACT_HOSTNAME }
                        .testTag("domain_match_mode_exact"),
                ) {
                    RadioButton(
                        selected = selectedMatchMode == DomainMatchMode.EXACT_HOSTNAME,
                        onClick = { selectedMatchMode = DomainMatchMode.EXACT_HOSTNAME },
                    )
                    Column {
                        Text(
                            text = DomainMatchMode.EXACT_HOSTNAME.displayName,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                        )
                        Text(
                            text = "Matches only the exact hostname entered",
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val res = onSave(
                        rawDomainInput,
                        selectedMatchMode,
                        initialRule?.enabled ?: true,
                    )
                    if (!res.isValid) {
                        validationError = res.errorMessage ?: "Invalid domain name."
                    }
                },
                modifier = Modifier.testTag("domain_dialog_save_button"),
            ) {
                Text("Save Rule")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("domain_dialog_cancel_button"),
            ) {
                Text("Cancel")
            }
        },
    )
}
