package dev.shizzi.ui

import androidx.compose.animation.AnimatedVisibility
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Laptop
import androidx.compose.material.icons.outlined.PhoneAndroid
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.shizzi.ClientRule
import dev.shizzi.ConnectedClient
import dev.shizzi.DatapathMode
import dev.shizzi.EnforcementState
import dev.shizzi.SessionUiState
import dev.shizzi.Traffic
import dev.shizzi.UiStatus
import dev.shizzi.ui.theme.ScreenPadding
import dev.shizzi.ui.theme.ShizziTheme
import java.math.BigDecimal
import java.util.Locale

private val STRICT_DECIMAL_REGEX = Regex("""^\d+(\.\d+)?$""")
private val THOUSAND_BD = BigDecimal.valueOf(1000L)
private val MAX_KBPS_BD = BigDecimal.valueOf(Int.MAX_VALUE.toLong())

data class BandwidthParseResult(
    val kbps: Int?,
    val errorMessage: String? = null,
) {
    val isValid: Boolean get() = kbps != null && errorMessage == null
}

/**
 * Formats a persisted [kbps] value (`ClientRule.bandwidthLimitKbps`) as an exact decimal Mbps string
 * without binary floating-point rounding (`512` -> `"0.512"`, `1000` -> `"1"`, `1500` -> `"1.5"`, `0` -> `"0"`).
 */
fun formatKbpsAsMbps(kbps: Int): String {
    if (kbps <= 0) return "0"
    return BigDecimal.valueOf(kbps.toLong())
        .divide(THOUSAND_BD)
        .stripTrailingZeros()
        .toPlainString()
}

/**
 * Strictly validates and converts a user-entered Mbps string to integer Kbps (`kbps = Mbps * 1000`).
 * Rejects blank input, negative numbers, non-numeric text, fractional precision finer than 1 Kbps (`0.001 Mbps`),
 * and values exceeding [Int.MAX_VALUE] Kbps.
 */
fun validateMbpsInput(rawInput: String): BandwidthParseResult {
    val trimmed = rawInput.trim()
    if (trimmed.isEmpty()) {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Enter a bandwidth limit in Mbps (0 = Unlimited).",
        )
    }
    val normalized = trimmed.replace(',', '.')
    if (normalized.startsWith("-")) {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Bandwidth limit cannot be negative.",
        )
    }
    if (!STRICT_DECIMAL_REGEX.matches(normalized)) {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Enter a valid non-negative number in Mbps (e.g. 0, 0.5, 1.5, 10).",
        )
    }
    val mbps = runCatching { BigDecimal(normalized) }.getOrElse {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Invalid number format.",
        )
    }
    val kbpsDecimal = mbps.multiply(THOUSAND_BD)
    val stripped = kbpsDecimal.stripTrailingZeros()
    if (stripped.scale() > 0) {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Maximum precision is 0.001 Mbps (1 Kbps).",
        )
    }
    if (stripped > MAX_KBPS_BD) {
        return BandwidthParseResult(
            kbps = null,
            errorMessage = "Bandwidth limit is too large (max 2147483.647 Mbps).",
        )
    }
    return runCatching {
        BandwidthParseResult(kbps = stripped.intValueExact(), errorMessage = null)
    }.getOrElse {
        BandwidthParseResult(
            kbps = null,
            errorMessage = "Bandwidth limit is out of supported range.",
        )
    }
}

/**
 * Convenience parser returning the exact Kbps `Int` or `null` if [rawInput] is invalid.
 */
fun parseMbpsToKbps(rawInput: String): Int? = validateMbpsInput(rawInput).kbps

/**
 * Formats an integer hour (`0..23`) as 24-hour `HH:00` with leading zero.
 */
fun formatScheduleHour(hour: Int): String =
    String.format(Locale.US, "%02d:00", hour.coerceIn(0, 23))

/**
 * Validates schedule hours. When [scheduleEnabled] is true, `startHour == endHour` is rejected
 * because an identical start and end hour grants 0 hours of access.
 */
fun isValidScheduleHours(
    scheduleEnabled: Boolean,
    startHour: Int,
    endHour: Int,
): Boolean {
    if (startHour !in 0..23 || endHour !in 0..23) return false
    if (!scheduleEnabled) return true
    return startHour != endHour
}

fun formatScheduleExplanation(startHour: Int, endHour: Int): String =
    "Internet allowed from ${formatScheduleHour(startHour)} to ${formatScheduleHour(endHour)}. Outside this window, access is blocked."

internal fun formatClientBandwidthBadgeLabel(
    client: ConnectedClient,
    isCurrentlyConnected: Boolean,
): String {
    val cap = if (client.bandwidthLimitKbps <= 0) {
        "Unlimited"
    } else {
        "${formatKbpsAsMbps(client.bandwidthLimitKbps)} Mbps"
    }
    if (!isCurrentlyConnected) return "Cap: $cap (saved)"
    return when (client.enforcementState) {
        EnforcementState.THROTTLING_OBSERVED ->
            "Cap: $cap (shaped • ${Traffic.format(client.shapedBytes)})"
        EnforcementState.PARTIAL_BPF_ENFORCEMENT ->
            "Cap: $cap (partial BPF • ${Traffic.format(client.shapedBytes)} shaped)"
        EnforcementState.PACKETS_MATCHED ->
            "Cap: $cap (matched • ${client.matchedPackets} pkts)"
        EnforcementState.POLICY_INSTALLED,
        EnforcementState.DATAPATH_ACTIVE,
        -> "Cap: $cap (requested • policy active)"
        EnforcementState.DEGRADED_MULTI_CLIENT ->
            "Cap: $cap — degraded (post-NAT unattributed)"
        EnforcementState.ENFORCEMENT_UNAVAILABLE ->
            "Cap: $cap — not enforced"
        else -> "Cap: $cap (configured)"
    }
}

data class ClientActions(
    val onToggleBlock: (mac: String, shouldBlock: Boolean) -> Unit,
    val onSaveRule: (rule: ClientRule) -> Unit,
    val onRemoveRule: (mac: String) -> Unit,
    val onRefresh: () -> Unit,
    val onOpenFirewallDiagnostic: () -> Unit = {},
    val onSetExperimentalBpfEnabled: (Boolean) -> Unit = {},
    val onCollectBpfSnapshotNow: () -> Unit = {},
)

@Composable
fun ClientsPage(
    clients: List<ConnectedClient>,
    actions: ClientActions,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    savedRules: List<ClientRule> = emptyList(),
    sessionState: SessionUiState = SessionUiState(),
    experimentalBpfEnabled: Boolean = false,
    bpfPollIntervalMs: Int = 1000,
) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedClientForEdit by remember { mutableStateOf<ConnectedClient?>(null) }
    var showAddDialog by remember { mutableStateOf(false) }

    val connectedMacSet = remember(clients) {
        clients.map { it.cleanMac }.toSet()
    }

    val offlineRules = remember(savedRules, connectedMacSet) {
        savedRules.filter { it.cleanMac !in connectedMacSet }
    }

    val filteredClients = remember(clients, searchQuery) {
        if (searchQuery.isBlank()) clients
        else {
            val q = searchQuery.trim().lowercase()
            clients.filter {
                it.mac.lowercase().contains(q) ||
                    it.ip.lowercase().contains(q) ||
                    it.displayName.lowercase().contains(q)
            }
        }
    }

    val filteredOfflineRules = remember(offlineRules, searchQuery) {
        if (searchQuery.isBlank()) offlineRules
        else {
            val q = searchQuery.trim().lowercase()
            offlineRules.filter {
                it.mac.lowercase().contains(q) ||
                    it.displayName.lowercase().contains(q)
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .systemBarsPadding(),
    ) {
        // Top Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = ShizziTheme.spacing.sm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            ScreenHeader(title = "Connected Devices", onBack = onBack)
        }

        Column(modifier = Modifier.padding(horizontal = ScreenPadding)) {
            // Stats & Quick Add Row
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                val blockedCount = clients.count { it.isRestricted().first }
                val limitedCount = clients.count { it.bandwidthLimitKbps > 0 }

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = if (clients.size == 1) "1 Connected Device" else "${clients.size} Connected Devices",
                        style = ShizziTheme.typography.body,
                        fontWeight = FontWeight.Bold,
                        color = ShizziTheme.colors.onSurface,
                        modifier = Modifier.testTag("connected_devices_count_text"),
                    )
                    val offlineSuffix = if (offlineRules.isNotEmpty()) {
                        " • ${offlineRules.size} saved offline"
                    } else {
                        ""
                    }
                    Text(
                        text = "$blockedCount blocked • $limitedCount bandwidth limited$offlineSuffix",
                        style = ShizziTheme.typography.caption,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                    if (sessionState.status == UiStatus.CONNECTED) {
                        Text(
                            text = "Datapath: ${sessionState.datapathMode.name} • Backend: ${sessionState.firewallBackend.name}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    IconButton(
                        onClick = actions.onRefresh,
                        modifier = Modifier.testTag("refresh_clients_button"),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Refresh,
                            contentDescription = "Refresh Clients",
                            tint = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }

                    Button(
                        onClick = { showAddDialog = true },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ShizziTheme.colors.primary,
                            contentColor = ShizziTheme.colors.onPrimary,
                        ),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.testTag("add_client_rule_button"),
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Add MAC")
                    }
                }
            }

            // Prominent warning banner if Direct-TUN fallback is active without kernel netfilter
            if (sessionState.status == UiStatus.CONNECTED &&
                sessionState.datapathMode == DatapathMode.DIRECT_TUN_FALLBACK &&
                !sessionState.kernelNetfilterAvailable
            ) {
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFFFA000).copy(alpha = 0.16f),
                    ),
                    border = BorderStroke(1.dp, Color(0xFFFFA000).copy(alpha = 0.45f)),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                        .testTag("enforcement_unavailable_banner"),
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = null,
                            tint = Color(0xFFFFA000),
                            modifier = Modifier.size(20.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Enforcement Unavailable (Direct-TUN Fallback)",
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp,
                                color = ShizziTheme.colors.onSurface,
                            )
                            Text(
                                text = "Userspace proxy did not attach (${sessionState.fallbackReason.ifBlank { "fallback active" }}) and kernel netfilter is unavailable. Rules are saved but cannot filter live packets.",
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )
                        }
                    }
                }
            }

            // Search Bar
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                placeholder = { Text("Search by MAC, IP, or Alias...") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Search,
                        contentDescription = null,
                        tint = ShizziTheme.colors.onSurfaceMuted,
                    )
                },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = ShizziTheme.colors.primary,
                    unfocusedBorderColor = ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.3f),
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                    .testTag("client_search_input"),
            )
        }

        if (filteredClients.isEmpty() && filteredOfflineRules.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Icon(
                        imageVector = Icons.Filled.Devices,
                        contentDescription = null,
                        tint = ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.6f),
                        modifier = Modifier.size(64.dp),
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        text = "No Connected Devices",
                        style = ShizziTheme.typography.body,
                        fontWeight = FontWeight.SemiBold,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Clients actively connected to your Wi-Fi hotspot will automatically appear here.",
                        style = ShizziTheme.typography.caption,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                    Spacer(Modifier.height(16.dp))
                    OutlinedButton(
                        onClick = { showAddDialog = true },
                        shape = RoundedCornerShape(10.dp),
                    ) {
                        Text("Pre-configure Rule by MAC")
                    }
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = ScreenPadding),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                if (filteredClients.isEmpty()) {
                    item(key = "no_active_clients_banner") {
                        Card(
                            shape = RoundedCornerShape(14.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = ShizziTheme.colors.surfaceVariant.copy(alpha = 0.6f),
                            ),
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Devices,
                                    contentDescription = null,
                                    tint = ShizziTheme.colors.onSurfaceMuted,
                                    modifier = Modifier.size(24.dp),
                                )
                                Spacer(Modifier.width(12.dp))
                                Column {
                                    Text(
                                        text = "0 Active Hotspot Connections",
                                        style = ShizziTheme.typography.body,
                                        fontWeight = FontWeight.SemiBold,
                                        color = ShizziTheme.colors.onSurface,
                                    )
                                    Text(
                                        text = "Saved rules below will automatically enforce as soon as those devices connect.",
                                        style = ShizziTheme.typography.caption,
                                        color = ShizziTheme.colors.onSurfaceMuted,
                                    )
                                }
                            }
                        }
                    }
                } else {
                    items(filteredClients, key = { "active_${it.cleanMac}" }) { client ->
                        ClientCard(
                            client = client,
                            isCurrentlyConnected = true,
                            onToggleBlock = { actions.onToggleBlock(client.mac, !client.isBlocked) },
                            onEdit = { selectedClientForEdit = client },
                            onDelete = { actions.onRemoveRule(client.mac) },
                        )
                    }
                }

                if (filteredOfflineRules.isNotEmpty()) {
                    item(key = "offline_rules_header") {
                        Column(modifier = Modifier.padding(top = 12.dp, bottom = 4.dp)) {
                            Text(
                                text = "Saved Rules (Offline — Not Connected)",
                                style = ShizziTheme.typography.caption,
                                fontWeight = FontWeight.Bold,
                                color = ShizziTheme.colors.onSurfaceMuted,
                            )
                        }
                    }

                    items(filteredOfflineRules, key = { "offline_${it.cleanMac}" }) { rule ->
                        val offlineClientView = ConnectedClient(
                            mac = rule.cleanMac,
                            ip = "Offline",
                            alias = rule.alias,
                            interfaceName = "saved rule",
                            isBlocked = rule.isBlocked,
                            bandwidthLimitKbps = rule.bandwidthLimitKbps,
                            connectionTimeLimitMinutes = rule.connectionTimeLimitMinutes,
                            scheduleEnabled = rule.scheduleEnabled,
                            scheduleStartHour = rule.scheduleStartHour,
                            scheduleEndHour = rule.scheduleEndHour,
                        )
                        ClientCard(
                            client = offlineClientView,
                            isCurrentlyConnected = false,
                            onToggleBlock = { actions.onToggleBlock(rule.cleanMac, !rule.isBlocked) },
                            onEdit = { selectedClientForEdit = offlineClientView },
                            onDelete = { actions.onRemoveRule(rule.cleanMac) },
                        )
                    }
                }

                item {
                    Spacer(Modifier.height(32.dp))
                }
            }
        }
    }

    // Edit Client Dialog
    selectedClientForEdit?.let { client ->
        ConfigureClientDialog(
            client = client,
            onDismiss = { selectedClientForEdit = null },
            onSave = { rule ->
                actions.onSaveRule(rule)
                selectedClientForEdit = null
            },
        )
    }

    // Add Client Dialog
    if (showAddDialog) {
        AddClientDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { rule ->
                actions.onSaveRule(rule)
                showAddDialog = false
            },
        )
    }
}

@Composable
private fun ClientCard(
    client: ConnectedClient,
    isCurrentlyConnected: Boolean,
    onToggleBlock: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    val (isRestricted, restrictReason) = client.isRestricted()
    val state = client.enforcementState

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = ShizziTheme.colors.surfaceVariant,
        ),
        modifier = Modifier
            .fillMaxWidth()
            .testTag("client_card_${client.cleanMac}"),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Header Row: Icon, Name/IP/MAC, and Quick Block Switch
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                val icon = if (client.displayName.contains("laptop", ignoreCase = true)) {
                    Icons.Outlined.Laptop
                } else {
                    Icons.Outlined.PhoneAndroid
                }

                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(CircleShape)
                        .background(
                            if (isRestricted) Color(0xFFFF5252).copy(alpha = 0.15f)
                            else ShizziTheme.colors.primary.copy(alpha = 0.15f),
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = if (isRestricted) Icons.Filled.Block else icon,
                        contentDescription = null,
                        tint = if (isRestricted) Color(0xFFFF5252) else ShizziTheme.colors.primary,
                        modifier = Modifier.size(22.dp),
                    )
                }

                Spacer(Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = client.displayName,
                        fontWeight = FontWeight.Bold,
                        style = ShizziTheme.typography.body,
                        color = ShizziTheme.colors.onSurface,
                    )
                    Text(
                        text = "${client.ip} • ${client.cleanMac}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = ShizziTheme.colors.onSurfaceMuted,
                    )
                    if (isCurrentlyConnected && client.seenPackets > 0L) {
                        val dropSummary = if (isRestricted) " • ${client.effectivePolicyVersionDrops} blockDrop" else ""
                        val shapeSummary = if (client.shapingDropPackets > 0L) " • ${client.shapingDropPackets} shapeDrop" else ""
                        Text(
                            text = "v${client.policyVersion} • seen=${client.seenPackets} (bpf=${client.bpfAttributedPackets}, direct=${client.directAttributedPackets})$dropSummary$shapeSummary",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 10.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }

                Switch(
                    checked = !client.isBlocked,
                    onCheckedChange = { onToggleBlock() },
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = ShizziTheme.colors.onPrimary,
                        checkedTrackColor = ShizziTheme.colors.primary,
                        uncheckedThumbColor = Color.White,
                        uncheckedTrackColor = Color(0xFFFF5252),
                    ),
                    modifier = Modifier.testTag("toggle_block_${client.cleanMac}"),
                )
            }

            Spacer(Modifier.height(10.dp))

            // Badges row
            @OptIn(ExperimentalLayoutApi::class)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                // Status badge (honest packet-verified vs partial BPF vs configured vs unavailable vs degraded)
                if (!isCurrentlyConnected) {
                    BadgeChip(
                        label = if (isRestricted) "Offline • ${restrictReason ?: "Blocked"} (saved)" else "Offline • Saved Rule",
                        color = if (isRestricted) Color(0xFFFF5252) else ShizziTheme.colors.onSurfaceMuted,
                        icon = if (isRestricted) Icons.Filled.Block else Icons.Filled.Devices,
                    )
                } else if (isRestricted) {
                    val badgeColor = when (state) {
                        EnforcementState.PACKETS_DROPPED -> Color(0xFFFF5252)
                        EnforcementState.PARTIAL_BPF_ENFORCEMENT -> Color(0xFFFF7043)
                        EnforcementState.ENFORCEMENT_UNAVAILABLE,
                        EnforcementState.DEGRADED_MULTI_CLIENT -> Color(0xFFFFA000)
                        else -> Color(0xFFFF7043)
                    }
                    BadgeChip(
                        label = client.formattedBlockStatusLabel(),
                        color = badgeColor,
                        icon = if (state == EnforcementState.ENFORCEMENT_UNAVAILABLE || state == EnforcementState.DEGRADED_MULTI_CLIENT) {
                            Icons.Filled.Warning
                        } else {
                            Icons.Filled.Block
                        },
                    )
                } else {
                    BadgeChip(
                        label = "Connected (${client.formattedUptime()})",
                        color = Color(0xFF4CAF50),
                        icon = Icons.Outlined.CheckCircle,
                    )
                }

                // Bandwidth badge (honest packet-verified vs policy active vs not enforced)
                if (client.bandwidthLimitKbps > 0) {
                    val capColor = if (isCurrentlyConnected && (state == EnforcementState.ENFORCEMENT_UNAVAILABLE || state == EnforcementState.DEGRADED_MULTI_CLIENT)) {
                        Color(0xFFFFA000)
                    } else {
                        ShizziTheme.colors.primary
                    }
                    BadgeChip(
                        label = formatClientBandwidthBadgeLabel(client, isCurrentlyConnected),
                        color = capColor,
                        icon = Icons.Filled.Speed,
                    )
                }

                // Live traffic badge for connected clients
                if (isCurrentlyConnected && (client.rxBytes > 0L || client.txBytes > 0L)) {
                    BadgeChip(
                        label = "↓ ${Traffic.format(client.rxBytes)} · ↑ ${Traffic.format(client.txBytes)}",
                        color = Color(0xFF26A69A),
                        icon = Icons.Filled.SwapVert,
                    )
                }

                // Time Limit badge
                if (client.connectionTimeLimitMinutes > 0) {
                    BadgeChip(
                        label = "Max: ${client.connectionTimeLimitMinutes}m",
                        color = Color(0xFFFFA000),
                        icon = Icons.Filled.Schedule,
                    )
                }

                // Schedule badge
                if (client.scheduleEnabled) {
                    BadgeChip(
                        label = "Sched: ${formatScheduleHour(client.scheduleStartHour)} - ${formatScheduleHour(client.scheduleEndHour)}",
                        color = Color(0xFF29B6F6),
                        icon = Icons.Filled.Schedule,
                    )
                }
            }

            Spacer(Modifier.height(8.dp))
            HorizontalDivider(
                color = ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.15f),
                thickness = 0.5.dp,
            )
            Spacer(Modifier.height(6.dp))

            // Action row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(
                    onClick = onEdit,
                    modifier = Modifier.testTag("configure_client_${client.cleanMac}"),
                ) {
                    Icon(Icons.Filled.Edit, contentDescription = null, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Configure Limits")
                }

                IconButton(
                    onClick = onDelete,
                    modifier = Modifier.testTag("delete_rule_${client.cleanMac}"),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = "Delete Rule",
                        tint = ShizziTheme.colors.onSurfaceMuted,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun BadgeChip(
    label: String,
    color: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = color.copy(alpha = 0.12f),
        border = BorderStroke(0.5.dp, color.copy(alpha = 0.3f)),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(12.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(
                text = label,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
                color = color,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun ConfigureClientDialog(
    client: ConnectedClient,
    onDismiss: () -> Unit,
    onSave: (ClientRule) -> Unit,
) {
    var alias by remember(client.cleanMac) { mutableStateOf(client.alias) }
    var isBlocked by remember(client.cleanMac) { mutableStateOf(client.isBlocked) }
    var bandwidthMbpsText by remember(client.cleanMac, client.bandwidthLimitKbps) {
        mutableStateOf(formatKbpsAsMbps(client.bandwidthLimitKbps))
    }
    var durationMinutes by remember(client.cleanMac) { mutableIntStateOf(client.connectionTimeLimitMinutes) }
    var scheduleEnabled by remember(client.cleanMac) { mutableStateOf(client.scheduleEnabled) }
    var scheduleStartHour by remember(client.cleanMac) { mutableIntStateOf(client.scheduleStartHour.coerceIn(0, 23)) }
    var scheduleEndHour by remember(client.cleanMac) { mutableIntStateOf(client.scheduleEndHour.coerceIn(0, 23)) }
    var activeHourPicker by remember { mutableStateOf<HourPickerTarget?>(null) }

    val bandwidthValidation = remember(bandwidthMbpsText) {
        validateMbpsInput(bandwidthMbpsText)
    }
    val scheduleHoursValid = remember(scheduleEnabled, scheduleStartHour, scheduleEndHour) {
        isValidScheduleHours(scheduleEnabled, scheduleStartHour, scheduleEndHour)
    }
    val canSave = bandwidthValidation.isValid && scheduleHoursValid

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Configure Host Rules") },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = "MAC: ${client.cleanMac}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Spacer(Modifier.height(12.dp))

                OutlinedTextField(
                    value = alias,
                    onValueChange = { alias = it },
                    label = { Text("Friendly Alias") },
                    placeholder = { Text("e.g. Geraldo's Laptop") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("configure_alias_input"),
                )

                Spacer(Modifier.height(16.dp))

                // Block Internet Access Toggle
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Block Internet Access",
                            fontWeight = FontWeight.SemiBold,
                            style = ShizziTheme.typography.body,
                        )
                        Text(
                            text = "Immediately drops all download & upload traffic for this client",
                            fontSize = 12.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                    Switch(
                        checked = isBlocked,
                        onCheckedChange = { isBlocked = it },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = Color(0xFFFF5252),
                        ),
                        modifier = Modifier.testTag("configure_block_switch"),
                    )
                }

                Spacer(Modifier.height(16.dp))

                // Numeric Bandwidth Rate Limit in Mbps
                OutlinedTextField(
                    value = bandwidthMbpsText,
                    onValueChange = { bandwidthMbpsText = it },
                    label = { Text("Bandwidth Limit (Mbps)") },
                    suffix = { Text("Mbps") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    isError = !bandwidthValidation.isValid,
                    supportingText = {
                        if (bandwidthValidation.errorMessage != null) {
                            Text(
                                text = bandwidthValidation.errorMessage,
                                color = Color(0xFFFF5252),
                                modifier = Modifier.testTag("bandwidth_limit_error_text"),
                            )
                        } else {
                            Text(
                                text = "0 = Unlimited. Applied separately to download and upload.",
                                modifier = Modifier.testTag("bandwidth_limit_helper_text"),
                            )
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("bandwidth_limit_mbps_input"),
                )

                Spacer(Modifier.height(16.dp))

                // Connection Duration Limit Presets
                Text(
                    text = "Connection Time Limit",
                    fontWeight = FontWeight.SemiBold,
                    style = ShizziTheme.typography.body,
                )
                Text(
                    text = "Automatically blocks host when elapsed duration is exceeded",
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Spacer(Modifier.height(6.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    val timePresets = listOf(
                        0 to "Unlimited",
                        15 to "15m",
                        30 to "30m",
                        60 to "1h",
                        120 to "2h",
                        240 to "4h",
                    )
                    timePresets.forEach { (mins, label) ->
                        val selected = durationMinutes == mins
                        LimitChip(
                            label = label,
                            isSelected = selected,
                            onClick = { durationMinutes = mins },
                        )
                    }
                }

                Spacer(Modifier.height(16.dp))

                // Time of day schedule
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Scheduled Access Window",
                            fontWeight = FontWeight.SemiBold,
                            style = ShizziTheme.typography.body,
                        )
                        Text(
                            text = "Only permit internet during specific hours",
                            fontSize = 11.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                    Switch(
                        checked = scheduleEnabled,
                        onCheckedChange = { scheduleEnabled = it },
                        modifier = Modifier.testTag("configure_schedule_switch"),
                    )
                }

                AnimatedVisibility(visible = scheduleEnabled) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            ScheduleHourSelectorButton(
                                label = "Start time",
                                hour = scheduleStartHour,
                                isError = !scheduleHoursValid,
                                onClick = { activeHourPicker = HourPickerTarget.START },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("schedule_start_time_button"),
                            )
                            ScheduleHourSelectorButton(
                                label = "End time",
                                hour = scheduleEndHour,
                                isError = !scheduleHoursValid,
                                onClick = { activeHourPicker = HourPickerTarget.END },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("schedule_end_time_button"),
                            )
                        }

                        Spacer(Modifier.height(8.dp))

                        Text(
                            text = "${formatScheduleHour(scheduleStartHour)} → ${formatScheduleHour(scheduleEndHour)}",
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 12.sp,
                            color = if (scheduleHoursValid) ShizziTheme.colors.primary else Color(0xFFFF5252),
                            modifier = Modifier.testTag("schedule_window_summary_text"),
                        )

                        Spacer(Modifier.height(2.dp))

                        if (!scheduleHoursValid) {
                            Text(
                                text = "Start time and end time cannot be the same (${formatScheduleHour(scheduleStartHour)}). Select different whole hours.",
                                fontSize = 11.sp,
                                color = Color(0xFFFF5252),
                                modifier = Modifier.testTag("schedule_error_text"),
                            )
                        } else {
                            Text(
                                text = formatScheduleExplanation(scheduleStartHour, scheduleEndHour),
                                fontSize = 11.sp,
                                color = ShizziTheme.colors.onSurfaceMuted,
                                modifier = Modifier.testTag("schedule_helper_text"),
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val resolvedKbps = bandwidthValidation.kbps ?: return@Button
                    if (!isValidScheduleHours(scheduleEnabled, scheduleStartHour, scheduleEndHour)) {
                        return@Button
                    }
                    onSave(
                        ClientRule(
                            mac = client.cleanMac,
                            alias = alias.trim(),
                            isBlocked = isBlocked,
                            bandwidthLimitKbps = resolvedKbps,
                            connectionTimeLimitMinutes = durationMinutes,
                            scheduleEnabled = scheduleEnabled,
                            scheduleStartHour = scheduleStartHour,
                            scheduleEndHour = scheduleEndHour,
                        ),
                    )
                },
                enabled = canSave,
                colors = ButtonDefaults.buttonColors(containerColor = ShizziTheme.colors.primary),
                modifier = Modifier.testTag("save_client_rules_button"),
            ) {
                Text("Save Rules")
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("cancel_client_rules_button"),
            ) {
                Text("Cancel")
            }
        },
    )

    activeHourPicker?.let { target ->
        val currentSelected = if (target == HourPickerTarget.START) scheduleStartHour else scheduleEndHour
        val dialogTitle = if (target == HourPickerTarget.START) "Select Start Time (24h)" else "Select End Time (24h)"
        HourPickerDialog(
            title = dialogTitle,
            selectedHour = currentSelected,
            onSelectHour = { chosenHour ->
                if (target == HourPickerTarget.START) {
                    scheduleStartHour = chosenHour
                } else {
                    scheduleEndHour = chosenHour
                }
                activeHourPicker = null
            },
            onDismiss = { activeHourPicker = null },
        )
    }
}

private enum class HourPickerTarget {
    START,
    END,
}

@Composable
private fun ScheduleHourSelectorButton(
    label: String,
    hour: Int,
    isError: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val borderColor = when {
        isError -> Color(0xFFFF5252)
        else -> ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.35f)
    }
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = ShizziTheme.colors.surfaceVariant.copy(alpha = 0.65f),
        border = BorderStroke(1.dp, borderColor),
        modifier = modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text(
                    text = label,
                    fontSize = 11.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Text(
                    text = formatScheduleHour(hour),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    color = ShizziTheme.colors.onSurface,
                )
            }
            Icon(
                imageVector = Icons.Filled.Schedule,
                contentDescription = label,
                tint = if (isError) Color(0xFFFF5252) else ShizziTheme.colors.primary,
                modifier = Modifier.size(18.dp),
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun HourPickerDialog(
    title: String,
    selectedHour: Int,
    onSelectHour: (Int) -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = "Whole hours only (00:00 – 23:00)",
                    fontSize = 12.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Spacer(Modifier.height(10.dp))
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    for (hour in 0..23) {
                        val isSelected = hour == selectedHour
                        val formatted = formatScheduleHour(hour)
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (isSelected) {
                                ShizziTheme.colors.primary.copy(alpha = 0.2f)
                            } else {
                                ShizziTheme.colors.surfaceVariant
                            },
                            border = BorderStroke(
                                width = 1.dp,
                                color = if (isSelected) {
                                    ShizziTheme.colors.primary
                                } else {
                                    ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.25f)
                                },
                            ),
                            modifier = Modifier
                                .clip(RoundedCornerShape(10.dp))
                                .clickable { onSelectHour(hour) }
                                .testTag("hour_option_$hour"),
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
                            ) {
                                Text(
                                    text = formatted,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 13.sp,
                                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                                    color = if (isSelected) ShizziTheme.colors.primary else ShizziTheme.colors.onSurface,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.testTag("hour_picker_cancel_button"),
            ) {
                Text("Cancel")
            }
        },
    )
}

@Composable
private fun AddClientDialog(
    onDismiss: () -> Unit,
    onAdd: (ClientRule) -> Unit,
) {
    var macInput by remember { mutableStateOf("") }
    var aliasInput by remember { mutableStateOf("") }
    var isBlocked by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Host by MAC") },
        text = {
            Column {
                Text(
                    text = "Enter the hardware MAC address of the device to pre-configure its access policy.",
                    fontSize = 12.sp,
                    color = ShizziTheme.colors.onSurfaceMuted,
                )
                Spacer(Modifier.height(12.dp))

                OutlinedTextField(
                    value = macInput,
                    onValueChange = {
                        macInput = it
                        errorMessage = null
                    },
                    label = { Text("MAC Address") },
                    placeholder = { Text("e.g. AA:BB:CC:DD:EE:FF") },
                    singleLine = true,
                    isError = errorMessage != null,
                    supportingText = { errorMessage?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth().testTag("add_mac_input"),
                )

                Spacer(Modifier.height(8.dp))

                OutlinedTextField(
                    value = aliasInput,
                    onValueChange = { aliasInput = it },
                    label = { Text("Device Alias (Optional)") },
                    placeholder = { Text("e.g. Living Room TV") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth().testTag("add_alias_input"),
                )

                Spacer(Modifier.height(12.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Block Internet Access Immediately")
                    Switch(
                        checked = isBlocked,
                        onCheckedChange = { isBlocked = it },
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val clean = macInput.trim().uppercase().replace('-', ':')
                    val isValidMac = Regex("^([0-9A-F]{2}:){5}([0-9A-F]{2})$").matches(clean)
                    if (!isValidMac) {
                        errorMessage = "Invalid MAC address format (must be XX:XX:XX:XX:XX:XX)"
                        return@Button
                    }
                    onAdd(
                        ClientRule(
                            mac = clean,
                            alias = aliasInput.trim(),
                            isBlocked = isBlocked,
                        ),
                    )
                },
                colors = ButtonDefaults.buttonColors(containerColor = ShizziTheme.colors.primary),
                modifier = Modifier.testTag("confirm_add_mac_button"),
            ) {
                Text("Add Rule")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        },
    )
}

@Composable
private fun LimitChip(
    label: String,
    isSelected: Boolean,
    onClick: () -> Unit,
) {
    val bg = if (isSelected) ShizziTheme.colors.primary.copy(alpha = 0.2f) else ShizziTheme.colors.surfaceVariant
    val border = if (isSelected) ShizziTheme.colors.primary else ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.25f)
    val text = if (isSelected) ShizziTheme.colors.primary else ShizziTheme.colors.onSurface

    Surface(
        shape = RoundedCornerShape(14.dp),
        color = bg,
        border = BorderStroke(1.dp, border),
        modifier = Modifier
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
        ) {
            if (isSelected) {
                Icon(
                    imageVector = Icons.Filled.Check,
                    contentDescription = null,
                    tint = ShizziTheme.colors.primary,
                    modifier = Modifier.padding(end = 4.dp).size(12.dp),
                )
            }
            Text(
                text = label,
                fontSize = 12.sp,
                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                color = text,
            )
        }
    }
}
