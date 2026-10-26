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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
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

data class ClientActions(
    val onToggleBlock: (mac: String, shouldBlock: Boolean) -> Unit,
    val onSaveRule: (rule: ClientRule) -> Unit,
    val onRemoveRule: (mac: String) -> Unit,
    val onRefresh: () -> Unit,
)

@Composable
fun ClientsPage(
    clients: List<ConnectedClient>,
    actions: ClientActions,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    savedRules: List<ClientRule> = emptyList(),
    sessionState: SessionUiState = SessionUiState(),
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
                    .padding(bottom = 12.dp),
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
                        val dropSummary = if (isRestricted) " • ${client.droppedPackets} dropped" else ""
                        Text(
                            text = "pkts: ${client.seenPackets} seen • ${client.matchedPackets} matched$dropSummary",
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
                // Status badge (honest packet-verified vs configured vs unavailable vs degraded)
                if (!isCurrentlyConnected) {
                    BadgeChip(
                        label = if (isRestricted) "Offline • ${restrictReason ?: "Blocked"} (saved)" else "Offline • Saved Rule",
                        color = if (isRestricted) Color(0xFFFF5252) else ShizziTheme.colors.onSurfaceMuted,
                        icon = if (isRestricted) Icons.Filled.Block else Icons.Filled.Devices,
                    )
                } else if (isRestricted) {
                    val badgeColor = when (state) {
                        EnforcementState.PACKETS_DROPPED -> Color(0xFFFF5252)
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
                        label = client.formattedBandwidthBadgeLabel(isCurrentlyConnected),
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
                        label = "Sched: ${client.scheduleStartHour}:00 - ${client.scheduleEndHour}:00",
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
private fun ConfigureClientDialog(
    client: ConnectedClient,
    onDismiss: () -> Unit,
    onSave: (ClientRule) -> Unit,
) {
    var alias by remember { mutableStateOf(client.alias) }
    var isBlocked by remember { mutableStateOf(client.isBlocked) }
    var bandwidthKbps by remember { mutableIntStateOf(client.bandwidthLimitKbps) }
    var durationMinutes by remember { mutableIntStateOf(client.connectionTimeLimitMinutes) }
    var scheduleEnabled by remember { mutableStateOf(client.scheduleEnabled) }
    var scheduleStartHour by remember { mutableIntStateOf(client.scheduleStartHour) }
    var scheduleEndHour by remember { mutableIntStateOf(client.scheduleEndHour) }

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
                    modifier = Modifier.fillMaxWidth(),
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
                    )
                }

                Spacer(Modifier.height(16.dp))

                // Bandwidth Rate Limit Presets
                Text(
                    text = "Bandwidth Limit (Per Direction: Download & Upload)",
                    fontWeight = FontWeight.SemiBold,
                    style = ShizziTheme.typography.body,
                )
                Spacer(Modifier.height(6.dp))
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    val presets = listOf(
                        0 to "Unlimited",
                        512 to "512 Kbps",
                        1000 to "1 Mbps",
                        2000 to "2 Mbps",
                        5000 to "5 Mbps",
                        10000 to "10 Mbps",
                        25000 to "25 Mbps",
                    )
                    presets.forEach { (limit, label) ->
                        val selected = bandwidthKbps == limit
                        LimitChip(
                            label = label,
                            isSelected = selected,
                            onClick = { bandwidthKbps = limit },
                        )
                    }
                }

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
                    )
                }

                AnimatedVisibility(visible = scheduleEnabled) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedTextField(
                            value = scheduleStartHour.toString(),
                            onValueChange = { scheduleStartHour = it.toIntOrNull()?.coerceIn(0, 23) ?: 0 },
                            label = { Text("Start Hour (0-23)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedTextField(
                            value = scheduleEndHour.toString(),
                            onValueChange = { scheduleEndHour = it.toIntOrNull()?.coerceIn(0, 23) ?: 23 },
                            label = { Text("End Hour (0-23)") },
                            singleLine = true,
                            modifier = Modifier.weight(1f),
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSave(
                        ClientRule(
                            mac = client.cleanMac,
                            alias = alias.trim(),
                            isBlocked = isBlocked,
                            bandwidthLimitKbps = bandwidthKbps,
                            connectionTimeLimitMinutes = durationMinutes,
                            scheduleEnabled = scheduleEnabled,
                            scheduleStartHour = scheduleStartHour,
                            scheduleEndHour = scheduleEndHour,
                        ),
                    )
                },
                colors = ButtonDefaults.buttonColors(containerColor = ShizziTheme.colors.primary),
            ) {
                Text("Save Rules")
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
