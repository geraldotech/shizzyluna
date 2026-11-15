package dev.shizzi.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.shizzi.VpnMode
import dev.shizzi.ui.theme.ShizziTheme

@Composable
fun VpnSection(
    selected: VpnMode,
    onSelect: (VpnMode) -> Unit,
    stopHotspotOnVpnDisconnect: Boolean = true,
    onSetStopHotspotOnVpnDisconnect: (Boolean) -> Unit = {},
) {
    var isPickerOpen by remember { mutableStateOf(false) }
    val isNeverMode = selected == VpnMode.NEVER

    Column(modifier = Modifier.fillMaxWidth()) {
        SettingsChoice(
            label = SettingsText(title = "VPN"),
            value = vpnModeLabel(selected),
            onClick = { isPickerOpen = true },
        )

        Spacer(Modifier.height(8.dp))

        Surface(
            shape = RoundedCornerShape(12.dp),
            color = ShizziTheme.colors.surface,
            border = BorderStroke(1.dp, ShizziTheme.colors.border.copy(alpha = 0.6f)),
            modifier = Modifier
                .fillMaxWidth()
                .alpha(if (isNeverMode) 0.55f else 1f)
                .testTag("vpn_stop_on_disconnect_toggle"),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = !isNeverMode) {
                            onSetStopHotspotOnVpnDisconnect(!stopHotspotOnVpnDisconnect)
                        },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f).padding(end = 10.dp)) {
                        Text(
                            text = "Stop hotspot when VPN disconnects",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp,
                            color = ShizziTheme.colors.onSurface,
                            modifier = Modifier.testTag("stop_hotspot_on_vpn_disconnect_label"),
                        )
                        Text(
                            text = if (isNeverMode) {
                                "Unavailable when VPN mode is set to Never."
                            } else {
                                "Turn this off to keep the hotspot on while the app waits for the VPN to reconnect."
                            },
                            fontSize = 11.sp,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                    Switch(
                        checked = stopHotspotOnVpnDisconnect,
                        onCheckedChange = { onSetStopHotspotOnVpnDisconnect(it) },
                        enabled = !isNeverMode,
                        modifier = Modifier.testTag("vpn_stop_on_disconnect_switch"),
                    )
                }

                if (!stopHotspotOnVpnDisconnect && !isNeverMode) {
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = Color(0xFFFFB300).copy(alpha = 0.12f),
                        border = BorderStroke(1.dp, Color(0xFFFFB300).copy(alpha = 0.45f)),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("vpn_keep_hotspot_warning_card"),
                    ) {
                        Text(
                            text = "While the VPN is disconnected, internet access may be interrupted. Traffic must not silently bypass the VPN.",
                            fontSize = 10.sp,
                            color = Color(0xFFFFB300),
                            modifier = Modifier
                                .padding(horizontal = 10.dp, vertical = 8.dp)
                                .testTag("vpn_keep_hotspot_warning_text"),
                        )
                    }
                }
            }
        }
    }

    if (!isPickerOpen) return

    VpnModePicker(
        selected = selected,
        onSelect = onSelect,
        onDismiss = { isPickerOpen = false },
    )
}

