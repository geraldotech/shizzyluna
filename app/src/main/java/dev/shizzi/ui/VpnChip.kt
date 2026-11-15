package dev.shizzi.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import dev.shizzi.VpnLifecycleState
import dev.shizzi.ui.theme.ShizziTheme

@Composable
fun VpnChip(
    isBypassed: Boolean = false,
    vpnLifecycleState: VpnLifecycleState = VpnLifecycleState.VPN_BOUND,
    vpnRecoveryCount: Long = 0L,
) {
    val isWaitingOrRebinding = vpnLifecycleState == VpnLifecycleState.VPN_WAITING_FOR_RECOVERY ||
        vpnLifecycleState == VpnLifecycleState.VPN_REBINDING ||
        vpnLifecycleState == VpnLifecycleState.VPN_RECOVERY_FAILED

    val tint = when {
        isWaitingOrRebinding -> Color(0xFFFFB300)
        isBypassed -> ShizziTheme.colors.onSurfaceMuted
        else -> ShizziTheme.colors.primary
    }

    val label = when {
        vpnLifecycleState == VpnLifecycleState.VPN_WAITING_FOR_RECOVERY ->
            "VPN DISCONNECTED — WAITING FOR RECONNECTION"
        vpnLifecycleState == VpnLifecycleState.VPN_REBINDING ||
            vpnLifecycleState == VpnLifecycleState.VPN_RECOVERY_FAILED ->
            "VPN RECONNECTING"
        isBypassed -> "VPN IGNORED"
        vpnLifecycleState == VpnLifecycleState.VPN_BOUND && vpnRecoveryCount > 0L ->
            "VPN RECOVERED"
        else -> "VPN CONNECTED"
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(ShizziTheme.spacing.sm),
        modifier = Modifier.testTag("vpn_status_chip"),
    ) {
        Icon(
            imageVector = Icons.Filled.VpnKey,
            contentDescription = null,
            tint = tint,
            modifier = Modifier.size(ShizziTheme.spacing.lg),
        )

        Text(
            text = label,
            style = ShizziTheme.typography.caption,
            color = tint,
            modifier = Modifier.testTag("vpn_status_chip_text"),
        )
    }
}

