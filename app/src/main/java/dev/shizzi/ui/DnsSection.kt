package dev.shizzi.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.shizzi.DnsPreset
import dev.shizzi.DnsSettings
import dev.shizzi.ui.theme.ShizziTheme

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DnsSection(
    settings: DnsSettings,
    onSetPreset: (DnsPreset) -> Unit,
    onSetCustomDns: (primary: String, secondary: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var customPrimary by remember(settings.customPrimary) { mutableStateOf(settings.customPrimary) }
    var customSecondary by remember(settings.customSecondary) { mutableStateOf(settings.customSecondary) }
    var isEditingCustom by remember(settings.preset) {
        mutableStateOf(settings.preset == DnsPreset.CUSTOM)
    }

    Column(modifier = modifier.fillMaxWidth().testTag("dns_section")) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = ShizziTheme.colors.surfaceVariant,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Dns,
                        contentDescription = "DNS Configuration",
                        tint = ShizziTheme.colors.primary,
                    )
                    Spacer(Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Upstream DNS Resolution",
                            style = ShizziTheme.typography.body,
                            fontWeight = FontWeight.SemiBold,
                            color = ShizziTheme.colors.onSurface,
                        )
                        Text(
                            text = "DNS servers applied to tethered devices & tunnel",
                            style = ShizziTheme.typography.caption,
                            color = ShizziTheme.colors.onSurfaceMuted,
                        )
                    }
                }

                Spacer(Modifier.height(16.dp))

                // Active DNS Summary
                val activeAddrs = settings.resolveAddresses()
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(ShizziTheme.colors.background)
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = if (activeAddrs.isNotEmpty()) {
                            "Active: ${activeAddrs.joinToString(", ")}"
                        } else {
                            "Active: System / Default carrier upstream"
                        },
                        style = ShizziTheme.typography.caption,
                        color = ShizziTheme.colors.primary,
                        fontWeight = FontWeight.Medium,
                    )
                }

                Spacer(Modifier.height(14.dp))

                // Presets
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    DnsPreset.entries.forEach { preset ->
                        val isSelected = settings.preset == preset
                        DnsChip(
                            label = preset.title,
                            isSelected = isSelected,
                            onClick = {
                                onSetPreset(preset)
                                isEditingCustom = (preset == DnsPreset.CUSTOM)
                            },
                        )
                    }
                }

                AnimatedVisibility(
                    visible = settings.preset == DnsPreset.CUSTOM,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically(),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 16.dp),
                    ) {
                        Text(
                            text = "Custom DNS Server Addresses",
                            style = ShizziTheme.typography.caption,
                            color = ShizziTheme.colors.onSurface,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Spacer(Modifier.height(8.dp))

                        OutlinedTextField(
                            value = customPrimary,
                            onValueChange = { customPrimary = it },
                            label = { Text("Primary DNS (IPv4 or IPv6)") },
                            placeholder = { Text("e.g. 1.1.1.1 or 8.8.8.8") },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = ShizziTheme.colors.primary,
                                unfocusedBorderColor = ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.3f),
                                focusedLabelColor = ShizziTheme.colors.primary,
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("custom_dns_primary_input"),
                        )

                        Spacer(Modifier.height(8.dp))

                        OutlinedTextField(
                            value = customSecondary,
                            onValueChange = { customSecondary = it },
                            label = { Text("Secondary DNS (Optional)") },
                            placeholder = { Text("e.g. 1.0.0.1 or 8.8.4.4") },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = ShizziTheme.colors.primary,
                                unfocusedBorderColor = ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.3f),
                                focusedLabelColor = ShizziTheme.colors.primary,
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("custom_dns_secondary_input"),
                        )

                        Spacer(Modifier.height(12.dp))

                        Button(
                            onClick = {
                                onSetCustomDns(customPrimary.trim(), customSecondary.trim())
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = ShizziTheme.colors.primary,
                                contentColor = ShizziTheme.colors.onPrimary,
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier
                                .align(Alignment.End)
                                .testTag("save_custom_dns_button"),
                        ) {
                            Text("Apply Custom DNS")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DnsChip(
    label: String,
    isSelected: Boolean,
    onClick: () -> Unit,
) {
    val bg = if (isSelected) ShizziTheme.colors.primary.copy(alpha = 0.15f) else ShizziTheme.colors.background
    val border = if (isSelected) ShizziTheme.colors.primary else ShizziTheme.colors.onSurfaceMuted.copy(alpha = 0.2f)
    val textColor = if (isSelected) ShizziTheme.colors.primary else ShizziTheme.colors.onSurface

    Surface(
        shape = RoundedCornerShape(20.dp),
        color = bg,
        border = BorderStroke(1.dp, border),
        modifier = Modifier
            .clip(RoundedCornerShape(20.dp))
            .clickable(onClick = onClick)
            .testTag("dns_chip_$label"),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
        ) {
            if (isSelected) {
                Icon(
                    imageVector = Icons.Filled.Check,
                    contentDescription = null,
                    tint = ShizziTheme.colors.primary,
                    modifier = Modifier.padding(end = 4.dp).height(14.dp).width(14.dp),
                )
            }
            Text(
                text = label,
                fontSize = 13.sp,
                fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal,
                color = textColor,
            )
        }
    }
}
