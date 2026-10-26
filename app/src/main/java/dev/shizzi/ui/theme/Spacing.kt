package dev.shizzi.ui.theme

import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

data class ShizziSpacing(
    val xs: Dp = 4.dp,
    val sm: Dp = 8.dp,
    val md: Dp = 12.dp,
    val lg: Dp = 16.dp,
    val xl: Dp = 24.dp,
    val xxl: Dp = 32.dp,
    val xxxl: Dp = 48.dp,
)

val Spacing = ShizziSpacing()
val ScreenPadding: Dp = Spacing.lg
val HeaderHeight: Dp = 56.dp
val MinTouchTarget: Dp = 48.dp
