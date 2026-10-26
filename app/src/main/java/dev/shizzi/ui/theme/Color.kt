package dev.shizzi.ui.theme

import androidx.compose.ui.graphics.Color

data class ShizziColors(
    val primary: Color,
    val onPrimary: Color,
    val primaryBright: Color,
    val background: Color,
    val surface: Color,
    val onSurface: Color,
    val onSurfaceMuted: Color,
    val border: Color,
    val shadow: Color,
    val isDark: Boolean,
    val primaryContainer: Color = primary,
    val onPrimaryContainer: Color = onPrimary,
    val secondary: Color = primary,
    val tertiary: Color = primary,
    val surfaceVariant: Color = surface,
    val surfaceContainer: Color = surface,
)

private val OnPrimary = Color(4278190080L)

val LightColors = ShizziColors(
    primary = Color(4279548070L),
    onPrimary = OnPrimary,
    primaryBright = Color(4284410580L),
    background = Color(4294638329L),
    surface = Color(4294967295L),
    onSurface = Color(4278979081L),
    onSurfaceMuted = Color(4283913038L),
    border = Color(4278190080L),
    shadow = Color(4278190080L),
    isDark = false,
)

val DarkColors = ShizziColors(
    primary = Color(4281193663L),
    onPrimary = OnPrimary,
    primaryBright = Color(4288280292L),
    background = Color(4278979081L),
    surface = Color(4280031511L),
    onSurface = Color(4294638329L),
    onSurfaceMuted = Color(4289241758L),
    border = Color(4294967295L),
    shadow = Color(4294967295L),
    isDark = true,
)
