package dev.shizzi.ui.theme

import android.content.Context
import android.os.Build
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import com.materialkolor.dynamiccolor.DynamicColor
import com.materialkolor.dynamiccolor.MaterialDynamicColors
import com.materialkolor.hct.Hct
import com.materialkolor.scheme.DynamicScheme
import com.materialkolor.scheme.SchemeExpressive
import com.materialkolor.scheme.SchemeTonalSpot

sealed interface AccentPalette {
    val colors: ShizziColors
    val scheme: ColorScheme

    data class Fixed(val isDark: Boolean) : AccentPalette {
        override val colors: ShizziColors = if (isDark) DarkColors else LightColors
        override val scheme: ColorScheme = materialSchemeOf(colors, isDark)
    }

    data class Material(val source: ColorScheme, val isDark: Boolean) : AccentPalette {
        override val colors: ShizziColors = shizziColorsFrom(source, isDark)
        override val scheme: ColorScheme = source
    }

    data class Generated(val source: DynamicScheme, val isDark: Boolean) : AccentPalette {
        override val colors: ShizziColors = shizziColorsFrom(source, isDark)
        override val scheme: ColorScheme = materialSchemeOf(colors, isDark)
    }
}

private const val BlackArgb = -16777216
private const val StandardContrast = 0.0
private const val WhiteArgb = -1
private const val DefaultSeed = -15419226
val DefaultAccentColor = Color(DefaultSeed)
private val Roles = MaterialDynamicColors()

fun accentPalette(accent: AccentChoice, isDark: Boolean, context: Context): AccentPalette {
    if (accent is AccentChoice.Default) {
        return AccentPalette.Fixed(isDark)
    }
    val dynamic = wallpaperScheme(accent, isDark, context)
    return if (dynamic != null) {
        AccentPalette.Material(dynamic, isDark)
    } else {
        AccentPalette.Generated(schemeFor(accent, isDark), isDark)
    }
}

private fun wallpaperScheme(accent: AccentChoice, isDark: Boolean, context: Context): ColorScheme? {
    if (accent is AccentChoice.Expressive && Build.VERSION.SDK_INT >= 31) {
        return if (isDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
    }
    return null
}

fun schemeFor(accent: AccentChoice, isDark: Boolean): DynamicScheme = when (accent) {
    is AccentChoice.Expressive -> SchemeExpressive(Hct.fromInt(DefaultSeed), isDark, StandardContrast)
    is AccentChoice.Custom -> SchemeTonalSpot(Hct.fromInt(accent.argb), isDark, StandardContrast)
    is AccentChoice.Default -> SchemeTonalSpot(Hct.fromInt(DefaultSeed), isDark, StandardContrast)
}

fun DynamicScheme.roleArgb(pick: MaterialDynamicColors.() -> DynamicColor): Int =
    pick(Roles).getArgb(this)

fun brutalEdgeArgb(isDark: Boolean): Int = if (isDark) WhiteArgb else BlackArgb

private fun DynamicScheme.role(pick: MaterialDynamicColors.() -> DynamicColor): Color =
    Color(roleArgb(pick))

private fun hardEdge(isDark: Boolean): Color = Color(brutalEdgeArgb(isDark))

private fun shizziColorsFrom(scheme: DynamicScheme, isDark: Boolean): ShizziColors {
    val primary = scheme.role { primary() }
    val onPrimary = scheme.role { onPrimary() }
    val primaryContainer = scheme.role { primaryContainer() }
    val background = scheme.role { background() }
    val surface = scheme.role { surfaceContainerLow() }
    val onSurface = scheme.role { onSurface() }
    val onSurfaceMuted = scheme.role { onSurfaceVariant() }
    val onPrimaryContainer = scheme.role { onPrimaryContainer() }
    val secondary = scheme.role { secondary() }
    val tertiary = scheme.role { tertiary() }
    val surfaceVariant = scheme.role { surfaceVariant() }
    val surfaceContainer = scheme.role { surfaceContainerHigh() }

    return ShizziColors(
        primary = primary,
        onPrimary = onPrimary,
        primaryBright = primaryContainer,
        background = background,
        surface = surface,
        onSurface = onSurface,
        onSurfaceMuted = onSurfaceMuted,
        border = hardEdge(isDark),
        shadow = hardEdge(isDark),
        isDark = isDark,
        primaryContainer = primaryContainer,
        onPrimaryContainer = onPrimaryContainer,
        secondary = secondary,
        tertiary = tertiary,
        surfaceVariant = surfaceVariant,
        surfaceContainer = surfaceContainer,
    )
}

private fun shizziColorsFrom(scheme: ColorScheme, isDark: Boolean): ShizziColors {
    return ShizziColors(
        primary = scheme.primary,
        onPrimary = scheme.onPrimary,
        primaryBright = scheme.primaryContainer,
        background = scheme.background,
        surface = scheme.surfaceContainerLow,
        onSurface = scheme.onSurface,
        onSurfaceMuted = scheme.onSurfaceVariant,
        border = hardEdge(isDark),
        shadow = hardEdge(isDark),
        isDark = isDark,
        primaryContainer = scheme.primaryContainer,
        onPrimaryContainer = scheme.onPrimaryContainer,
        secondary = scheme.secondary,
        tertiary = scheme.tertiary,
        surfaceVariant = scheme.surfaceVariant,
        surfaceContainer = scheme.surfaceContainerHigh,
    )
}

private fun materialSchemeOf(colors: ShizziColors, isDark: Boolean): ColorScheme {
    val base = if (isDark) darkColorScheme() else lightColorScheme()
    return base.copy(
        primary = colors.primary,
        onPrimary = colors.onPrimary,
        primaryContainer = colors.primaryContainer,
        onPrimaryContainer = colors.onPrimaryContainer,
        secondary = colors.secondary,
        tertiary = colors.tertiary,
        background = colors.background,
        surface = colors.surface,
        onSurface = colors.onSurface,
        surfaceVariant = colors.surfaceVariant,
        onSurfaceVariant = colors.onSurfaceMuted,
        outline = colors.border,
        surfaceContainer = colors.surfaceContainer,
    )
}
