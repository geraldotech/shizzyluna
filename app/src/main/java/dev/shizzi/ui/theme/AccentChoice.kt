package dev.shizzi.ui.theme

sealed interface AccentChoice {
    data object Default : AccentChoice
    data object Expressive : AccentChoice
    data class Custom(val argb: Int) : AccentChoice
}

val PresetAccents: List<Int> = listOf(
    -2024120,
    -429290,
    -1395960,
    -14498466,
    -16337196,
    -12877066,
    -7643914,
    -1292135,
)
