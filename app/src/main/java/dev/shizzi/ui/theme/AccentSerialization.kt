package dev.shizzi.ui.theme

private const val DEFAULT_NAME = "default"
private const val EXPRESSIVE_NAME = "expressive"
private const val OPAQUE = -16777216
private const val RGB_MASK = 16777215

fun AccentChoice.serialize(): String = when (this) {
    is AccentChoice.Default -> DEFAULT_NAME
    is AccentChoice.Expressive -> EXPRESSIVE_NAME
    is AccentChoice.Custom -> toHex(argb)
}

fun parseAccent(stored: String?): AccentChoice = when (stored) {
    null, "", DEFAULT_NAME -> AccentChoice.Default
    EXPRESSIVE_NAME -> AccentChoice.Expressive
    else -> parseHex(stored)?.let { AccentChoice.Custom(it) } ?: AccentChoice.Default
}

fun serializeAccents(accents: List<Int>): String =
    accents.joinToString(",") { toHex(it) }

fun parseAccents(stored: String?): List<Int> {
    if (stored.isNullOrBlank()) return emptyList()
    return stored.split(",").mapNotNull { parseHex(it.trim()) }
}

private fun toHex(value: Int): String =
    String.format("#%06X", value and RGB_MASK)

private fun parseHex(value: String): Int? {
    if (value.startsWith("#") && value.length == 7) {
        val hex = value.drop(1).toIntOrNull(16) ?: return null
        return hex or OPAQUE
    }
    return null
}
