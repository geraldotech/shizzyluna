package dev.shizzi.ui.theme

import androidx.compose.runtime.Composable
import java.util.Locale

@Composable
fun themedLabel(text: String): String = when (ShizziTheme.design) {
    DesignLanguage.NEOBRUTALISM -> text.uppercase(Locale.ROOT)
    DesignLanguage.MATERIAL_EXPRESSIVE -> text
}
