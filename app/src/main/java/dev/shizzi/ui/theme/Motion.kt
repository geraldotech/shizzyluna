package dev.shizzi.ui.theme

import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Easing
import androidx.compose.animation.core.FiniteAnimationSpec
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable

data class ShizziMotion(
    val fastMillis: Int,
    val standardMillis: Int,
    val slowMillis: Int,
    val fastStiffness: Float,
    val standardStiffness: Float,
    val emphasizedStiffness: Float,
    val damping: Float,
    val easing: Easing,
)

private val StandardEasing = CubicBezierEasing(0.2f, 0.0f, 0.0f, 1.0f)

val BrutalMotion = ShizziMotion(
    fastMillis = 90,
    standardMillis = 160,
    slowMillis = 240,
    fastStiffness = 10000.0f,
    standardStiffness = 1500.0f,
    emphasizedStiffness = 400.0f,
    damping = 1.0f,
    easing = StandardEasing,
)

val ExpressiveMotion = ShizziMotion(
    fastMillis = 140,
    standardMillis = 260,
    slowMillis = 400,
    fastStiffness = 1500.0f,
    standardStiffness = 400.0f,
    emphasizedStiffness = 400.0f,
    damping = 0.5f,
    easing = StandardEasing,
)

@Composable
fun <T> fastSpring(): FiniteAnimationSpec<T> {
    val motion = ShizziTheme.motion
    return spring(dampingRatio = motion.damping, stiffness = motion.fastStiffness)
}

@Composable
fun <T> standardSpring(): FiniteAnimationSpec<T> {
    val motion = ShizziTheme.motion
    return spring(dampingRatio = motion.damping, stiffness = motion.standardStiffness)
}

@Composable
fun <T> emphasizedSpring(): FiniteAnimationSpec<T> {
    val motion = ShizziTheme.motion
    return spring(dampingRatio = motion.damping, stiffness = motion.emphasizedStiffness)
}

@Composable
fun <T> standardTween(): FiniteAnimationSpec<T> {
    val motion = ShizziTheme.motion
    return tween(durationMillis = motion.standardMillis, easing = motion.easing)
}

@Composable
fun <T> fastTween(): FiniteAnimationSpec<T> {
    val motion = ShizziTheme.motion
    return tween(durationMillis = motion.fastMillis, easing = motion.easing)
}
