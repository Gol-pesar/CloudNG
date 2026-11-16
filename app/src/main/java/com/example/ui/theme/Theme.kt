package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val DarkColorScheme = darkColorScheme(
    primary = CyberCyan,
    onPrimary = ObsidianBg,
    primaryContainer = CyberCyanContainer,
    onPrimaryContainer = Color(0xFFBAE6FD),
    secondary = CyberIndigo,
    onSecondary = Color.White,
    secondaryContainer = CyberIndigoContainer,
    onSecondaryContainer = Color(0xFFC7D2FE),
    tertiary = SignalEmerald,
    onTertiary = ObsidianBg,
    tertiaryContainer = SignalEmeraldContainer,
    onTertiaryContainer = Color(0xFFA7F3D0),
    error = SignalRose,
    onError = Color.White,
    errorContainer = SignalRoseContainer,
    onErrorContainer = Color(0xFFFECACA),
    background = ObsidianBg,
    onBackground = TextPrimaryDark,
    surface = ObsidianSurface,
    onSurface = TextPrimaryDark,
    surfaceVariant = ObsidianSurfaceHigh,
    onSurfaceVariant = TextSecondaryDark,
    surfaceContainerLowest = ObsidianBg,
    surfaceContainerLow = ObsidianSurface,
    surfaceContainer = ObsidianSurfaceHigh,
    surfaceContainerHigh = ObsidianSurfaceHighest,
    outline = ObsidianOutline,
    outlineVariant = Color(0xFF1C263B),
)

private val LightColorScheme = lightColorScheme(
    primary = LightCyan,
    onPrimary = Color.White,
    primaryContainer = LightCyanContainer,
    onPrimaryContainer = Color(0xFF0C4A6E),
    secondary = LightIndigo,
    onSecondary = Color.White,
    secondaryContainer = LightIndigoContainer,
    onSecondaryContainer = Color(0xFF312E81),
    tertiary = SignalEmerald,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD1FAE5),
    onTertiaryContainer = Color(0xFF065F46),
    error = SignalRose,
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF991B1B),
    background = LightBg,
    onBackground = TextPrimaryLight,
    surface = LightSurface,
    onSurface = TextPrimaryLight,
    surfaceVariant = LightSurfaceHigh,
    onSurfaceVariant = TextSecondaryLight,
    surfaceContainerLowest = LightSurface,
    surfaceContainerLow = LightBg,
    surfaceContainer = LightSurfaceHigh,
    surfaceContainerHigh = LightSurfaceHighest,
    outline = LightOutline,
    outlineVariant = Color(0xFFE2E8F0),
)

val AppShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

enum class ThemePreference {
    DARK,
    LIGHT,
    SYSTEM,
}

@Composable
fun SocksGuardTheme(
    themePreference: ThemePreference = ThemePreference.DARK,
    content: @Composable () -> Unit,
) {
    val useDark = when (themePreference) {
        ThemePreference.DARK -> true
        ThemePreference.LIGHT -> false
        ThemePreference.SYSTEM -> isSystemInDarkTheme()
    }
    val colorScheme = if (useDark) DarkColorScheme else LightColorScheme

    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        shapes = AppShapes,
        content = content,
    )
}
