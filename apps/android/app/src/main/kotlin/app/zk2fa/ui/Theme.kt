package app.zk2fa.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Indigo = Color(0xFF4F46E5)
private val IndigoLight = Color(0xFFA5B4FC)

@Composable
fun VeilTheme(content: @Composable () -> Unit) {
    val colors =
        if (isSystemInDarkTheme()) {
            darkColorScheme(primary = IndigoLight, secondary = IndigoLight)
        } else {
            lightColorScheme(primary = Indigo, secondary = Indigo)
        }
    MaterialTheme(colorScheme = colors, content = content)
}
