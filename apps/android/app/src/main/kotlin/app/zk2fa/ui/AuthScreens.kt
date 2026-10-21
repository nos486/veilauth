package app.zk2fa.ui

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zk2fa.AppContainer
import app.zk2fa.net.Network
import kotlinx.coroutines.launch

@Composable
fun LoginScreen(c: AppContainer) {
    val scope = rememberCoroutineScope()
    var email by remember { mutableStateOf(c.accounts.lastEmail()) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    ScreenColumn {
        Text("veilauth", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Log in to your vault. Your password never leaves this phone; only a derived key is sent to ${Network.apiBaseUrl.host}.",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("E-mail") },
            singleLine = true,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, autoCorrectEnabled = false),
        )
        PasswordField(password, { password = it }, "Master password", enabled = !busy)
        ErrorText(error)
        if (busy) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
            Text("Deriving keys… this takes a few seconds on purpose.", style = MaterialTheme.typography.bodySmall)
        }
        Button(
            onClick = {
                if (email.isBlank() || password.isEmpty()) {
                    error = "Enter your e-mail and password."
                    return@Button
                }
                busy = true
                error = null
                scope.launch {
                    try {
                        c.controller.logIn(email, password)
                        password = ""
                    } catch (e: Exception) {
                        error = messageFor(e)
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Log in") }
        Text(
            "No account yet? Create one in the web app; sign-up on Android comes in a later version.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
fun UnlockScreen(
    c: AppContainer,
    activity: FragmentActivity,
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val biometric by c.settings.biometric.collectAsStateWithLifecycle()
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmLogout by remember { mutableStateOf(false) }
    val canUseBiometrics = biometric && biometricsAvailable(context)

    LaunchedEffect(canUseBiometrics) {
        if (canUseBiometrics) unlockWithBiometrics(activity, c) { msg -> error = msg }
    }

    ScreenColumn {
        Text("Vault locked", style = MaterialTheme.typography.headlineMedium)
        Text(c.accounts.lastEmail(), style = MaterialTheme.typography.bodyMedium)
        PasswordField(password, { password = it }, "Master password", enabled = !busy)
        ErrorText(error)
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        Button(
            onClick = {
                busy = true
                error = null
                scope.launch {
                    try {
                        c.controller.unlockWithPassword(password)
                        password = ""
                    } catch (e: Exception) {
                        error = messageFor(e)
                    } finally {
                        busy = false
                    }
                }
            },
            enabled = !busy && password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Unlock") }
        if (canUseBiometrics) {
            OutlinedButton(
                onClick = { unlockWithBiometrics(activity, c) { msg -> error = msg } },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Unlock with biometrics") }
        }
        TextButton(onClick = { confirmLogout = true }, enabled = !busy) { Text("Log out of this device") }
    }
    if (confirmLogout) {
        ConfirmDialog(
            title = "Log out?",
            text = "This removes the vault from this phone. Your tokens stay on the server and on your other devices.",
            confirm = "Log out",
            onConfirm = {
                confirmLogout = false
                scope.launch { c.controller.logOut() }
            },
            onDismiss = { confirmLogout = false },
        )
    }
}
