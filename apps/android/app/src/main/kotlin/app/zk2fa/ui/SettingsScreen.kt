package app.zk2fa.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zk2fa.AppContainer
import app.zk2fa.BuildConfig
import app.zk2fa.data.AutoLock
import app.zk2fa.net.Network
import app.zk2fa.update.UpdateState
import kotlinx.coroutines.launch

private fun autoLockLabel(seconds: Int): String =
    when (seconds) {
        AutoLock.IMMEDIATELY -> "Immediately when the app is left"
        AutoLock.NEVER -> "Never (biometric unlock only)"
        in 1..59 -> "After $seconds seconds"
        else -> "After ${seconds / 60} minute${if (seconds >= 120) "s" else ""}"
    }

@Composable
fun SettingsScreen(
    c: AppContainer,
    activity: FragmentActivity,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val autoLock by c.settings.autoLockSeconds.collectAsStateWithLifecycle()
    val biometric by c.settings.biometric.collectAsStateWithLifecycle()
    var message by remember { mutableStateOf<String?>(null) }
    var update by remember { mutableStateOf<UpdateState>(UpdateState.Idle) }
    var confirmLogout by remember { mutableStateOf(false) }

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onDone) { Text("Back") }
            Text("Settings", style = MaterialTheme.typography.headlineSmall)
        }

        Text("Unlock", style = MaterialTheme.typography.titleMedium)
        if (biometricsAvailable(context)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Biometric unlock", Modifier.weight(1f))
                Switch(checked = biometric, onCheckedChange = { on ->
                    if (on) {
                        enableBiometricUnlock(activity, c) { err -> message = err }
                    } else {
                        disableBiometricUnlock(c)
                    }
                })
            }
        } else {
            Text("Biometric unlock needs a strong fingerprint or face sensor set up on this phone.", style = MaterialTheme.typography.bodySmall)
        }

        Text("Auto-lock", style = MaterialTheme.typography.titleMedium)
        AutoLock.choices.filter { it != AutoLock.NEVER || biometric }.forEach { seconds ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .selectable(selected = autoLock == seconds, role = Role.RadioButton, onClick = { c.settings.setAutoLockSeconds(seconds) }),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = autoLock == seconds, onClick = null)
                Text(autoLockLabel(seconds))
            }
        }
        Text("Copied codes are cleared from the clipboard after 30 seconds.", style = MaterialTheme.typography.bodySmall)

        if (c.updater.supported) {
            HorizontalDivider()
            Text("Updates", style = MaterialTheme.typography.titleMedium)
            when (val u = update) {
                is UpdateState.Available ->
                    Button(onClick = {
                        update = UpdateState.Downloading
                        scope.launch {
                            update =
                                try {
                                    c.updater.install(u.info)
                                    UpdateState.Installing
                                } catch (e: Exception) {
                                    UpdateState.Failed(messageFor(e))
                                }
                        }
                    }, modifier = Modifier.fillMaxWidth()) { Text("Install ${u.info.versionName}") }
                UpdateState.Downloading -> Text("Downloading and verifying…")
                UpdateState.Installing -> Text("Handing the update to Android…")
                else ->
                    OutlinedButton(onClick = {
                        update = UpdateState.Checking
                        scope.launch {
                            update =
                                try {
                                    c.updater.check()?.let { UpdateState.Available(it) } ?: UpdateState.UpToDate
                                } catch (e: Exception) {
                                    UpdateState.Failed(messageFor(e))
                                }
                        }
                    }, enabled = update != UpdateState.Checking, modifier = Modifier.fillMaxWidth()) { Text("Check for updates") }
            }
            when (val u = update) {
                UpdateState.UpToDate -> Text("You have the latest version.")
                is UpdateState.Failed -> ErrorText(u.reason)
                else -> Unit
            }
            Text(
                "Updates come from GitHub Releases. Each APK is checked against its published SHA-256 and must be signed with the same key as this app.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        HorizontalDivider()
        Text("Account", style = MaterialTheme.typography.titleMedium)
        Text("${c.accounts.lastEmail()} on ${Network.apiBaseUrl.host}", style = MaterialTheme.typography.bodyMedium)
        Text("Devices, password change and account deletion are in the web app for now.", style = MaterialTheme.typography.bodySmall)
        OutlinedButton(onClick = { confirmLogout = true }, modifier = Modifier.fillMaxWidth()) { Text("Log out of this device") }
        ErrorText(message)
        Text("veilauth ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", style = MaterialTheme.typography.bodySmall)
    }
    if (confirmLogout) {
        ConfirmDialog(
            title = "Log out?",
            text = "This removes the vault from this phone. Edits that were not synced yet are lost.",
            confirm = "Log out",
            onConfirm = {
                confirmLogout = false
                scope.launch { c.controller.logOut() }
            },
            onDismiss = { confirmLogout = false },
        )
    }
}
