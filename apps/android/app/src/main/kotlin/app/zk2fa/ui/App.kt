package app.zk2fa.ui

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zk2fa.AppContainer
import app.zk2fa.Phase
import app.zk2fa.core.vault.Vault

private enum class Screen { VAULT, ADD, SCAN, EDIT, TRASH, SETTINGS }

@Composable
fun App(
    c: AppContainer,
    activity: FragmentActivity,
) {
    val phase by c.controller.phase.collectAsStateWithLifecycle()
    when (val p = phase) {
        Phase.SignedOut -> LoginScreen(c)
        Phase.Locked -> UnlockScreen(c, activity)
        is Phase.Unlocked -> UnlockedApp(c, p.vault, activity)
    }
}

@Composable
private fun UnlockedApp(
    c: AppContainer,
    vault: Vault,
    activity: FragmentActivity,
) {
    var screen by rememberSaveable { mutableStateOf(Screen.VAULT) }
    var editing by rememberSaveable { mutableStateOf<String?>(null) }
    val back = { screen = Screen.VAULT }
    BackHandler(enabled = screen != Screen.VAULT) { back() }
    when (screen) {
        Screen.VAULT ->
            VaultScreen(
                c = c,
                vault = vault,
                onAdd = { screen = Screen.ADD },
                onScan = { screen = Screen.SCAN },
                onEdit = {
                    editing = it
                    screen = Screen.EDIT
                },
                onTrash = { screen = Screen.TRASH },
                onSettings = { screen = Screen.SETTINGS },
            )
        Screen.ADD -> AddTokenScreen(c, vault, onDone = back)
        Screen.SCAN -> ScanScreen(c, vault, onDone = back)
        Screen.EDIT -> EditTokenScreen(c, vault, editing, onDone = back)
        Screen.TRASH -> TrashScreen(c, vault, onDone = back)
        Screen.SETTINGS -> SettingsScreen(c, activity, onDone = back)
    }
}
