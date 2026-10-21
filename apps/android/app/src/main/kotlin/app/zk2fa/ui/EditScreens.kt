package app.zk2fa.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zk2fa.AppContainer
import app.zk2fa.core.vault.Vault
import app.zk2fa.core.vault.VaultToken
import kotlinx.coroutines.launch

@Composable
fun EditTokenScreen(
    c: AppContainer,
    vault: Vault,
    id: String?,
    onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var entry by remember { mutableStateOf<VaultToken?>(null) }
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf("") }
    var favorite by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var confirmTrash by remember { mutableStateOf(false) }

    LaunchedEffect(id) {
        val found = vault.tokens().firstOrNull { it.id == id }
        if (found == null) {
            onDone()
            return@LaunchedEffect
        }
        entry = found
        issuer = found.token.issuer
        account = found.token.account
        notes = found.token.notes
        favorite = found.token.favorite
    }
    val current = entry ?: return

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onDone) { Text("Back") }
            Text("Edit token", style = MaterialTheme.typography.headlineSmall)
        }
        OutlinedTextField(issuer, { issuer = it }, label = { Text("Service (issuer)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(account, { account = it }, label = { Text("Account") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(notes, { notes = it }, label = { Text("Notes") }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Favorite", Modifier.weight(1f))
            Switch(checked = favorite, onCheckedChange = { favorite = it })
        }
        Text(
            "${current.token.type.uppercase()} · ${current.token.algorithm} · ${current.token.digits} digits" +
                if (current.token.type == "totp") " · ${current.token.period} s" else "",
            style = MaterialTheme.typography.bodySmall,
        )
        ErrorText(error)
        Button(onClick = {
            if (issuer.length > 256 || account.length > 256 || notes.length > 2048) {
                error = "Too long: names up to 256 characters, notes up to 2048."
                return@Button
            }
            scope.launch {
                vault.save(current.id, current.token.copy(issuer = issuer.trim(), account = account.trim(), notes = notes, favorite = favorite))
                c.controller.afterEdit()
                onDone()
            }
        }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
        OutlinedButton(onClick = { confirmTrash = true }, modifier = Modifier.fillMaxWidth()) { Text("Move to trash") }
    }
    if (confirmTrash) {
        ConfirmDialog(
            title = "Move to trash?",
            text = "The token stops showing codes. You can restore it from the trash.",
            confirm = "Move to trash",
            onConfirm = {
                confirmTrash = false
                scope.launch {
                    vault.moveToTrash(current)
                    c.controller.afterEdit()
                    onDone()
                }
            },
            onDismiss = { confirmTrash = false },
        )
    }
}

@Composable
fun TrashScreen(
    c: AppContainer,
    vault: Vault,
    onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val version by c.store.version.collectAsStateWithLifecycle()
    var trashed by remember { mutableStateOf<List<VaultToken>>(emptyList()) }
    var deleting by remember { mutableStateOf<VaultToken?>(null) }
    LaunchedEffect(version) { trashed = vault.tokens().filter { it.token.trashedAt != null } }

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onDone) { Text("Back") }
            Text("Trash", style = MaterialTheme.typography.headlineSmall)
        }
        if (trashed.isEmpty()) Text("The trash is empty.")
        trashed.forEach { entry ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text(title(entry.token), style = MaterialTheme.typography.titleMedium)
                    if (entry.token.account.isNotEmpty()) Text(entry.token.account, style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = {
                            scope.launch {
                                vault.restore(entry)
                                c.controller.afterEdit()
                            }
                        }) { Text("Restore") }
                        TextButton(onClick = { deleting = entry }) { Text("Delete forever") }
                    }
                }
            }
        }
    }
    deleting?.let { entry ->
        ConfirmDialog(
            title = "Delete forever?",
            text = "\"${title(entry.token)}\" is removed from all your devices. Make sure 2FA is turned off or moved for that account first, or you may be locked out.",
            confirm = "Delete",
            onConfirm = {
                deleting = null
                scope.launch {
                    vault.deleteForever(entry.id)
                    c.controller.afterEdit()
                }
            },
            onDismiss = { deleting = null },
        )
    }
}
