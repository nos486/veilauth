package app.zk2fa.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zk2fa.AppContainer
import app.zk2fa.core.otp.secondsRemaining
import app.zk2fa.core.vault.Vault
import app.zk2fa.core.vault.VaultToken
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(
    c: AppContainer,
    vault: Vault,
    onAdd: () -> Unit,
    onScan: () -> Unit,
    onEdit: (String) -> Unit,
    onTrash: () -> Unit,
    onSettings: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val version by c.store.version.collectAsStateWithLifecycle()
    val notice by c.controller.notice.collectAsStateWithLifecycle()
    val syncing by c.controller.syncing.collectAsStateWithLifecycle()
    var tokens by remember { mutableStateOf<List<VaultToken>?>(null) }
    var query by remember { mutableStateOf("") }
    val now by produceState(System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1000 - value % 1000)
        }
    }
    LaunchedEffect(version) { tokens = vault.tokens() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("veilauth") },
                actions = {
                    TextButton(onClick = { scope.launch { c.controller.syncNow() } }, enabled = !syncing) { Text(if (syncing) "Syncing" else "Sync") }
                    TextButton(onClick = onSettings) { Text("Settings") }
                    TextButton(onClick = { c.controller.lock() }) { Text("Lock") }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Button(onClick = onScan, modifier = Modifier.weight(1f)) { Text("Scan QR") }
                Button(onClick = onAdd, modifier = Modifier.weight(1f)) { Text("Enter key") }
            }
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            notice?.let { code ->
                Card(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                ) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(noticeText(code), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        TextButton(onClick = { c.controller.clearNotice() }) { Text("OK") }
                    }
                }
            }
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search") },
                singleLine = true,
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
            )
            val all = tokens
            val live = all.orEmpty().filter { it.token.trashedAt == null }
            val shown =
                live.filter {
                    query.isBlank() || it.token.issuer.contains(query, ignoreCase = true) || it.token.account.contains(query, ignoreCase = true)
                }
            when {
                all == null -> LinearProgressIndicator(Modifier.fillMaxWidth().padding(16.dp))
                live.isEmpty() ->
                    Text(
                        "No tokens yet. Scan a QR code from a website, or enter its setup key.",
                        Modifier.padding(24.dp),
                    )
                else ->
                    LazyColumn(
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(shown, key = { it.id }) { entry ->
                            TokenRow(
                                entry = entry,
                                now = now,
                                onCopy = { code ->
                                    c.clipboard.copySensitive(code)
                                    scope.launch { snackbar.showSnackbar("Copied. The clipboard is cleared in 30 seconds.") }
                                },
                                onNextHotp = {
                                    scope.launch {
                                        vault.advanceHotp(entry)
                                        c.controller.afterEdit()
                                    }
                                },
                                onEdit = { onEdit(entry.id) },
                            )
                        }
                        val trashed = all.size - live.size
                        if (trashed > 0) {
                            item {
                                TextButton(onClick = onTrash) { Text("Trash ($trashed)") }
                            }
                        }
                    }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun TokenRow(
    entry: VaultToken,
    now: Long,
    onCopy: (String) -> Unit,
    onNextHotp: () -> Unit,
    onEdit: () -> Unit,
) {
    val t = entry.token
    val code = codeFor(t, now)
    val name = title(t)
    Card(
        Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClickLabel = "Copy code",
                onLongClickLabel = "Edit",
                onClick = { if (code != null) onCopy(code) },
                onLongClick = onEdit,
            ),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text((if (t.favorite) "★ " else "") + name, fontWeight = FontWeight.SemiBold)
                    if (t.issuer.isNotEmpty() && t.account.isNotEmpty()) Text(t.account, style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = onEdit) { Text("Edit") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (code == null) "Invalid secret" else groupCode(code),
                    style = MaterialTheme.typography.headlineMedium,
                    fontFamily = FontFamily.Monospace,
                    modifier =
                        Modifier
                            .weight(1f)
                            .semantics { contentDescription = "Code for $name: ${code?.toList()?.joinToString(" ") ?: "unavailable"}" },
                )
                if (t.type == "hotp") {
                    TextButton(onClick = onNextHotp) { Text("Next code") }
                } else {
                    val period = if (t.type == "steam") 30 else t.period
                    val left = secondsRemaining(now, period)
                    Text("${left}s", style = MaterialTheme.typography.bodyMedium)
                }
            }
            if (t.type != "hotp") {
                val period = if (t.type == "steam") 30 else t.period
                LinearProgressIndicator(
                    progress = { secondsRemaining(now, period) / period.toFloat() },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (entry.pending) Text("Not synced yet", style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
fun ConfirmDialog(
    title: String,
    text: String,
    confirm: String,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
