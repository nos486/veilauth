package app.zk2fa.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.zk2fa.AppContainer
import app.zk2fa.core.otp.DEFAULT_PERIOD
import app.zk2fa.core.otp.OtpAlgorithm
import app.zk2fa.core.otp.OtpErrorCode
import app.zk2fa.core.otp.OtpException
import app.zk2fa.core.otp.OtpParams
import app.zk2fa.core.otp.OtpType
import app.zk2fa.core.otp.STEAM_DIGITS
import app.zk2fa.core.otp.parseOtpAuthUri
import app.zk2fa.core.otp.parseSecret
import app.zk2fa.core.otp.validateCounter
import app.zk2fa.core.otp.validateDigits
import app.zk2fa.core.otp.validatePeriod
import app.zk2fa.core.vault.Vault
import kotlinx.coroutines.launch

private fun number(
    text: String,
    code: OtpErrorCode,
): Long = text.trim().toLongOrNull() ?: throw OtpException(code)

@Composable
fun AddTokenScreen(
    c: AppContainer,
    vault: Vault,
    onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var uri by remember { mutableStateOf("") }
    var issuer by remember { mutableStateOf("") }
    var account by remember { mutableStateOf("") }
    var secret by remember { mutableStateOf("") }
    var type by remember { mutableStateOf(OtpType.TOTP) }
    var algorithm by remember { mutableStateOf(OtpAlgorithm.SHA1) }
    var digits by remember { mutableStateOf("6") }
    var period by remember { mutableStateOf("30") }
    var counter by remember { mutableStateOf("0") }
    var error by remember { mutableStateOf<String?>(null) }

    fun save(params: OtpParams) {
        scope.launch {
            vault.add(params)
            c.controller.afterEdit()
            onDone()
        }
    }

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onDone) { Text("Back") }
            Text("Add a token", style = MaterialTheme.typography.headlineSmall)
        }
        OutlinedTextField(
            value = uri,
            onValueChange = { uri = it },
            label = { Text("otpauth:// link (optional)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false),
        )
        if (uri.isNotBlank()) {
            Button(onClick = {
                try {
                    save(parseOtpAuthUri(uri))
                } catch (e: OtpException) {
                    error = messageFor(e)
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Add from link") }
        }
        Text("Or enter the setup key", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(issuer, { issuer = it }, label = { Text("Service (issuer)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(account, { account = it }, label = { Text("Account") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(
            value = secret,
            onValueChange = { secret = it },
            label = { Text("Secret key") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            keyboardOptions =
                KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    capitalization = KeyboardCapitalization.Characters,
                    autoCorrectEnabled = false,
                ),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OtpType.entries.forEach { t ->
                FilterChip(selected = type == t, onClick = { type = t }, label = { Text(t.wireName.uppercase()) })
            }
        }
        if (type != OtpType.STEAM) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OtpAlgorithm.entries.forEach { a ->
                    FilterChip(selected = algorithm == a, onClick = { algorithm = a }, label = { Text(a.name) })
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    digits,
                    { digits = it },
                    label = { Text("Digits") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                )
                if (type == OtpType.TOTP) {
                    OutlinedTextField(
                        period,
                        { period = it },
                        label = { Text("Period (s)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                } else {
                    OutlinedTextField(
                        counter,
                        { counter = it },
                        label = { Text("Counter") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                }
            }
        }
        ErrorText(error)
        Button(onClick = {
            try {
                val params =
                    OtpParams(
                        type = type,
                        issuer = issuer.trim(),
                        account = account.trim(),
                        secret = parseSecret(secret),
                        algorithm = if (type == OtpType.STEAM) OtpAlgorithm.SHA1 else algorithm,
                        digits = if (type == OtpType.STEAM) STEAM_DIGITS else validateDigits(type, number(digits, OtpErrorCode.INVALID_DIGITS)),
                        period = if (type == OtpType.TOTP) validatePeriod(number(period, OtpErrorCode.INVALID_PERIOD)) else DEFAULT_PERIOD,
                        counter = if (type == OtpType.HOTP) validateCounter(number(counter, OtpErrorCode.INVALID_COUNTER)) else 0,
                    )
                if (params.issuer.isEmpty() && params.account.isEmpty()) {
                    error = "Enter a service or account name."
                    return@Button
                }
                save(params)
            } catch (e: OtpException) {
                error = messageFor(e)
            }
        }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
    }
}
