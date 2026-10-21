package app.zk2fa.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.zk2fa.AppContainer
import app.zk2fa.core.otp.BatchAddResult
import app.zk2fa.core.otp.MigrationBatch
import app.zk2fa.core.otp.MigrationEntry
import app.zk2fa.core.otp.OtpException
import app.zk2fa.core.otp.OtpParams
import app.zk2fa.core.otp.decodeMigrationUri
import app.zk2fa.core.otp.parseOtpAuthUri
import app.zk2fa.core.vault.Vault
import com.google.mlkit.vision.barcode.BarcodeScanner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.concurrent.Executors

private fun qrScanner(): BarcodeScanner =
    BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())

/** What a scanned QR code turned into. */
private sealed interface Scanned {
    data class Single(
        val params: OtpParams,
    ) : Scanned

    data class Batch(
        val ok: List<OtpParams>,
        val failed: Int,
    ) : Scanned
}

@Composable
fun ScanScreen(
    c: AppContainer,
    vault: Vault,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val scanner = remember { qrScanner() }
    val batch = remember { MigrationBatch() }
    var hasCamera by remember { mutableStateOf(granted(context)) }
    var status by remember { mutableStateOf<String?>(null) }
    var result by remember { mutableStateOf<Scanned?>(null) }
    var lastRaw by remember { mutableStateOf<String?>(null) }

    DisposableEffect(Unit) { onDispose { scanner.close() } }

    fun handle(raw: String) {
        if (result != null || raw == lastRaw) return
        lastRaw = raw
        try {
            if (raw.trim().startsWith("otpauth-migration:", ignoreCase = true)) {
                when (val r = batch.add(decodeMigrationUri(raw))) {
                    is BatchAddResult.Incomplete -> status = "Export ${r.received} of ${r.total} scanned. Scan the next QR code."
                    is BatchAddResult.Duplicate -> status = "Already scanned (${r.received} of ${r.total})."
                    is BatchAddResult.Complete ->
                        result =
                            Scanned.Batch(
                                ok = r.entries.filterIsInstance<MigrationEntry.Ok>().map { it.value },
                                failed = r.entries.count { it is MigrationEntry.Failed },
                            )
                }
            } else {
                result = Scanned.Single(parseOtpAuthUri(raw))
            }
        } catch (e: OtpException) {
            status = messageFor(e)
        }
    }

    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { hasCamera = it }
    val picker =
        rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri: Uri? ->
            if (uri == null) return@rememberLauncherForActivityResult
            val image =
                try {
                    InputImage.fromFilePath(context, uri)
                } catch (e: IOException) {
                    status = "That image could not be opened."
                    return@rememberLauncherForActivityResult
                }
            scanner
                .process(image)
                .addOnSuccessListener { codes ->
                    val raw = codes.firstNotNullOfOrNull { it.rawValue }
                    if (raw == null) status = "No QR code found in that image." else handle(raw)
                }.addOnFailureListener { status = "No QR code found in that image." }
        }

    ScreenColumn {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onDone) { Text("Back") }
            Text("Scan a QR code", style = MaterialTheme.typography.headlineSmall)
        }
        when (val r = result) {
            null -> {
                if (hasCamera) {
                    CameraPreview(scanner, onCode = ::handle)
                } else {
                    Text("Camera access is needed to scan. The camera image is processed on this phone only.")
                    Button(onClick = { permission.launch(Manifest.permission.CAMERA) }, modifier = Modifier.fillMaxWidth()) { Text("Allow camera") }
                }
                OutlinedButton(
                    onClick = { picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Pick a screenshot instead") }
                Text("Google Authenticator exports (Transfer accounts) work too, one QR code after another.", style = MaterialTheme.typography.bodySmall)
            }
            is Scanned.Single -> {
                Text("Add ${r.params.issuer.ifEmpty { "this token" }}${if (r.params.account.isNotEmpty()) " (${r.params.account})" else ""}?")
                Button(onClick = {
                    scope.launch {
                        vault.add(r.params)
                        c.controller.afterEdit()
                        onDone()
                    }
                }, modifier = Modifier.fillMaxWidth()) { Text("Add token") }
                OutlinedButton(onClick = {
                    result = null
                    lastRaw = null
                }, modifier = Modifier.fillMaxWidth()) { Text("Scan again") }
            }
            is Scanned.Batch -> {
                Text("Found ${r.ok.size} token(s) in the export." + if (r.failed > 0) " ${r.failed} could not be imported (unsupported settings)." else "")
                Button(onClick = {
                    scope.launch {
                        r.ok.forEach { vault.add(it) }
                        c.controller.afterEdit()
                        onDone()
                    }
                }, enabled = r.ok.isNotEmpty(), modifier = Modifier.fillMaxWidth()) { Text("Import ${r.ok.size}") }
            }
        }
        ErrorText(status)
    }
}

private fun granted(context: Context): Boolean =
    ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

@androidx.annotation.OptIn(ExperimentalGetImage::class)
@Composable
private fun CameraPreview(
    scanner: BarcodeScanner,
    onCode: (String) -> Unit,
) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val view = remember { PreviewView(context) }
    DisposableEffect(owner) {
        val future = ProcessCameraProvider.getInstance(context)
        val main = ContextCompat.getMainExecutor(context)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.setSurfaceProvider(view.surfaceProvider) }
            val analysis =
                ImageAnalysis
                    .Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
            analysis.setAnalyzer(executor) { proxy ->
                val media = proxy.image
                if (media == null) {
                    proxy.close()
                    return@setAnalyzer
                }
                scanner
                    .process(InputImage.fromMediaImage(media, proxy.imageInfo.rotationDegrees))
                    .addOnSuccessListener(main) { codes -> codes.firstNotNullOfOrNull { it.rawValue }?.let(onCode) }
                    .addOnCompleteListener { proxy.close() }
            }
            provider.unbindAll()
            provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        }, main)
        onDispose {
            if (future.isDone) future.get().unbindAll()
            executor.shutdown()
        }
    }
    AndroidView(
        factory = { view },
        modifier =
            Modifier
                .fillMaxWidth()
                .aspectRatio(1f),
    )
}
