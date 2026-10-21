package app.zk2fa.ui

import android.content.Context
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.zk2fa.AppContainer
import app.zk2fa.core.crypto.wipe
import app.zk2fa.security.Keystore
import app.zk2fa.security.Sealed
import java.security.GeneralSecurityException
import javax.crypto.Cipher

fun biometricsAvailable(context: Context): Boolean =
    BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

private fun prompt(
    activity: FragmentActivity,
    cipher: Cipher,
    title: String,
    onSuccess: (Cipher) -> Unit,
    onError: (String?) -> Unit,
) {
    val callback =
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c == null) onError("Biometric check returned no key.") else onSuccess(c)
            }

            override fun onAuthenticationError(
                errorCode: Int,
                errString: CharSequence,
            ) {
                val cancelled =
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                onError(if (cancelled) null else errString.toString())
            }
        }
    val info =
        BiometricPrompt.PromptInfo
            .Builder()
            .setTitle(title)
            .setNegativeButtonText("Use password")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build()
    BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback).authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

/** Wraps the unlocked vault key with a new biometric-bound Keystore key. */
fun enableBiometricUnlock(
    activity: FragmentActivity,
    c: AppContainer,
    onDone: (error: String?) -> Unit,
) {
    val raw = c.controller.exportKeyForBiometrics()
    val cipher =
        try {
            Keystore.biometricEncryptCipher()
        } catch (e: GeneralSecurityException) {
            wipe(raw)
            onDone("This device cannot create a biometric key.")
            return
        }
    prompt(activity, cipher, "Turn on biometric unlock", onSuccess = { ready ->
        try {
            c.accounts.saveBiometricVaultKey(Sealed(ready.iv, ready.doFinal(raw)))
            c.settings.setBiometric(true)
            onDone(null)
        } catch (e: GeneralSecurityException) {
            onDone("Biometric unlock could not be turned on.")
        } finally {
            wipe(raw)
        }
    }, onError = { msg ->
        wipe(raw)
        onDone(msg)
    })
}

fun disableBiometricUnlock(c: AppContainer) {
    c.accounts.clearBiometricVaultKey()
    c.settings.setBiometric(false)
}

/** Unwraps the vault key with the biometric Keystore key and unlocks. */
fun unlockWithBiometrics(
    activity: FragmentActivity,
    c: AppContainer,
    onError: (String?) -> Unit,
) {
    val sealed = c.accounts.biometricVaultKey()
    if (sealed == null) {
        disableBiometricUnlock(c)
        onError("Biometric unlock is not set up. Use your password.")
        return
    }
    val cipher =
        try {
            Keystore.biometricDecryptCipher(sealed.iv)
        } catch (e: KeyPermanentlyInvalidatedException) {
            disableBiometricUnlock(c)
            onError("Biometrics changed on this device, so biometric unlock was turned off. Use your password.")
            return
        } catch (e: GeneralSecurityException) {
            disableBiometricUnlock(c)
            onError("Biometric unlock is no longer available. Use your password.")
            return
        }
    if (cipher == null) {
        disableBiometricUnlock(c)
        onError("Biometric unlock is not set up. Use your password.")
        return
    }
    prompt(activity, cipher, "Unlock veilauth", onSuccess = { ready ->
        try {
            c.controller.unlockWithKey(ready.doFinal(sealed.ciphertext))
        } catch (e: GeneralSecurityException) {
            onError("Biometric unlock failed. Use your password.")
        }
    }, onError = onError)
}
