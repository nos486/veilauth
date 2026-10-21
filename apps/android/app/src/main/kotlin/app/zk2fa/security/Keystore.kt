package app.zk2fa.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A Keystore AES-GCM ciphertext: the IV is chosen by the Keystore (randomized encryption). */
class Sealed(
    val iv: ByteArray,
    val ciphertext: ByteArray,
)

/**
 * Android Keystore keys. Key material never leaves secure hardware (TEE/StrongBox where present).
 *  - [SESSION]: no user authentication; protects the refresh token at rest.
 *  - [BIOMETRIC]: every use needs a strong biometric; invalidated when a new fingerprint/face is
 *    enrolled. Wraps the vault key for biometric unlock.
 */
object Keystore {
    private const val PROVIDER = "AndroidKeyStore"
    private const val SESSION = "veilauth.session.v1"
    private const val BIOMETRIC = "veilauth.biometric.v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"

    private fun keyStore(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun existing(alias: String): SecretKey? = keyStore().getKey(alias, null) as? SecretKey

    private fun generate(
        alias: String,
        biometric: Boolean,
    ): SecretKey {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
        if (biometric) {
            spec.setUserAuthenticationRequired(true)
            spec.setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec.build())
        return generator.generateKey()
    }

    private fun sessionKey(): SecretKey = existing(SESSION) ?: generate(SESSION, biometric = false)

    fun sealSession(plaintext: ByteArray): Sealed {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey())
        return Sealed(cipher.iv, cipher.doFinal(plaintext))
    }

    fun openSession(sealed: Sealed): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, sessionKey(), GCMParameterSpec(128, sealed.iv))
        return cipher.doFinal(sealed.ciphertext)
    }

    /** Cipher to pass to BiometricPrompt for wrapping the vault key; creates a fresh key. */
    fun biometricEncryptCipher(): Cipher {
        deleteBiometricKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, generate(BIOMETRIC, biometric = true))
        return cipher
    }

    /**
     * Cipher to pass to BiometricPrompt for unwrapping. Throws
     * `KeyPermanentlyInvalidatedException` after a biometric enrollment change.
     */
    fun biometricDecryptCipher(iv: ByteArray): Cipher? {
        val key = existing(BIOMETRIC) ?: return null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return cipher
    }

    fun deleteBiometricKey() {
        val ks = keyStore()
        if (ks.containsAlias(BIOMETRIC)) ks.deleteEntry(BIOMETRIC)
    }
}
