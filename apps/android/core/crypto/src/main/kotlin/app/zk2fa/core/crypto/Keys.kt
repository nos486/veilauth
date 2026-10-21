package app.zk2fa.core.crypto

import javax.crypto.SecretKey

public fun generateVaultKeyBytes(): ByteArray = randomBytes(KEY_BYTES)

private fun wrap(
    kek: SecretKey,
    vaultKey: ByteArray,
    context: String,
): String {
    if (vaultKey.size != KEY_BYTES) throw CryptoException(CryptoErrorCode.INVALID_ENCODING, "vault key must be 32 bytes")
    return seal(kek, vaultKey, context)
}

private fun unwrap(
    kek: SecretKey,
    envelope: String,
    context: String,
): ByteArray {
    if (parseEnvelope(envelope).body.size != KEY_BYTES + TAG_BYTES) throw CryptoException(CryptoErrorCode.DECRYPT_FAILED)
    return open(kek, envelope, context)
}

/** wrappedVaultKey = Envelope(kek, vaultKey, "zk2fa/v1/vk|" + userId) */
public fun wrapVaultKey(
    kek: SecretKey,
    vaultKey: ByteArray,
    userId: String,
): String = wrap(kek, vaultKey, Ctx.vaultKey(userId))

/** Returns the raw 32-byte vault key; the caller wipes it once it is held by a key object. */
public fun unwrapVaultKey(
    kek: SecretKey,
    wrapped: String,
    userId: String,
): ByteArray = unwrap(kek, wrapped, Ctx.vaultKey(userId))

/** recoveryWrappedVaultKey = Envelope(recoveryKek, vaultKey, "zk2fa/v1/rvk|" + userId) */
public fun wrapVaultKeyForRecovery(
    recoveryKek: SecretKey,
    vaultKey: ByteArray,
    userId: String,
): String = wrap(recoveryKek, vaultKey, Ctx.recoveryVaultKey(userId))

public fun unwrapVaultKeyWithRecovery(
    recoveryKek: SecretKey,
    wrapped: String,
    userId: String,
): ByteArray = unwrap(recoveryKek, wrapped, Ctx.recoveryVaultKey(userId))
