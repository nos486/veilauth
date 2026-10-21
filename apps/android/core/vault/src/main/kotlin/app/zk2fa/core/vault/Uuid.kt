package app.zk2fa.core.vault

import app.zk2fa.core.crypto.randomBytes

/** UUIDv7 (RFC 9562): 48-bit ms timestamp, version 7, variant 10, 74 random bits. Lowercase. */
public fun uuidV7(now: Long = System.currentTimeMillis()): String {
    val b = randomBytes(16)
    var ts = now
    for (i in 5 downTo 0) {
        b[i] = (ts and 0xff).toByte()
        ts = ts ushr 8
    }
    b[6] = (0x70 or (b[6].toInt() and 0x0f)).toByte()
    b[8] = (0x80 or (b[8].toInt() and 0x3f)).toByte()
    val hex = b.joinToString("") { "%02x".format(it) }
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
}
