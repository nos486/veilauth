package app.zk2fa.core.vault

import app.zk2fa.core.crypto.TokenItem
import app.zk2fa.core.crypto.canonicalJson

/** Appended to the account name of the copy kept when two devices edited one token (build spec §5.3). */
public const val CONFLICT_SUFFIX: String = " (conflicted copy)"

public sealed interface TokenResolution {
    /** both sides are the same: drop the local change */
    public data object Same : TokenResolution

    /** HOTP on both sides: keep the local edit with the higher counter, on top of the server copy */
    public data class Merge(
        val value: TokenItem,
    ) : TokenResolution

    /** keep the server copy as is and save the local version as a new token */
    public data class Copy(
        val value: TokenItem,
    ) : TokenResolution
}

/** Decides how to reconcile a locally edited token with a different server version. Never drops a token. */
public fun resolveTokenConflict(
    local: TokenItem,
    server: TokenItem,
): TokenResolution {
    if (canonicalJson(local.toJson()) == canonicalJson(server.toJson())) return TokenResolution.Same
    if (local.type == "hotp" && server.type == "hotp" && local.secret == server.secret) {
        return TokenResolution.Merge(local.copy(counter = maxOf(local.counter, server.counter)))
    }
    val account = if (local.account.endsWith(CONFLICT_SUFFIX)) local.account else (local.account + CONFLICT_SUFFIX).take(256)
    return TokenResolution.Copy(local.copy(account = account))
}
