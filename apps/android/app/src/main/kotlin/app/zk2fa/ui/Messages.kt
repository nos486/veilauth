package app.zk2fa.ui

import app.zk2fa.UserError
import app.zk2fa.core.api.ApiException
import app.zk2fa.core.crypto.CryptoErrorCode
import app.zk2fa.core.crypto.CryptoException
import app.zk2fa.core.otp.OtpErrorCode
import app.zk2fa.core.otp.OtpException
import app.zk2fa.update.UpdateException

/** Error → sentence. Never includes the input, which may be a secret. */
fun messageFor(e: Throwable): String =
    when (e) {
        is UserError ->
            when (e.code) {
                "WRONG_PASSWORD" -> "Wrong password."
                "NO_ACCOUNT" -> "No account on this device. Log in first."
                "LOCKED" -> "The vault is locked."
                else -> "Something went wrong (${e.code})."
            }
        is ApiException ->
            when (e.code) {
                "NETWORK" -> "No connection to the server."
                "INVALID_CREDENTIALS" -> "Wrong e-mail or password."
                "RATE_LIMITED" -> "Too many attempts. Try again later."
                "ACCOUNT_LOCKED" -> "This account is temporarily locked after failed log-ins. Try again later."
                "TURNSTILE_REQUIRED", "TURNSTILE_FAILED" ->
                    "Several log-ins failed, so the server now asks for a human check that the app cannot show. Log in once on the web app, or wait an hour."
                "KDF_PARAMS_REJECTED" -> "The server asked for unsafe password settings. Refused."
                "SESSION_REVOKED", "REFRESH_REUSED", "UNAUTHORIZED" -> "You were signed out. Log in again."
                else -> "Server error (${e.code})."
            }
        is CryptoException ->
            when (e.code) {
                CryptoErrorCode.DECRYPT_FAILED -> "Wrong password, or the data was changed."
                CryptoErrorCode.KDF_PARAMS_REJECTED -> "The server asked for unsafe password settings. Refused."
                else -> "Encryption error (${e.code})."
            }
        is OtpException ->
            when (e.code) {
                OtpErrorCode.MISSING_SECRET -> "The secret key is missing."
                OtpErrorCode.INVALID_SECRET -> "The secret key is not valid base32."
                OtpErrorCode.INVALID_URI -> "Not a valid otpauth:// link."
                OtpErrorCode.UNSUPPORTED_TYPE -> "This kind of code is not supported."
                OtpErrorCode.INVALID_ALGORITHM -> "Unsupported algorithm."
                OtpErrorCode.INVALID_DIGITS -> "Digits must be 6, 7 or 8."
                OtpErrorCode.INVALID_PERIOD -> "The period must be between 1 and 86400 seconds."
                OtpErrorCode.INVALID_COUNTER -> "The counter is not valid."
                OtpErrorCode.MIGRATION_DECODE_FAILED -> "This export QR code could not be read."
                OtpErrorCode.INVALID_TIME -> "The device clock is wrong."
            }
        is UpdateException ->
            when (e.reason) {
                "HASH_MISMATCH", "SIGNATURE_MISMATCH", "WRONG_PACKAGE", "WRONG_VERSION", "NOT_AN_APK" ->
                    "The downloaded update failed verification and was deleted (${e.reason})."
                "NETWORK" -> "Could not reach GitHub."
                else -> "Update failed (${e.reason})."
            }
        else -> "Something went wrong."
    }

/** Vault-screen notices from [app.zk2fa.AppController.notice]. */
fun noticeText(code: String): String =
    when (code) {
        "SESSION_ENDED" -> "The server ended this session. Codes still work offline; unlock with your password to sign in again."
        "ROLLBACK" -> "The server sent older copies of some items. They were ignored."
        "SYNC_FAILED" -> "Sync failed. Your changes are kept and will be sent later."
        else -> code
    }
