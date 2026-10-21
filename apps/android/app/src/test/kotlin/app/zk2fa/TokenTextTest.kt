package app.zk2fa

import app.zk2fa.core.crypto.TokenItem
import app.zk2fa.ui.codeFor
import app.zk2fa.ui.groupCode
import app.zk2fa.ui.title
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TokenTextTest {
    private fun token(
        type: String = "totp",
        secret: String = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
        digits: Int = 8,
    ) = TokenItem(type, "Example", "alice", secret, "SHA1", digits, 30, 1, null, null, emptyList(), "", false, 0, null)

    @Test
    fun `codes match RFC 6238 and 4226`() {
        assertEquals("94287082", codeFor(token(), 59_000))
        assertEquals("287082", codeFor(token(digits = 6), 59_000))
        assertEquals("287082", codeFor(token(type = "hotp", digits = 6), 0))
    }

    @Test
    fun `a broken secret shows no code`() {
        assertNull(codeFor(token(secret = "not base32!"), 0))
    }

    @Test
    fun `codes are grouped for reading`() {
        assertEquals("123 456", groupCode("123456"))
        assertEquals("1234 5678", groupCode("12345678"))
        assertEquals("HFDGV", groupCode("HFDGV"))
        assertEquals("Example", title(token()))
    }
}
