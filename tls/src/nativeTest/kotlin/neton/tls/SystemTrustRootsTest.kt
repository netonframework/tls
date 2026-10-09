@file:OptIn(kotlin.experimental.ExperimentalNativeApi::class)

package neton.tls

import neton.openssl.TlsContext
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SystemTrustRootsTest {
    @Test
    fun theSystemHasRootsThatLoadIntoAClientContext() {
        if (Platform.osFamily == OsFamily.IOS) {
            assertFailsWith<UnsupportedOperationException> { systemTrustRootsPem() }
            return
        }
        val pem = systemTrustRootsPem()
        val count = pemCertificates(pem).size
        println("system roots: $count")
        // Every desktop and server system ships well over a hundred; a handful would mean a reader stopped early
        assertTrue(count > 20, "only $count system roots")
        // Each one once, and the bundle loads as trust roots
        assertEquals(count, pemCertificates(pem).map { it.asList() }.toSet().size)
        TlsContext(server = false, trustRootsPem = pem, alpnProtocols = listOf("h2", "http/1.1")).close()
    }

    @Test
    fun pemReadingSkipsWhatIsNotACertificate() {
        val identity = testIdentity()
        val der = pemCertificates(identity.certificate).single()
        // Android's files put a text dump before the block; other blocks are skipped
        val text = "Certificate:\n    Data: ...\n".encodeToByteArray() + identity.certificate + identity.key
        assertContentEquals(der, pemCertificates(text).single())
        assertEquals(0, pemCertificates(ByteArray(0)).size)
        assertEquals(0, pemCertificates("no certificates".encodeToByteArray()).size)
        assertEquals(0, pemDirectory("/no/such/directory").size)
        assertEquals(null, readFileOrNull("/no/such/file"))
    }
}
