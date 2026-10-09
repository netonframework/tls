package neton.tls.http

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.http.Body
import neton.http.EmptyBody
import neton.http.Frame
import neton.http.FullBody
import neton.http.Incoming
import neton.http.Request
import neton.http.Response
import neton.http.Version
import neton.http.auto.AutoServerConfig
import neton.http.client.Client
import neton.http.client.ConnectError
import neton.http.h1.HttpService
import neton.io.bytes.Bytes
import neton.io.net.listen
import neton.io.net.runReactor
import neton.openssl.TlsContext
import neton.tls.TlsFailureException
import neton.tls.tlsAccept
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** HttpsConnector with the pooling client against this stack's own HTTPS server (tlsAccept + the auto server). */
class HttpsConnectorTest {
    private val identity = testIdentity()

    private class Server(val port: Int) {
        var accepted = 0
    }

    /** HTTPS on 127.0.0.1 offering [alpn]; each response says the protocol version it was served with. */
    private suspend fun CoroutineScope.server(alpn: List<String>): Server {
        val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key, alpnProtocols = alpn)
        val listener = listen("127.0.0.1", 0)
        val s = Server(listener.localAddress.port)
        launch {
            try {
                while (true) {
                    val tcp = listener.accept()
                    s.accepted++
                    launch {
                        try {
                            val tls = tlsAccept(tcp, context)
                            val service = HttpService { req ->
                                Response.builder().body(FullBody(Bytes.wrap("${req.version} ${req.uri.path}".encodeToByteArray())) as Body)
                            }
                            AutoServerConfig().serveConnection(tls, tls.alpn, service).serve()
                        } catch (e: Exception) {
                        }
                    }
                }
            } finally {
                listener.close()
                context.close()
            }
        }
        return s
    }

    private fun trustingTestCa(alpn: List<String> = listOf("h2", "http/1.1")) =
        TlsContext(server = false, trustRootsPem = identity.certificate, alpnProtocols = alpn)

    private suspend fun Incoming.text(): String {
        val sb = StringBuilder()
        while (true) {
            val f = nextFrame() ?: break
            if (f is Frame.Data) sb.append(f.bytes.toByteArray().decodeToString())
        }
        return sb.toString()
    }

    private suspend fun Client.getText(url: String): Pair<Version, String> {
        val r = request(Request.get(url).body(EmptyBody as Body))
        return r.version to r.body.text()
    }

    private fun test(block: suspend CoroutineScope.() -> Unit) = runReactor {
        withTimeout(30.seconds) {
            coroutineScope {
                block()
                coroutineContext[Job]!!.children.forEach { it.cancel() }
            }
        }
    }

    @Test
    fun http2ByAlpnSharesOneConnection() = test {
        val s = server(listOf("h2", "http/1.1"))
        val tls = trustingTestCa()
        val client = Client.builder().build(this, HttpsConnector(tls))
        // The first connection learns h2 by ALPN; afterwards concurrent requests share it. (A burst before any connection
        // exists may open several, as hyper-util's client does: HTTP/2 is only known once the handshake is done.)
        assertEquals(Version.HTTP_2 to "HTTP/2.0 /first", client.getText("https://localhost:${s.port}/first"))
        val results = (0 until 5).map { async { client.getText("https://localhost:${s.port}/r$it") } }.awaitAll()
        results.forEachIndexed { i, (version, body) ->
            assertEquals(Version.HTTP_2, version)
            assertEquals("HTTP/2.0 /r$i", body)
        }
        assertEquals(1, s.accepted)
        client.close()
        tls.close()
    }

    @Test
    fun http1WhenTheServerOffersOnlyHttp1() = test {
        val s = server(listOf("http/1.1"))
        val tls = trustingTestCa()
        val client = Client.builder().build(this, HttpsConnector(tls))
        repeat(3) { i ->
            val (version, body) = client.getText("https://localhost:${s.port}/s$i")
            assertEquals(Version.HTTP_11, version)
            assertEquals("HTTP/1.1 /s$i", body)
        }
        assertEquals(1, s.accepted) // kept alive and reused
        client.close()
        tls.close()
    }

    @Test
    fun anIpAddressIsVerifiedAgainstTheCertificatesIpSan() = test {
        val s = server(listOf("h2", "http/1.1"))
        val tls = trustingTestCa()
        val client = Client.builder().build(this, HttpsConnector(tls))
        assertEquals("HTTP/2.0 /ip", client.getText("https://127.0.0.1:${s.port}/ip").second)
        client.close()
        tls.close()
    }

    @Test
    fun anUntrustedServerIsRefused() = test {
        val s = server(listOf("h2", "http/1.1"))
        val other = TlsContext(server = false, trustRootsPem = testIdentity().certificate, alpnProtocols = listOf("h2"))
        val client = Client.builder().build(this, HttpsConnector(other))
        assertFailsWith<TlsFailureException> { client.getText("https://localhost:${s.port}/") }
        client.close()
        other.close()
    }

    @Test
    fun plainHttpUnlessHttpsOnly() = test {
        val client = Client.builder().build(this, HttpsConnector(trustingTestCa(), httpsOnly = true))
        assertFailsWith<ConnectError> { client.getText("http://127.0.0.1:1/") }
        client.close()
    }

    @Test
    fun theDefaultContextUsesTheSystemRoots() {
        // Loads the system's roots with ALPN h2 / http/1.1; a connection to the public Internet is not made here
        HttpsConnector().close()
    }
}
