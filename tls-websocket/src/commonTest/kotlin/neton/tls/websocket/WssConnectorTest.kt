package neton.tls.websocket

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.net.listen
import neton.io.net.runReactor
import neton.openssl.TlsContext
import neton.tls.TlsFailureException
import neton.tls.tlsAccept
import neton.websocket.Message
import neton.websocket.accept
import neton.websocket.connect
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** wss through WssConnector against an echo server on this stack (tlsAccept + websocket accept). */
class WssConnectorTest {
    private val identity = testIdentity()

    /** A wss echo server on 127.0.0.1; returns its port. */
    private suspend fun CoroutineScope.echoServer(): Int {
        val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key,
            alpnProtocols = listOf("http/1.1"))
        val listener = listen("127.0.0.1", 0)
        launch {
            try {
                while (true) {
                    val tcp = listener.accept()
                    launch {
                        try {
                            val ws = accept(tlsAccept(tcp, context))
                            while (true) {
                                val m = ws.receive() ?: break
                                if (m is Message.Text) ws.send(m)
                            }
                        } catch (e: Exception) {
                        }
                    }
                }
            } finally {
                listener.close()
                context.close()
            }
        }
        return listener.localAddress.port
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
    fun wssEchoes() = test {
        val port = echoServer()
        val tls = TlsContext(server = false, trustRootsPem = identity.certificate, alpnProtocols = listOf("http/1.1"))
        val (ws, response) = connect("wss://localhost:$port/echo", tlsConnector = WssConnector(tls))
        assertEquals(101, response.status.asU16())
        for (text in listOf("hello", "über TLS", "x".repeat(70_000))) {
            ws.send(Message.text(text))
            assertEquals(Message.text(text), ws.receive())
        }
        ws.close()
        tls.close()
    }

    @Test
    fun anUntrustedServerIsRefused() = test {
        val port = echoServer()
        val other = TlsContext(server = false, trustRootsPem = testIdentity().certificate)
        assertFailsWith<TlsFailureException> { connect("wss://localhost:$port/echo", tlsConnector = WssConnector(other)) }
        other.close()
    }

    @Test
    fun theDefaultContextUsesTheSystemRoots() {
        WssConnector().close()
    }
}
