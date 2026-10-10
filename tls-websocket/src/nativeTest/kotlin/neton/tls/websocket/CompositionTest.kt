package neton.tls.websocket

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Buffer
import neton.io.core.IoStream
import neton.io.net.connect as tcpConnect
import neton.io.net.listen
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.tls.tlsAccept
import neton.tls.tlsConnect
import neton.websocket.Message
import neton.websocket.WebSocket
import neton.websocket.WebSocketException
import neton.websocket.accept
import neton.websocket.connect
import neton.websocket.frame.CloseCode
import neton.websocket.frame.CloseFrame
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * wss over TLS over TCP on the reactor, every layer real (SPEC §10): messages far larger than a TLS record and the
 * socket buffers arrive intact; a server that stops reading holds the client's sends back; a close and a connection cut
 * without one reach the other side as such.
 */
class CompositionTest {
    private val identity = testIdentity()

    /** A wss server on 127.0.0.1 running [session] on each connection (with its TLS stream); returns its port. */
    private suspend fun CoroutineScope.server(session: suspend (WebSocket, IoStream) -> Unit): Int {
        val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key,
            alpnProtocols = listOf("http/1.1"))
        val listener = listen("127.0.0.1", 0)
        launch {
            try {
                while (true) {
                    val tcp = listener.accept()
                    launch {
                        try {
                            val tls = tlsAccept(tcp, context)
                            session(accept(tls), tls)
                        } catch (_: Exception) {
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

    private fun test(block: suspend CoroutineScope.(TlsContext) -> Unit) = runReactor {
        withTimeout(60.seconds) {
            coroutineScope {
                val tls = TlsContext(server = false, trustRootsPem = identity.certificate, alpnProtocols = listOf("http/1.1"))
                block(tls)
                tls.close()
                coroutineContext[Job]!!.children.forEach { it.cancel() }
            }
        }
    }

    private suspend fun connectTo(port: Int, tls: TlsContext) = connect("wss://localhost:$port/", tlsConnector = WssConnector(tls)).first

    @Test
    fun largeMessagesCrossEveryLayerIntact() = test { tls ->
        val port = server { ws, _ ->
            while (true) {
                val m = ws.receive() ?: break
                if (m is Message.Binary) ws.send(m)
            }
        }
        val ws = connectTo(port, tls)
        for (size in listOf(BIG, 1, BIG / 3)) {
            val sent = pattern(size, seed = size)
            ws.send(Message.binary(sent))
            val got = assertIs<Message.Binary>(ws.receive()).data.toByteArray()
            assertTrue(sent.contentEquals(got), "a $size-byte message came back different")
        }
        ws.close()
    }

    @Test
    fun aServerThatStopsReadingHoldsTheClientBack() = test { tls ->
        val reading = CompletableDeferred<Unit>()
        var received = 0L
        val port = server { ws, _ ->
            reading.await()
            while (true) {
                val m = ws.receive() ?: break
                if (m is Message.Binary) received += m.data.size
            }
        }
        val ws = connectTo(port, tls)
        var sent = 0L
        val sender = launch {
            val chunk = Message.binary(pattern(CHUNK, seed = 7))
            while (sent < TOTAL) { ws.send(chunk); sent += CHUNK }
            ws.close()
        }
        var last = -1L
        while (sent != last) { last = sent; delay(500) }
        assertTrue(sent < HELD_BOUND, "the client got $sent bytes out while the server read none")
        assertTrue(sender.isActive, "sending is held, not finished")
        // The server reads again: everything arrives.
        reading.complete(Unit)
        sender.join()
        while (ws.receive() != null) {}
        assertEquals(TOTAL, received)
    }

    @Test
    fun aCloseReachesThePeerWithItsCode() = test { tls ->
        val port = server { ws, _ ->
            ws.close(CloseFrame(CloseCode.Away))
            while (ws.receive() != null) {}
        }
        val ws = connectTo(port, tls)
        val close = assertIs<Message.Close>(ws.receive())
        assertEquals(CloseCode.Away, close.frame?.code)
        assertNull(ws.receive(), "the connection then ends normally")
    }

    /**
     * The client closes; the server answers and, its closing handshake done, ends the transport cleanly: a raw TLS client
     * reads close_notify (EOF), not a truncation.
     */
    @Test
    fun aServerEndsTheTlsStreamWithCloseNotify() = test { tls ->
        val port = server { ws, _ -> while (ws.receive() != null) {} }
        val raw = tlsConnect(tcpConnect("127.0.0.1", port), tls, PeerIdentity.Dns("localhost"))
        val request = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        raw.write(Buffer().also { it.writeBytes(request.encodeToByteArray()) })
        // A masked close frame (all-zero mask) with code 1000.
        raw.write(Buffer().also { it.writeBytes(byteArrayOf(0x88.toByte(), 0x82.toByte(), 0, 0, 0, 0, 0x03, 0xE8.toByte())) })
        raw.flush()
        val got = Buffer()
        while (raw.read(got) >= 0) {}
        val bytes = got.readAll()
        assertTrue(bytes.decodeToString().startsWith("HTTP/1.1 101"), "the handshake was answered")
        assertEquals(0x88.toByte(), bytes[bytes.size - 4], "the close was echoed")
        raw.close()
    }

    @Test
    fun aConnectionCutWithoutACloseIsAnErrorNotAnEnd() = test { tls ->
        val port = server { _, stream -> stream.close() }
        val ws = connectTo(port, tls)
        val e = assertFailsWith<WebSocketException> { while (ws.receive() != null) {} }
        assertTrue(e !is WebSocketException.ConnectionClosed, "got $e")
    }

    companion object {
        const val BIG = 8 * 1024 * 1024 + 123
        const val CHUNK = 256 * 1024
        const val TOTAL = 64L * 1024 * 1024
        /** Far above the write buffer, TLS and socket buffers, far below [TOTAL]. */
        const val HELD_BOUND = 32L * 1024 * 1024

        fun pattern(n: Int, seed: Int) = ByteArray(n) { (it * 31 + seed + (it shr 13)).toByte() }
    }
}
