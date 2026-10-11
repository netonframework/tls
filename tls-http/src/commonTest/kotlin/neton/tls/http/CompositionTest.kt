package neton.tls.http

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
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
import neton.http.h1.HttpService
import neton.io.bytes.Bytes
import neton.io.net.listen
import neton.io.net.runReactor
import neton.openssl.TlsContext
import neton.tls.tlsAccept
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * HTTP over TLS over TCP on the reactor, every layer real (SPEC §10): bodies far larger than a TLS record, a flow-control
 * window and the socket buffers arrive intact both ways; a client that stops reading holds the server's body back; a
 * response the client drops, or one the server fails, ends without leaving the other side producing or waiting. Each
 * on HTTP/2 and HTTP/1.1 (chosen by ALPN).
 */
abstract class CompositionTest(private val alpn: List<String>, private val version: Version) {
    private val identity = testIdentity()

    /** A body of endless [CHUNK]-sized frames, failing once [failAfter] bytes were taken; counts what was taken. */
    private class Endless(private val failAfter: Long = Long.MAX_VALUE) : Body {
        var taken = 0L
        override suspend fun nextFrame(): Frame? {
            if (taken >= failAfter) throw IllegalStateException("the body failed")
            taken += CHUNK
            return Frame.Data(Bytes.wrap(ByteArray(CHUNK) { it.toByte() }))
        }
    }

    private class Server(val port: Int) {
        var accepted = 0
        var ended = 0
        var endless: Endless? = null
    }

    /**
     * `/big` answers [BIG] patterned bytes, `/upload` the length and checksum of the request body, `/endless` and
     * `/fail` an [Endless] body (the latter failing after 1 MiB).
     */
    private suspend fun CoroutineScope.server(): Server {
        val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key, alpnProtocols = alpn)
        val listener = listen("127.0.0.1", 0)
        val s = Server(listener.localAddress.port)
        val service = HttpService { req ->
            val body: Body = when (req.uri.path) {
                "/big" -> FullBody(Bytes.wrap(pattern(BIG)))
                "/upload" -> { val (n, sum) = req.body.digest(); FullBody(Bytes.wrap("$n $sum".encodeToByteArray())) }
                "/endless" -> Endless().also { s.endless = it }
                "/fail" -> Endless(failAfter = 1 shl 20).also { s.endless = it }
                else -> EmptyBody
            }
            Response.builder().body(body)
        }
        launch {
            try {
                while (true) {
                    val tcp = listener.accept()
                    s.accepted++
                    launch {
                        try {
                            val tls = tlsAccept(tcp, context)
                            AutoServerConfig().serveConnection(tls, tls.alpn, service).serve()
                        } catch (_: Exception) {
                        } finally {
                            s.ended++
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

    private fun test(block: suspend CoroutineScope.(Server, Client) -> Unit) = runReactor {
        withTimeout(60.seconds) {
            coroutineScope {
                val s = server()
                val tls = TlsContext(server = false, trustRootsPem = identity.certificate, alpnProtocols = listOf("h2", "http/1.1"))
                val client = Client.builder().build(this, HttpsConnector(tls))
                block(s, client)
                client.close()
                tls.close()
                coroutineContext[Job]!!.children.forEach { it.cancel() }
            }
        }
    }

    private suspend fun Client.get(s: Server, path: String) =
        request(Request.get("https://localhost:${s.port}$path").body(EmptyBody as Body)).also { assertEquals(version, it.version) }

    /** Waits until the server's [Endless] body stops being taken from; returns how much was taken. */
    private suspend fun settled(s: Server): Long {
        var last = -1L
        while (true) {
            delay(500)
            val now = s.endless!!.taken
            if (now == last) return now
            last = now
        }
    }

    @Test
    fun largeBodiesCrossEveryLayerIntact() = test { s, client ->
        val (n, sum) = client.get(s, "/big").body.digest()
        assertEquals(BIG.toLong() to checksum(pattern(BIG)), n to sum)
        val upload = Request.post("https://localhost:${s.port}/upload").body(FullBody(Bytes.wrap(pattern(BIG))) as Body)
        assertEquals("$BIG ${checksum(pattern(BIG))}", client.request(upload).body.text())
        assertEquals(1, s.accepted, "one connection carried everything")
    }

    @Test
    fun aClientThatStopsReadingHoldsTheServerBack() = test { s, client ->
        val body = client.get(s, "/endless").body
        repeat(4) { body.nextFrame() }
        val held = settled(s)
        assertTrue(held < HELD_BOUND, "the server took $held bytes of an endless body while the client read none")
        // Reading again lets it go on.
        var read = 0L
        while (read < 4L * HELD_BOUND) read += (body.nextFrame() as Frame.Data).bytes.size
        assertTrue(s.endless!!.taken > held + 3L * HELD_BOUND)
        body.close()
    }

    @Test
    fun aDroppedResponseStopsTheServer() = test { s, client ->
        val body = client.get(s, "/endless").body
        repeat(4) { body.nextFrame() }
        body.close()
        val taken = settled(s)
        assertTrue(taken < HELD_BOUND, "the server took $taken bytes after the client dropped the body")
        // HTTP/2 resets the stream and gives its window back: the same connection carries on. HTTP/1 cannot skip the
        // rest of a body, so its connection is closed rather than left with the server stuck writing.
        if (version == Version.HTTP_2) assertEquals(0, s.ended) else assertEquals(1, s.ended, "the connection was closed")
        assertEquals(BIG.toLong(), client.get(s, "/big").body.digest().first)
        assertEquals(if (version == Version.HTTP_2) 1 else 2, s.accepted)
    }

    @Test
    fun aResponseTheServerFailsEndsWithAnErrorNotATruncatedBody() = test { s, client ->
        val body = client.get(s, "/fail").body
        val outcome = runCatching { body.digest() }
        assertTrue(outcome.isFailure, "the body ended normally after ${outcome.getOrNull()?.first} bytes")
        // The client carries on.
        assertEquals(BIG.toLong(), client.get(s, "/big").body.digest().first)
    }

    companion object {
        const val CHUNK = 64 * 1024
        const val BIG = 8 * 1024 * 1024 + 123
        /** Far above the window and socket buffers, far below what an unchecked producer reaches in a second. */
        const val HELD_BOUND = 32L * 1024 * 1024

        fun pattern(n: Int) = ByteArray(n) { (it * 31 + (it shr 13)).toByte() }

        fun checksum(bytes: ByteArray): Long {
            var h = 1125899906842597L
            for (b in bytes) h = 31 * h + b
            return h
        }

        /** Reads [this] to its end: its length and [checksum]. */
        suspend fun Body.digest(): Pair<Long, Long> {
            var n = 0L
            var h = 1125899906842597L
            while (true) {
                val f = nextFrame() ?: break
                if (f !is Frame.Data) continue
                val b = f.bytes.toByteArray()
                for (x in b) h = 31 * h + x
                n += b.size
            }
            return n to h
        }

        suspend fun Incoming.text(): String {
            val sb = StringBuilder()
            while (true) {
                val f = nextFrame() ?: break
                if (f is Frame.Data) sb.append(f.bytes.toByteArray().decodeToString())
            }
            return sb.toString()
        }
    }
}

class CompositionTestHttp2 : CompositionTest(listOf("h2", "http/1.1"), Version.HTTP_2)

class CompositionTestHttp1 : CompositionTest(listOf("http/1.1"), Version.HTTP_11)
