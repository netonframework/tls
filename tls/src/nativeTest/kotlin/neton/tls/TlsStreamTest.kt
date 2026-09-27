package neton.tls

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Buffer
import neton.io.core.ClosedException
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.core.memoryStreamPair
import neton.io.net.connect
import neton.io.net.listen
import neton.io.net.runReactor
import neton.io.testkit.IoStreamConformance
import neton.io.testkit.StreamPair
import neton.openssl.ClientAuthentication
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.openssl.TlsFailureKind
import neton.openssl.TlsVersion
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** SPEC §4. Ports below 32768 (outside the ephemeral range). */
class TlsStreamTest {
    private val identity = testIdentity()

    private class Contexts(val client: TlsContext, val server: TlsContext) {
        fun close() { client.close(); server.close() }
    }

    private fun contexts(
        version: TlsVersion = TlsVersion.TLS13, id: TestIdentity = identity, roots: ByteArray = id.certificate,
        clientAlpn: List<String> = listOf("http/1.1", "h2"), serverAlpn: List<String> = listOf("h2", "http/1.1"),
        auth: ClientAuthentication = ClientAuthentication.NONE, clientId: TestIdentity? = null,
    ) = Contexts(
        TlsContext(false, roots, clientId?.certificate, clientId?.key, version, version, clientAlpn),
        TlsContext(true, clientId?.certificate ?: roots, id.certificate, id.key, version, version, serverAlpn, auth),
    )

    private var nextPort = 22600

    private suspend fun tcpRaw(): Pair<IoStream, IoStream> {
        val port = nextPort++
        val l = listen("127.0.0.1", port)
        val a = connect("127.0.0.1", port)
        val b = l.accept()
        l.close()
        return a to b
    }

    /** Client and server TLS over [raw], handshaken concurrently. */
    private suspend fun tls(
        raw: Pair<IoStream, IoStream>, c: Contexts, peer: PeerIdentity = PeerIdentity.Dns("localhost"), buffer: Int = DEFAULT_BUFFER,
    ): Pair<TlsStream, TlsStream> =
        coroutineScope {
            val server = async { tlsAccept(raw.second, c.server, buffer) }
            val client = tlsConnect(raw.first, c.client, peer, buffer)
            client to server.await()
        }

    private fun buf(bytes: ByteArray) = Buffer().also { it.writeBytes(bytes) }

    private suspend fun readExactly(s: IoStream, n: Int): ByteArray {
        val acc = Buffer()
        while (acc.readableBytes < n) { val r = Buffer(); if (s.read(r) < 0) break; acc.writeBytes(r.readAll()) }
        return acc.readAll()
    }

    // ---- conformance --------------------------------------------------------------------------

    private fun conformance(name: String, open: suspend () -> Pair<IoStream, IoStream>) = runReactor {
        val c = contexts()
        val failures = IoStreamConformance(name, {
            val (a, b) = tls(open(), c)
            StreamPair(a, b)
        }, orderlyClose = { it.shutdownOutput(); it.close() }).run()
        c.close()
        failures.forEach { println("FAIL $it") }
        assertEquals(emptyList(), failures)
    }

    @Test fun conformanceOverTcp() = conformance("tls(tcp)") { tcpRaw() }

    @Test fun conformanceOverMemory() = conformance("tls(memory)") { memoryStreamPair() }

    // ---- specific -----------------------------------------------------------------------------

    @Test
    fun tls12And13HandshakeAlpnAndData() = runReactor {
        for (v in TlsVersion.entries) {
            val c = contexts(version = v)
            val (a, b) = tls(tcpRaw(), c)
            assertEquals("h2", a.alpn); assertEquals("h2", b.alpn)
            assertEquals(if (v == TlsVersion.TLS12) "TLSv1.2" else "TLSv1.3", a.protocolVersion)
            assertEquals("localhost", b.serverName)
            assertEquals(1, a.peerCertificates().size)
            a.write(buf("ping".encodeToByteArray()))
            assertEquals("ping", readExactly(b, 4).decodeToString())
            b.write(buf("pong".encodeToByteArray()))
            assertEquals("pong", readExactly(a, 4).decodeToString())
            a.close(); b.close(); c.close()
        }
    }

    /** An inner stream that hands out at most one byte per read. */
    private class OneByte(private val inner: IoStream) : IoStream by inner {
        private val pending = Buffer()
        override suspend fun read(dst: Buffer): Int {
            if (pending.readableBytes == 0 && inner.read(pending) < 0) return -1
            dst.writeByte(pending.backingArray()[pending.readerIndex()]); pending.consume(1)
            return 1
        }
    }

    @Test
    fun oneByteFragmentsBothWays() = runReactor {
        val c = contexts()
        val (ra, rb) = tcpRaw()
        val (a, b) = tls(OneByte(ra) to OneByte(rb), c)
        val data = ByteArray(40_000) { (it * 7).toByte() }
        launch { a.write(buf(data)) }
        assertContentEquals(data, readExactly(b, data.size))
        a.close(); b.close(); c.close()
    }

    @Test fun largeTransfersBothWaysAtOnce() = bothWays(DEFAULT_BUFFER)

    /** The smallest allowed engine buffer (one whole record) still carries full-duplex traffic. */
    @Test fun largeTransfersBothWaysWithTheSmallestBuffer() = bothWays(MIN_BUFFER)

    /** Below one record, writes would need retries while the engine refuses reads: rejected (SPEC §2). */
    @Test fun bufferBelowOneRecordIsRejected() = runReactor {
        val c = contexts()
        val (a, _) = tcpRaw()
        assertFailsWith<IllegalArgumentException> { TlsStream(a, c.client.newEngine(PeerIdentity.Dns("localhost"), 16 * 1024), 16 * 1024) }
        a.close(); c.close()
    }

    private fun bothWays(buffer: Int) = runReactor {
        val c = contexts()
        val (a, b) = tls(tcpRaw(), c, buffer = buffer)
        val n = 1 shl 20
        val x = ByteArray(n) { it.toByte() }; val y = ByteArray(n) { (it * 3).toByte() }
        val w1 = launch { a.write(buf(x)) }; val w2 = launch { b.write(buf(y)) }
        val r1 = async { readExactly(b, n) }; val r2 = async { readExactly(a, n) }
        assertContentEquals(x, r1.await()); assertContentEquals(y, r2.await())
        w1.join(); w2.join()
        a.close(); b.close(); c.close()
    }

    @Test
    fun handshakeFailuresAreClassified() = runReactor {
        suspend fun fails(expected: TlsFailureKind, c: Contexts, peer: PeerIdentity = PeerIdentity.Dns("localhost")) {
            val raw = tcpRaw()
            val serverSide = async { runCatching { tlsAccept(raw.second, c.server) } }
            val e = assertFailsWith<TlsFailureException> { tlsConnect(raw.first, c.client, peer) }
            assertEquals(expected, e.kind); assertTrue(e.duringHandshake)
            serverSide.await().getOrNull()?.close()
            c.close()
        }
        fails(TlsFailureKind.HOSTNAME, contexts(), PeerIdentity.Dns("wrong.invalid"))
        fails(TlsFailureKind.CERTIFICATE, contexts(roots = testIdentity().certificate))
        fails(TlsFailureKind.EXPIRED, testIdentity(expired = true).let { contexts(id = it) })
        fails(TlsFailureKind.PROTOCOL, contexts(clientAlpn = listOf("h3")))
    }

    @Test
    fun mutualTls() = runReactor {
        val c = contexts(auth = ClientAuthentication.REQUIRE, clientId = testIdentity())
        val (a, b) = tls(tcpRaw(), c)
        a.write(buf("m".encodeToByteArray())); assertEquals("m", readExactly(b, 1).decodeToString())
        assertEquals(1, b.peerCertificates().size)
        a.close(); b.close(); c.close()
    }

    @Test
    fun closeNotifyIsEofAndBareEofIsTruncation() = runReactor {
        val c = contexts()
        val (a, b) = tls(tcpRaw(), c)
        a.write(buf("bye".encodeToByteArray()))
        a.shutdownOutput()
        assertEquals("bye", readExactly(b, 3).decodeToString())
        assertEquals(-1, b.read(Buffer()))
        // Half-close: a can still read.
        b.write(buf("ok".encodeToByteArray())); assertEquals("ok", readExactly(a, 2).decodeToString())
        a.close(); b.close()

        val (x, y) = tls(tcpRaw(), c)
        x.write(buf("cut".encodeToByteArray()))
        x.close()                                    // no close_notify
        assertEquals("cut", readExactly(y, 3).decodeToString())
        assertFailsWith<TlsTruncatedException> { y.read(Buffer()) }
        y.close(); c.close()
    }

    @Test
    fun closeWakesParkedOperationsAndCancelCloses() = runReactor {
        val c = contexts()
        val (a, b) = tls(tcpRaw(), c)
        val parked = async { runCatching { a.read(Buffer()) }.exceptionOrNull() }
        delay(50)
        a.close()
        assertTrue(parked.await() is ClosedException)
        assertFailsWith<ClosedException> { a.write(buf(byteArrayOf(1))) }

        val (p, q) = tls(tcpRaw(), c)
        val reader = launch { p.read(Buffer()) }
        delay(50); reader.cancel(); reader.join()
        assertFailsWith<ClosedException> { p.read(Buffer()) }       // no ResumableAfterCancel: closed
        b.close(); q.close(); c.close()
    }
}
