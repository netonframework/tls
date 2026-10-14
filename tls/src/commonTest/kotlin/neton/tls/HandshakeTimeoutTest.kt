package neton.tls

import kotlinx.coroutines.async
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import neton.io.bytes.Buffer
import neton.io.core.IoException
import neton.io.core.memoryStreamPair
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The handshake limit of tlsConnect / tlsAccept (SPEC §9): a peer that connects and then sends nothing (or too little)
 * does not hold the stream and the engine; the stream is closed and the caller gets [TlsHandshakeTimeoutException].
 */
class HandshakeTimeoutTest {
    private val identity = testIdentity()

    @Test
    fun outerTimeoutIsNotReportedAsAHandshakeTimeout() = runReactor {
        withTimeout(10.seconds) {
            val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key)
            try {
                for (limit in listOf(0L, 5_000L)) {
                    val (peer, stream) = memoryStreamPair()
                    try {
                        assertNull(withTimeoutOrNull(100) {
                            tlsAccept(stream, context, handshakeTimeoutMillis = limit)
                        })
                        assertEquals(-1, drain(peer))
                    } finally { stream.close(); peer.close() }
                }
            } finally { context.close() }
        }
    }

    @Test
    fun explicitCancellationClosesTheHandshakeStream() = runReactor {
        withTimeout(10.seconds) {
            val context = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key)
            val (peer, stream) = memoryStreamPair()
            val reading = CompletableDeferred<Unit>()
            val tracked = object : neton.io.core.IoStream by stream {
                override suspend fun read(dst: Buffer): Int { reading.complete(Unit); return stream.read(dst) }
            }
            try {
                val job = launch { tlsAccept(tracked, context, handshakeTimeoutMillis = 0) }
                reading.await()
                job.cancelAndJoin()
                assertEquals(-1, drain(peer))
            } finally { stream.close(); peer.close(); context.close() }
        }
    }

    /** Reads everything [peer] sends until it ends; returns how it ended (-1 at EOF). */
    private suspend fun drain(peer: neton.io.core.IoStream): Int {
        while (true) {
            val n = try { peer.read(Buffer()) } catch (_: IoException) { return -2 }
            if (n < 0) return n
        }
    }

    @Test
    fun aServerGivesUpOnAClientThatSendsNothing() = runReactor {
        withTimeout(10.seconds) {
            val (silentClient, serverSide) = memoryStreamPair()
            val server = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key)
            val start = TimeSource.Monotonic.markNow()
            val e = assertFailsWith<TlsHandshakeTimeoutException> { tlsAccept(serverSide, server, handshakeTimeoutMillis = 200) }
            val took = start.elapsedNow()
            assertEquals(200L, e.timeoutMillis)
            assertTrue(took.inWholeMilliseconds in 150..2000, "gave up after $took")
            assertEquals(-1, drain(silentClient), "the server's side of the stream was closed")
            server.close()
        }
    }

    @Test
    fun aClientGivesUpOnAServerThatNeverAnswers() = runReactor {
        withTimeout(10.seconds) {
            val (clientSide, mute) = memoryStreamPair()
            val client = TlsContext(server = false, trustRootsPem = identity.certificate)
            coroutineScope {
                // The "server" takes the ClientHello and never answers.
                val swallowed = async { drain(mute) }
                assertFailsWith<TlsHandshakeTimeoutException> {
                    tlsConnect(clientSide, client, PeerIdentity.Dns("localhost"), handshakeTimeoutMillis = 200)
                }
                assertEquals(-1, swallowed.await(), "the client's side of the stream was closed")
            }
            client.close()
        }
    }

    @Test
    fun noLimitWithZeroAndAHandshakeWithinTheLimitSucceeds() = runReactor {
        withTimeout(10.seconds) {
            val server = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key)
            val client = TlsContext(server = false, trustRootsPem = identity.certificate)
            for (limit in listOf(0L, 5_000L)) {
                val (a, b) = memoryStreamPair()
                coroutineScope {
                    val accepted = async { tlsAccept(b, server, handshakeTimeoutMillis = limit) }
                    val tls = tlsConnect(a, client, PeerIdentity.Dns("localhost"), handshakeTimeoutMillis = limit)
                    val peer = accepted.await()
                    launch { tls.write(Buffer().also { it.writeBytes("ping".encodeToByteArray()) }) }
                    val got = Buffer()
                    while (got.readableBytes < 4) peer.read(got)
                    assertEquals("ping", got.readAll().decodeToString())
                    tls.close(); peer.close()
                }
            }
            assertEquals(10_000L, DEFAULT_HANDSHAKE_TIMEOUT_MILLIS)
            server.close(); client.close()
        }
    }
}
