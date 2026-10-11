package neton.tls

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Buffer
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.core.memoryStreamPair
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * A write cancelled while the inner stream was sending (SPEC §3, the IoStream contract: a cancelled write advances
 * `src` by what was sent, no more, no less), made deterministic. On a completion-based driver (Windows IOCP) the
 * kernel can finish a send while the cancellation is being delivered: the inner stream then reports the bytes as
 * sent *and* the write as cancelled. CI first saw it on IOCP (run 37925871731: the peer received 196,608 bytes while
 * `src` said 180,224, one record more); the fix is dc1e86a. The real race depends on timing, so here an inner stream
 * double reproduces both outcomes on demand:
 * - the record went out whole, then the cancellation: the peer decrypts it, so `src` must have advanced past it;
 * - the record was cut in half: it never decrypts, so `src` stays at its start.
 */
class CancelledWriteTest {
    private val identity = testIdentity()

    /**
     * Passes everything through until [arm]ed; then the [afterWrites]-th write sends [fraction] of what it was given
     * (all of it, or a part) and throws [CancellationException], as an IOCP send that completed (or partly completed)
     * while the coroutine was being cancelled.
     */
    private class CancelAfterSending(private val inner: IoStream) : IoStream by inner {
        private var countdown = -1
        private var fraction = 1.0

        fun arm(afterWrites: Int, fraction: Double) {
            countdown = afterWrites
            this.fraction = fraction
        }

        override suspend fun write(src: Buffer): Int {
            if (countdown < 0 || --countdown > 0) return inner.write(src)
            countdown = -1
            val n = (src.readableBytes * fraction).toInt()
            val part = Buffer().also { it.writeBytes(src.backingArray(), src.readerIndex(), n) }
            while (part.readableBytes > 0) inner.write(part)
            src.consume(n)
            throw CancellationException("cancelled after sending $n bytes")
        }
    }

    /** The client side writes [payload] through a [CancelAfterSending] armed with [afterWrites] and [fraction]. */
    private fun cancelledWrite(afterWrites: Int, fraction: Double, check: (consumed: Int, received: ByteArray) -> Unit) = runReactor {
        withTimeout(30.seconds) {
            val (a, b) = memoryStreamPair(256 * 1024)
            val wrapped = CancelAfterSending(a)
            val client = TlsContext(server = false, trustRootsPem = identity.certificate)
            val server = TlsContext(server = true, certificateChainPem = identity.certificate, privateKeyPem = identity.key)
            coroutineScope {
                val accepted = async { tlsAccept(b, server) }
                val tls = tlsConnect(wrapped, client, PeerIdentity.Dns("localhost"))
                val peer = accepted.await()
                // Read everything the peer can decrypt until the stream ends (the cancelled client closes it).
                val received = async {
                    val all = Buffer()
                    try {
                        while (true) {
                            val r = Buffer()
                            if (peer.read(r) < 0) break
                            all.writeBytes(r.readAll())
                        }
                    } catch (_: IoException) {
                        // Ended without close_notify (the client closed on the cancellation): expected.
                    }
                    all.readAll()
                }
                val payload = Random(7).nextBytes(3 * 16 * 1024 + 100) // three full records and a short fourth
                val src = Buffer().also { it.writeBytes(payload) }
                wrapped.arm(afterWrites, fraction)
                try {
                    tls.write(src)
                    error("the write was expected to be cancelled")
                } catch (_: CancellationException) {
                }
                val consumed = payload.size - src.readableBytes
                val bytes = received.await()
                assertContentEquals(payload.copyOf(bytes.size), bytes, "the peer received a prefix of the payload")
                check(consumed, bytes)
                peer.close()
            }
            client.close()
            server.close()
        }
    }

    @Test
    fun aRecordSentWholeBeforeTheCancellationCountsAsWritten() = cancelledWrite(afterWrites = 2, fraction = 1.0) { consumed, received ->
        // Records 1 and 2 left; the cancellation came after record 2 was sent whole.
        assertEquals(2 * 16 * 1024, consumed, "src must advance past every record the peer can decrypt")
        assertEquals(consumed, received.size, "src says exactly what the peer received")
    }

    @Test
    fun aRecordCutInHalfDoesNotCount() = cancelledWrite(afterWrites = 2, fraction = 0.5) { consumed, received ->
        // Record 1 left whole; record 2 only in part, which never decrypts.
        assertEquals(16 * 1024, consumed, "a record cut in half must not advance src")
        assertEquals(consumed, received.size, "src says exactly what the peer received")
    }

    @Test
    fun theFirstRecordSentWholeCountsToo() = cancelledWrite(afterWrites = 1, fraction = 1.0) { consumed, received ->
        assertEquals(16 * 1024, consumed)
        assertEquals(consumed, received.size)
    }
}
