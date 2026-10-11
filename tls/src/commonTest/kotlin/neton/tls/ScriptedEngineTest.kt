package neton.tls

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Buffer
import neton.io.core.ClosedException
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.core.memoryStreamPair
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.openssl.TlsEngine
import neton.openssl.TlsProgress
import neton.openssl.TlsVersion
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A scripted engine: "ciphertext" is the plaintext itself, through bounded input / output queues like a BIO
 * pair. It can be told to answer every [messageBytes] of input read with [replyBytes] of output (a peer
 * provoking one protocol reply per message)
 * and to make writes wait for input (WANT_READ). It enforces openssl-kotlin's rule: no read while a write
 * waits for its retry. Everything it outputs is logged in production order.
 */
private class ScriptedEngine(private val bio: Int) : EngineOps {
    private val input = ArrayDeque<Byte>()
    private val output = ArrayDeque<Byte>()
    val produced = ArrayList<Byte>()
    var replyBytes = 0
    var messageBytes = 10
    private var sinceReply = 0
    /** Writes return NEED_READ until this much input has been fed since the write began. */
    var writeNeedsInput = 0
    var readsWhileWritePending = 0
    private var pendingWrite = -1        // length of the write being retried, -1 if none
    private var copied = 0               // bytes of that write already in [output]
    private var fedSinceWrite = 0
    var closed = false

    override fun handshake() = TlsProgress.COMPLETE
    override fun read(output: ByteArray, offset: Int, length: Int): Int {
        if (pendingWrite >= 0) { readsWhileWritePending++; error("read while a write waits for its retry") }
        if (input.isEmpty()) return TlsEngine.NEED_READ
        val n = minOf(length, input.size)
        repeat(n) { output[offset + it] = input.removeFirst() }
        if (replyBytes > 0) {
            sinceReply += n
            while (sinceReply >= messageBytes) { sinceReply -= messageBytes; repeat(replyBytes) { emit(0x7E) } }
        }
        return n
    }
    override fun write(input: ByteArray, offset: Int, length: Int): Int {
        if (pendingWrite < 0) { pendingWrite = length; copied = 0; fedSinceWrite = 0 }
        check(length == pendingWrite) { "retry with different bytes" }
        if (fedSinceWrite < writeNeedsInput) return TlsEngine.NEED_READ
        while (copied < length && output.size < bio) emit(input[offset + copied++])
        if (copied < length) return TlsEngine.NEED_WRITE
        pendingWrite = -1
        return length
    }
    private fun emit(b: Byte) { output.addLast(b); produced.add(b) }
    override fun feedCiphertext(input: ByteArray, offset: Int, length: Int): Int {
        val n = minOf(length, bio - this.input.size)
        repeat(n) { this.input.addLast(input[offset + it]) }
        fedSinceWrite += n
        return n
    }
    override fun drainCiphertext(output: ByteArray, offset: Int, length: Int): Int {
        val n = minOf(length, this.output.size)
        repeat(n) { output[offset + it] = this.output.removeFirst() }
        return n
    }
    override val pendingCiphertext: Int get() = output.size
    override fun transportEof() {}
    override fun closeNotify() = TlsProgress.COMPLETE
    override fun close() { closed = true }
    override val negotiatedAlpn: String? get() = null
    override val protocolVersion: String? get() = "scripted"
    override val cipherSuite: String? get() = null
    override val serverName: String? get() = null
    override fun peerCertificateChainDer(): List<ByteArray> = emptyList()
    override fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray) {}
}

class ScriptedEngineTest {

    private fun buf(bytes: ByteArray) = Buffer().also { it.writeBytes(bytes) }

    private suspend fun readExactly(s: IoStream, n: Int): ByteArray {
        val acc = Buffer()
        while (acc.readableBytes < n) { val r = Buffer(); if (s.read(r) < 0) break; acc.writeBytes(r.readAll()) }
        return acc.readAll()
    }

    /**
     * SPEC §2 pending budget: sending is blocked (the peer does not read) while the peer keeps sending input
     * that makes the engine produce output on every read. The writer sends small messages, so what is being
     * sent is small and the reader's output piles up in the overflow buffer: that is what must be bounded
     * (a check on the buffer being sent alone would never trigger here). Everything waiting to be sent ([stage] + overflow)
     * must stay within pendingLimit + one engine buffer + one record; then, once the peer reads, it receives
     * exactly what the engine produced, in order.
     */
    @Test
    fun readerOutputWhileSendingIsBlockedStaysWithinTheBudget() = runReactor {
        val bio = 1024
        val (a, peer) = memoryStreamPair(2048)
        val engine = ScriptedEngine(bio).also { it.replyBytes = 100 }
        val tls = TlsStream(a, engine, bio)
        tls.pendingLimit = 4 * 1024
        val data = ByteArray(64 * 1024) { (it % 97).toByte() }
        val writer = launch { var i = 0; while (i < data.size) { tls.write(buf(data.copyOfRange(i, i + 100.coerceAtMost(data.size - i)))); i += 100 } }
        val reader = launch { try { while (tls.read(Buffer()) >= 0) { } } catch (_: IoException) { } }
        val flood = launch { repeat(2_000) { peer.write(buf(ByteArray(10) { 1 })); delay(0) } }
        delay(500)
        val bound = tls.pendingLimit + bio + 17 * 1024
        println("ScriptedEngineTest: pending high water ${tls.pendingHighWater} (limit ${tls.pendingLimit}, bound $bound)")
        assertTrue(tls.pendingHighWater > tls.pendingLimit, "reader output never reached the budget: not exercised")
        assertTrue(tls.pendingHighWater <= bound, "pending ciphertext reached ${tls.pendingHighWater} > $bound")
        // Now the peer reads, and keeps reading like a live peer: the writer and the flood finish, and the peer
        // receives exactly what the engine produced, in production order.
        val received = Buffer()
        val sink = launch { try { while (true) { val r = Buffer(); if (peer.read(r) < 0) break; received.writeBytes(r.readAll()) } } catch (_: IoException) { } }
        withTimeout(10_000) { writer.join(); flood.join() }
        withTimeout(10_000) { while (received.readableBytes < engine.produced.size || engine.pendingCiphertext > 0) delay(10) }
        assertContentEquals(engine.produced.toByteArray(), received.readAll())
        assertEquals(0, engine.readsWhileWritePending)
        println("ScriptedEngineTest: final pending high water ${tls.pendingHighWater}")
        assertTrue(tls.pendingHighWater <= bound)
        sink.cancel()
        reader.cancel(); tls.close()
    }

    /**
     * A write that returns WANT_READ gets its input by itself (no reader running) and completes; with a reader
     * running, the reader never calls the engine while that write waits (the scripted engine would fail).
     */
    @Test
    fun writeWaitingForInputFeedsItselfAndTheReaderWaits() = runReactor {
        for (withReader in listOf(false, true)) {
            val (a, peer) = memoryStreamPair(8 * 1024)
            val engine = ScriptedEngine(1024).also { it.writeNeedsInput = 5 }
            val tls = TlsStream(a, engine, 1024)
            val reader = if (withReader) launch { try { while (tls.read(Buffer()) >= 0) { } } catch (_: IoException) { } } else null
            val data = ByteArray(3000) { it.toByte() }
            val writer = async { tls.write(buf(data)) }
            delay(50)
            assertTrue(writer.isActive, "the write should be waiting for input")
            peer.write(buf(ByteArray(5) { 9 }))                                // the input the write waits for
            assertEquals(data.size, withTimeout(5_000) { writer.await() })
            assertContentEquals(data, readExactly(peer, data.size))
            assertEquals(0, engine.readsWhileWritePending)
            reader?.cancel(); tls.close()
        }
    }

    /** SPEC §3: a failed handshake releases the engine and the stream (the caller never gets the TlsStream). */
    @Test
    fun failedHandshakesReleaseEverything() = runReactor {
        val identity = testIdentity()
        val ctx = TlsContext(false, identity.certificate, minimumVersion = TlsVersion.TLS13, maximumVersion = TlsVersion.TLS13)

        class Tracking(private val inner: IoStream) : IoStream by inner {
            var closed = false
            override fun close() { closed = true; inner.close() }
        }

        // The peer closes before answering.
        val (a1, p1) = memoryStreamPair()
        val t1 = Tracking(a1)
        launch { p1.read(Buffer()); p1.close() }
        assertFailsWith<IoException> { tlsConnect(t1, ctx, PeerIdentity.Dns("localhost")) }
        assertTrue(t1.closed, "peer closed during the handshake: the stream was not released")

        // inner itself reports that it was closed.
        val (a2, _) = memoryStreamPair()
        val t2 = object : IoStream by a2 {
            var closed = false
            override suspend fun read(dst: Buffer): Int = throw ClosedException("inner closed")
            override fun close() { closed = true; a2.close() }
        }
        assertFailsWith<ClosedException> { tlsConnect(t2, ctx, PeerIdentity.Dns("localhost")) }
        assertTrue(t2.closed, "inner closed during the handshake: the stream was not released")
        ctx.close()
    }
}
