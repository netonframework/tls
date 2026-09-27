package neton.tls

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import neton.io.bytes.Buffer
import neton.io.core.ClosedException
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.core.StreamCapability
import neton.io.core.intResult
import neton.io.core.requireTimeoutCapabilities
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.openssl.TlsEngine
import neton.openssl.TlsException
import neton.openssl.TlsFailureKind
import neton.openssl.TlsProgress

/** TLS failed: during the handshake ([duringHandshake]) or later (a bad record, an alert). */
open class TlsFailureException(
    val kind: TlsFailureKind,
    /** X509 verification result (0 = ok). */
    val verificationCode: Int,
    /** TLS alert received or sent, when known. */
    val alertCode: Int?,
    val duringHandshake: Boolean,
    message: String,
) : IoException(message)

/** The peer ended the transport without close_notify: the data may have been cut short (SPEC §3). */
class TlsTruncatedException : IoException("TLS stream ended without close_notify (possible truncation)")

/** Open a client TLS session over [stream] to [peer] and complete the handshake. On failure [stream] is closed. */
suspend fun tlsConnect(stream: IoStream, context: TlsContext, peer: PeerIdentity, bufferCapacity: Int = DEFAULT_BUFFER): TlsStream =
    start(stream, bufferCapacity) { context.newEngine(peer, bufferCapacity) }

/** Accept a server TLS session over [stream] and complete the handshake. On failure [stream] is closed. */
suspend fun tlsAccept(stream: IoStream, context: TlsContext, bufferCapacity: Int = DEFAULT_BUFFER): TlsStream =
    start(stream, bufferCapacity) { context.newEngine(bufferCapacity = bufferCapacity) }

private inline fun newTls(stream: IoStream, bufferCapacity: Int, engine: () -> TlsEngine): TlsStream {
    val e = try { engine() } catch (t: Throwable) { stream.close(); throw t }
    return TlsStream(stream, e, bufferCapacity)
}

private suspend inline fun start(stream: IoStream, bufferCapacity: Int, engine: () -> TlsEngine): TlsStream {
    val tls = newTls(stream, bufferCapacity, engine)
    tls.handshake()
    return tls
}

/**
 * Engine ciphertext buffer size. Twice a record: with pending ciphertext flushed before each write, a
 * full 16 KiB record always fits, so a write rarely has to be retried (while one is pending the engine
 * refuses reads, which would stall a full-duplex connection; SPEC §2).
 */
const val DEFAULT_BUFFER = 32 * 1024

/** Smallest engine buffer that holds one full record (16 KiB plaintext plus header, tag and padding). */
const val MIN_BUFFER = 17 * 1024

/**
 * TLS over [inner] as an [IoStream] (SPEC §2–§3). The [engine] (openssl-kotlin) does all TLS work;
 * this class moves ciphertext between it and [inner] and maps the result onto the IoStream contract.
 * Takes ownership of [inner] and [engine]: [close] closes both.
 */
class TlsStream(private val inner: IoStream, private val engine: TlsEngine, bufferCapacity: Int = DEFAULT_BUFFER) : IoStream {
    init {
        // The engine refuses reads while a write waits for its retry. If both peers' writers were waiting
        // (each blocked on TCP until the other reads), neither reader could run: a deadlock, reproduced
        // with a 16 KiB buffer. Flushing before each write plus room for a whole record means application
        // writes never need a retry (SPEC §2).
        require(bufferCapacity >= MIN_BUFFER) { "engine buffer must hold a whole TLS record (>= $MIN_BUFFER bytes)" }
    }

    override val capabilities: Set<StreamCapability> =
        inner.capabilities.filterTo(mutableSetOf(StreamCapability.HalfClose)) {
            it == StreamCapability.ReadTimeout || it == StreamCapability.WriteTimeout || it == StreamCapability.IdleTimeout
        }

    // Ciphertext from the peer not yet taken by the engine (its input BIO is bounded), and to the peer.
    private val cin = Buffer(bufferCapacity + RECORD_SLACK)
    private val cout = Buffer(bufferCapacity + RECORD_SLACK)

    /** One writer on [inner] at a time: the writer, and the reader when it must send (alerts, TLS 1.3 post-handshake replies). */
    private val writeLock = Mutex()
    private val handshakeLock = Mutex()
    private var handshakeDone = false
    private var peerClosed = false
    private var inputEof = false
    private var closed = false
    private var reading = false
    private var writing = false
    /** The engine holds a write to be retried with the same bytes; it refuses reads until then. */
    private var writeRetryPending = false

    /** Negotiated ALPN protocol, or null. Valid after the handshake. */
    val alpn: String? get() = afterHandshake { engine.negotiatedAlpn }
    val protocolVersion: String? get() = afterHandshake { engine.protocolVersion }
    val cipherSuite: String? get() = afterHandshake { engine.cipherSuite }
    /** Server side: the SNI name the client asked for. */
    val serverName: String? get() = afterHandshake { engine.serverName }
    /** The peer's certificate chain as DER, leaf first. */
    fun peerCertificates(): List<ByteArray> = afterHandshake { engine.peerCertificateChainDer() }
    fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray) = afterHandshake { engine.exportKeyingMaterial(label, context, output) }

    private inline fun <T> afterHandshake(block: () -> T): T {
        checkOpen(); check(handshakeDone) { "TLS handshake not complete" }
        return block()
    }

    /** Complete the handshake (done implicitly by the first read or write). */
    suspend fun handshake() = guarded(duringHandshake = true) { ensureHandshake() }

    override suspend fun read(dst: Buffer): Int {
        check(!reading) { "concurrent read on a TLS stream" }
        reading = true
        val n = try {
            guarded(duringHandshake = false) { if (!handshakeDone) ensureHandshake(); readRecord(dst) }
        } finally { reading = false }
        return intResult(n)          // no Int box per read (SPEC §5)
    }

    override suspend fun write(src: Buffer): Int {
        check(!writing) { "concurrent write on a TLS stream" }
        writing = true
        val n = try {
            guarded(duringHandshake = false) { if (!handshakeDone) ensureHandshake(); writeAll(src) }
        } finally { writing = false }
        return intResult(n)
    }

    override suspend fun flush() {}

    override suspend fun shutdownOutput() = guarded(duringHandshake = false) {
        ensureHandshake()
        writeLock.withLock {
            checkOpen()
            if (!engine.closeNotifySent) engine.closeNotify()
            flushCiphertext()
        }
    }

    override fun setTimeouts(readTimeoutMillis: Long, writeTimeoutMillis: Long, idleTimeoutMillis: Long) {
        requireTimeoutCapabilities(this, readTimeoutMillis, writeTimeoutMillis, idleTimeoutMillis)
        inner.setTimeouts(readTimeoutMillis, writeTimeoutMillis, idleTimeoutMillis)
    }

    override fun setReadTimeout(millis: Long) {
        requireTimeoutCapabilities(this, millis, 0, 0)
        inner.setReadTimeout(millis)
    }

    /** Immediate and idempotent; sends no close_notify (use [shutdownOutput] first for a clean end). */
    override fun close() {
        if (closed) return
        closed = true
        try { inner.close() } finally { engine.close() }
    }

    // ---- internals -------------------------------------------------------------------------------

    private fun checkOpen() { if (closed) throw ClosedException() }

    /**
     * Map failures onto the IoStream contract: TLS errors become [TlsFailureException] (after sending the
     * engine's alert, best effort) and close the stream; a cancellation or timeout closes it too, since
     * a record may have been cut in half (no ResumableAfterCancel, SPEC §3).
     */
    private suspend inline fun <T> guarded(duringHandshake: Boolean, block: () -> T): T {
        try {
            return block()
        } catch (e: TlsException) {
            val failure = if (e.kind == TlsFailureKind.UNEXPECTED_EOF) TlsTruncatedException()
                else TlsFailureException(e.kind, e.verificationCode, e.alertCode, duringHandshake || !handshakeDone, e.message ?: "TLS failure")
            sendAlertAndClose()
            throw failure
        } catch (e: ClosedException) {
            throw e
        } catch (e: CancellationException) {
            close(); throw e
        } catch (e: IoException) {
            close(); throw e
        }
    }

    private suspend fun sendAlertAndClose() {
        if (!closed) try {
            if (!writeLock.isLocked) writeLock.withLock { flushCiphertext() }
        } catch (_: Throwable) {
        }
        close()
    }

    private suspend fun ensureHandshake() {
        if (handshakeDone) return
        handshakeLock.withLock {
            while (!handshakeDone) {
                checkOpen()
                val progress = engine.handshake()
                if (engine.pendingCiphertext > 0) writeLock.withLock { flushCiphertext() }
                when (progress) {
                    TlsProgress.COMPLETE -> handshakeDone = true
                    TlsProgress.NEED_READ -> if (!feedMore()) engine.transportEof()
                    TlsProgress.NEED_WRITE -> {}
                    TlsProgress.PEER_CLOSED -> throw ClosedException("TLS peer closed during the handshake")
                }
            }
        }
    }

    // Hot paths are inline: a separate suspend function allocates its continuation on every call in
    // Kotlin/Native (12 allocations per echo request before). Rare paths stay out of line: every inline
    // copy adds GC slots to the caller's frame, which Kotlin/Native zeroes on each entry and resume
    // (inlining all of them grew read's frame to 2.7 KB, about 5.4k instructions per request; SPEC §5).
    private suspend inline fun readRecord(dst: Buffer): Int {
        if (peerClosed) return -1
        while (true) {
            checkOpen()
            // While a write waits for its retry the engine refuses reads: wait for the writer to finish it.
            if (writeRetryPending) { writeLock.withLock { }; continue }
            dst.reserve(MIN_READ)
            val space = dst.backingArray().size - dst.writerIndex()
            val n = engine.read(dst.backingArray(), dst.writerIndex(), space)
            if (n > 0) {
                dst.commitWrite(n)
                if (engine.pendingCiphertext > 0) flushLocked()
                return n
            }
            when (n) {
                TlsEngine.PEER_CLOSED -> {
                    peerClosed = true
                    if (engine.pendingCiphertext > 0) flushLocked()
                    return -1
                }
                TlsEngine.NEED_WRITE -> flushLocked()
                TlsEngine.NEED_READ -> {
                    if (engine.pendingCiphertext > 0) flushLocked()
                    if (!feedMore()) engine.transportEof()   // the next engine.read reports truncation or close
                }
                else -> unexpected("read", n)
            }
        }
    }

    /** Give the engine more ciphertext; false at transport EOF. */
    private suspend inline fun feedMore(): Boolean {
        if (inputEof) return false
        if (cin.readableBytes == 0) {
            val n = inner.read(cin)
            checkOpen()
            if (n < 0) { inputEof = true; return false }
        }
        val fed = engine.feedCiphertext(cin.backingArray(), cin.readerIndex(), cin.readableBytes)
        if (fed == 0) throw IoException("TLS engine accepted no ciphertext while waiting for input")
        cin.consume(fed)
        return true
    }

    private suspend inline fun writeAll(src: Buffer): Int {
        val total = src.readableBytes
        while (src.readableBytes > 0) {
            val len = minOf(src.readableBytes, MAX_PLAINTEXT_RECORD)
            writeLock.withLock {
                checkOpen()
                // Room for the whole record, so the write normally completes at once.
                if (engine.pendingCiphertext > 0) flushOutOfLine()
                while (true) {
                    // Retries pass exactly the same bytes (the engine requires it); src moves only after the
                    // record's ciphertext has been handed to inner.
                    val r = engine.write(src.backingArray(), src.readerIndex(), len)
                    if (r > 0) { writeRetryPending = false; break }
                    when (r) {
                        TlsEngine.NEED_WRITE -> { writeRetryPending = true; flushOutOfLine() }
                        TlsEngine.NEED_READ -> throw IoException("TLS write needs peer data (renegotiation is not supported)")
                        else -> unexpected("write", r)
                    }
                }
                flushCiphertext()
                src.consume(len)
            }
        }
        return total
    }

    /** Rare paths: take the write lock and flush (out of line, see above). */
    private suspend fun flushLocked() = writeLock.withLock { flushCiphertext() }

    /** Rare paths with the lock already held. */
    private suspend fun flushOutOfLine() = flushCiphertext()

    private fun unexpected(op: String, result: Int): Nothing = error("unexpected TLS $op result $result")

    /** Write every pending ciphertext byte to [inner]. Caller holds [writeLock]. */
    private suspend inline fun flushCiphertext() {
        while (true) {
            while (true) {
                val pending = engine.pendingCiphertext
                if (pending == 0) break
                cout.reserve(minOf(pending, cout.backingArray().size.coerceAtLeast(RECORD_SLACK)))
                val space = cout.backingArray().size - cout.writerIndex()
                val n = engine.drainCiphertext(cout.backingArray(), cout.writerIndex(), space)
                if (n <= 0) break
                cout.commitWrite(n)
            }
            if (cout.readableBytes == 0) return
            inner.write(cout)
            checkOpen()
        }
    }

    private companion object {
        const val MAX_PLAINTEXT_RECORD = 16 * 1024
        /** Headroom above the engine buffer for one record's header, tag and padding. */
        const val RECORD_SLACK = 1024
        /** Space offered to each engine read: a whole record's plaintext when the caller's buffer allows. */
        const val MIN_READ = 4 * 1024
    }
}
