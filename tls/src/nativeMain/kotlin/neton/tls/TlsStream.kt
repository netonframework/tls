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
    // Any handshake failure (TLS error, peer close, inner closed, cancellation) releases the engine and
    // the stream: the caller never receives the TlsStream, so nobody else could (close is idempotent).
    try { tls.handshake() } catch (t: Throwable) { tls.close(); throw t }
    return tls
}

/** Engine ciphertext buffer size (the BIO pair's capacity per direction). */
const val DEFAULT_BUFFER = 16 * 1024

/**
 * TLS over [inner] as an [IoStream] (SPEC §2–§3). The [engine] (openssl-kotlin) does all TLS work;
 * this class moves ciphertext between it and [inner] and maps the result onto the IoStream contract.
 * Takes ownership of [inner] and [engine]: [close] closes both.
 *
 * Scheduling follows OpenSSL's retry contract (SSL_get_error(3), SPEC §2):
 * - WANT_WRITE: the engine's output is drained into [stage] at once, without suspending, and the same
 *   call is repeated; nothing else touches the engine in between, and no retry stays pending across a
 *   network wait, so a blocked network write never stops the reader.
 * - WANT_READ from a write: the writer obtains more input itself (coordinated with the reader through
 *   [feedLock]) and repeats the write; the reader waits meanwhile (the engine refuses reads then).
 * - Ciphertext goes out through [stage]: whoever holds [writeLock] writes it to [inner]. While that write is
 *   in flight, newly drained ciphertext goes to [overflow] (the buffer being sent is never touched; with
 *   io_uring the kernel owns it) and is appended afterwards, so order is kept. [stage] is always the same
 *   array, so the reactor's pin cache hits (alternating arrays cost a pin allocation per write).
 */
class TlsStream internal constructor(private val inner: IoStream, private val engine: EngineOps, bufferCapacity: Int) : IoStream {

    /** TLS over [inner] driven by [engine]; takes ownership of both. */
    constructor(inner: IoStream, engine: TlsEngine, bufferCapacity: Int = DEFAULT_BUFFER) : this(inner, OpenSslEngineOps(engine), bufferCapacity)

    override val capabilities: Set<StreamCapability> =
        inner.capabilities.filterTo(mutableSetOf(StreamCapability.HalfClose)) {
            it == StreamCapability.ReadTimeout || it == StreamCapability.WriteTimeout || it == StreamCapability.IdleTimeout
        }

    /** Ciphertext from the peer not yet taken by the engine (its input BIO is bounded). */
    private val cin = Buffer(bufferCapacity + RECORD_SLACK)
    /** Ciphertext drained from the engine, not yet handed to [inner] (or being handed, see [flushing]). */
    private val stage = Buffer(bufferCapacity + RECORD_SLACK)
    /** Ciphertext drained while [stage] is being written. Rare (the reader's replies). */
    private val overflow = Buffer(0)
    /** [stage] is in an [inner] write: do not touch it. */
    private var flushing = false
    /** Budget for ciphertext waiting to be sent ([stage] + [overflow]) before the reader stops (SPEC §2). */
    internal var pendingLimit = PENDING_LIMIT
    /** Highest [stage] + [overflow] seen: tests check the bound. */
    internal var pendingHighWater = 0
        private set
    private val pendingCiphertextBytes: Int get() = stage.readableBytes + overflow.readableBytes

    /** One writer on [inner]: whoever flushes [stage]. */
    private val writeLock = Mutex()
    /** One reader on [inner]: the reader, or a writer or the handshake that needs input. */
    private val feedLock = Mutex()
    /** Held by a writer while its write waits (WANT_READ) for input; the reader waits on it. */
    private val retryLock = Mutex()
    private val handshakeLock = Mutex()
    /** Incremented whenever ciphertext is fed: a waiter that sees it change need not read [inner] itself. */
    private var fedGeneration = 0L
    private var handshakeDone = false
    private var peerClosed = false
    private var inputEof = false
    private var closed = false
    private var reading = false
    private var writing = false
    /** A write waits for input (WANT_READ); the engine refuses reads until it is repeated successfully. */
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
        } finally {
            writing = false
            // A write abandoned while waiting for input (failure, cancel: the stream is closed then) must
            // still release the reader waiting on retryLock.
            if (writeRetryPending) endWriteRetry()
        }
        return intResult(n)
    }

    override suspend fun flush() {}

    override suspend fun shutdownOutput() = guarded(duringHandshake = false) {
        if (!handshakeDone) ensureHandshake()
        checkOpen()
        while (true) {
            // Not yet received the peer's close_notify is NEED_READ here: fine, ours is out.
            val p = engine.closeNotify()
            drainToStage()
            if (p != TlsProgress.NEED_WRITE) break
        }
        flushLocked()
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
            close(); throw e                  // idempotent; also when inner reported the close itself
        } catch (e: CancellationException) {
            close(); throw e
        } catch (e: IoException) {
            close(); throw e
        }
    }

    private suspend fun sendAlertAndClose() {
        if (!closed) try {
            drainToStage()                      // allowed after a failure: the alert the engine produced
            if (!writeLock.isLocked) flushLocked()
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
                drainToStage()
                when (progress) {
                    TlsProgress.COMPLETE -> { handshakeDone = true; flushLocked() }
                    TlsProgress.NEED_WRITE -> {}                       // drained: repeat at once
                    TlsProgress.NEED_READ -> { flushLocked(); feedOnce() }
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
            // A write waiting for input holds the engine (it refuses reads); the writer feeds itself.
            if (writeRetryPending) { waitForWriteRetry(); continue }
            dst.reserve(MIN_READ)
            val space = dst.backingArray().size - dst.writerIndex()
            val n = engine.read(dst.backingArray(), dst.writerIndex(), space)
            if (n > 0) {
                dst.commitWrite(n)
                if (engine.pendingCiphertext > 0) readerProduced()
                return n
            }
            when (n) {
                TlsEngine.PEER_CLOSED -> {
                    peerClosed = true
                    if (engine.pendingCiphertext > 0) readerProduced()
                    return -1
                }
                TlsEngine.NEED_WRITE -> drainToStage()                 // repeat the read at once
                TlsEngine.NEED_READ -> {
                    if (engine.pendingCiphertext > 0) readerProduced()
                    // Read inner only if nobody fed the engine since we looked (a writer may have).
                    val seen = fedGeneration
                    feedLock.lock()
                    try { if (fedGeneration == seen && !feedMore()) engine.transportEof() } finally { feedLock.unlock() }
                }
                else -> unexpected("read", n)
            }
        }
    }

    /**
     * Take ciphertext the engine produced while reading (alerts, post-handshake replies such as KeyUpdate
     * responses) and send it. A writer holding the lock sends it after its current write; otherwise send it
     * now. Once everything waiting to be sent ([stage] + [overflow]) exceeds [pendingLimit], wait until it
     * is sent before reading on, so a peer that keeps provoking replies while not reading cannot grow it.
     * One engine read adds at most the engine's buffer (it is drained each time), so the high water mark
     * stays within [pendingLimit] + engine buffer + one record.
     */
    private suspend fun readerProduced() {
        drainToStage()
        if (!writeLock.isLocked) flushLocked()
        else if (pendingCiphertextBytes > pendingLimit) {
            // Blocks until the holder has sent everything and released the lock (it drains overflow too).
            flushLocked()
        }
    }

    private suspend fun waitForWriteRetry() = retryLock.withLock { }

    /** Out of line: feed once under [feedLock], unless someone fed meanwhile. */
    private suspend fun feedOnce() {
        val seen = fedGeneration
        feedLock.withLock { if (fedGeneration == seen && !feedMore()) engine.transportEof() }
    }

    /** Give the engine more ciphertext; false at transport EOF. Caller holds [feedLock]. */
    private suspend inline fun feedMore(): Boolean {
        if (inputEof) return false
        if (cin.readableBytes == 0) {
            val n = inner.read(cin)
            checkOpen()
            if (n < 0) { inputEof = true; return false }
        }
        val fed = engine.feedCiphertext(cin.backingArray(), cin.readerIndex(), cin.readableBytes)
        // A full input BIO is fine: the engine has unprocessed input and the next call makes progress.
        cin.consume(fed)
        fedGeneration++
        return true
    }

    private suspend inline fun writeAll(src: Buffer): Int {
        val total = src.readableBytes
        while (src.readableBytes > 0) {
            val len = minOf(src.readableBytes, MAX_PLAINTEXT_RECORD)
            checkOpen()
            while (true) {
                // Retries pass exactly the same bytes (the engine requires it); src moves only after the
                // record's ciphertext has been handed to inner.
                val r = engine.write(src.backingArray(), src.readerIndex(), len)
                if (r > 0) break
                when (r) {
                    TlsEngine.NEED_WRITE -> drainToStage()             // no suspension before the retry
                    TlsEngine.NEED_READ -> writerNeedsInput()
                    else -> unexpected("write", r)
                }
            }
            if (writeRetryPending) endWriteRetry()
            drainToStage()
            flushInline()                                           // hot: inline, no frame of its own
            src.consume(len)
        }
        return total
    }

    /** A write returned WANT_READ: hold the engine (the reader waits), send what is staged, feed, repeat. */
    private suspend fun writerNeedsInput() {
        if (!writeRetryPending) { retryLock.lock(); writeRetryPending = true }
        drainToStage()
        flushLocked()
        feedOnce()
    }

    private fun endWriteRetry() { writeRetryPending = false; retryLock.unlock() }

    /** Move everything the engine has produced into [stage] ([overflow] while [stage] is being sent). Never suspends. */
    private fun drainToStage() {
        val into = if (flushing) overflow else stage
        while (true) {
            val pending = engine.pendingCiphertext
            if (pending == 0) return
            into.reserve(pending)
            val n = engine.drainCiphertext(into.backingArray(), into.writerIndex(), into.backingArray().size - into.writerIndex())
            if (n <= 0) return
            into.commitWrite(n)
            val waiting = pendingCiphertextBytes
            if (waiting > pendingHighWater) pendingHighWater = waiting
        }
    }

    /** Send [stage] (and whatever is staged meanwhile) to [inner]. Rare paths: out of line. */
    private suspend fun flushLocked() = flushInline()

    private suspend inline fun flushInline() = writeLock.withLock {
        while (stage.readableBytes > 0) {
            flushing = true
            try { inner.write(stage) } finally { flushing = false }
            checkOpen()
            if (overflow.readableBytes > 0) { stage.writeBytes(overflow.backingArray(), overflow.readerIndex(), overflow.readableBytes); overflow.clear() }
        }
    }

    private fun unexpected(op: String, result: Int): Nothing = error("unexpected TLS $op result $result")

    private companion object {
        const val MAX_PLAINTEXT_RECORD = 16 * 1024
        /** Headroom above the engine buffer for one record's header, tag and padding. */
        const val RECORD_SLACK = 1024
        /** Space offered to each engine read: a whole record's plaintext when the caller's buffer allows. */
        const val MIN_READ = 4 * 1024
        /** Ciphertext waiting to be sent past which the reader stops producing more (SPEC §2). */
        const val PENDING_LIMIT = 64 * 1024
    }
}
