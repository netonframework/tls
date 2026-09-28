@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package neton.tls

import kotlinx.cinterop.*
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Buffer
import neton.io.core.IoStream
import neton.io.core.memoryStreamPair
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.openssl.TlsVersion
import neton.openssl.c.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A TLS 1.3 server made from raw OpenSSL calls (test only), so a test can do what the safe engine does not
 * expose: request key updates. Driven over [stream] through a BIO pair.
 */
private class RawTlsServer(private val stream: IoStream, id: TestIdentity) {
    private val ctx = checkNotNull(SSL_CTX_new(TLS_server_method()))
    private val ssl: CPointer<SSL>
    private val net: CPointer<BIO>
    private val scratch = ByteArray(16 * 1024)
    /** One writer on the stream (the flood and, when the SSL object needs it, the reader). */
    private val writeLock = kotlinx.coroutines.sync.Mutex()

    init {
        check(neton_openssl_tls13_only(ctx) == 1)
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET)
        val cert = id.certificate.usePinned { BIO_new_mem_buf(it.addressOf(0), id.certificate.size) }!!
        val key = id.key.usePinned { BIO_new_mem_buf(it.addressOf(0), id.key.size) }!!
        val x509 = checkNotNull(PEM_read_bio_X509(cert, null, null, null))
        val pkey = checkNotNull(PEM_read_bio_PrivateKey(key, null, null, null))
        check(SSL_CTX_use_certificate(ctx, x509) == 1 && SSL_CTX_use_PrivateKey(ctx, pkey) == 1)
        X509_free(x509); EVP_PKEY_free(pkey); BIO_free(cert); BIO_free(key)
        ssl = checkNotNull(SSL_new(ctx))
        val (inner, network) = memScoped {
            val i = alloc<CPointerVar<BIO>>(); val n = alloc<CPointerVar<BIO>>()
            check(BIO_new_bio_pair(i.ptr, 0u, n.ptr, 0u) == 1)
            i.value!! to n.value!!
        }
        net = network
        SSL_set_bio(ssl, inner, inner)
        SSL_set_accept_state(ssl)
    }

    /** Send everything the SSL object produced. */
    suspend fun flushOut() = writeLock.withLock {
        while (true) {
            val n = scratch.usePinned { BIO_read(net, it.addressOf(0), scratch.size) }
            if (n <= 0) return
            stream.write(Buffer().also { it.writeBytes(scratch, 0, n) })
        }
    }

    /** Read once from the stream into the SSL object; false at EOF. */
    suspend fun feedOnce(): Boolean {
        val b = Buffer()
        if (stream.read(b) < 0) return false
        val bytes = b.readAll()
        var off = 0
        while (off < bytes.size) {
            val n = bytes.usePinned { BIO_write(net, it.addressOf(off), bytes.size - off) }
            check(n > 0) { "raw server input BIO full" }
            off += n
        }
        return true
    }

    suspend fun handshake() {
        while (true) {
            val r = SSL_do_handshake(ssl)
            flushOut()
            if (r == 1) return
            check(SSL_get_error(ssl, r) == SSL_ERROR_WANT_READ) { "raw handshake failed" }
            check(feedOnce())
        }
    }

    /** Ask the peer to update its keys too; the request goes out now. */
    suspend fun requestKeyUpdate() {
        check(SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED) == 1)
        SSL_do_handshake(ssl)
        flushOut()
    }

    /**
     * Read and decrypt application data until [n] bytes arrived (processing the peer's KeyUpdates too). Like a
     * real peer it keeps reading while its own writes are blocked: it flushes only when the SSL object needs it.
     */
    suspend fun readApplication(n: Int): Int {
        val out = ByteArray(16 * 1024)
        var got = 0
        while (got < n) {
            val r = out.usePinned { SSL_read(ssl, it.addressOf(0), out.size) }
            if (r > 0) { got += r; continue }
            when (SSL_get_error(ssl, r)) {
                SSL_ERROR_WANT_READ -> if (!feedOnce()) break
                SSL_ERROR_WANT_WRITE -> flushOut()
                else -> error("raw read failed")
            }
        }
        return got
    }

    /** Keep reading (and discarding) until cancelled, as a live peer would while it still sends. */
    suspend fun drainForever() { readApplication(Int.MAX_VALUE) }

    fun free() { SSL_free(ssl); BIO_free(net); SSL_CTX_free(ctx) }
}

class KeyUpdateTest {
    private val identity = testIdentity()

    /**
     * Peer-initiated TLS 1.3 key updates with real OpenSSL, while our sending is blocked (the peer does not
     * read): 5 000 KeyUpdate(update_requested) messages are processed, memory stays bounded, and once the peer
     * reads again everything completes with the application data intact.
     *
     * This does not exercise the pending budget: OpenSSL 4.0.2 does not answer a KeyUpdate while reading. It
     * only sets a flag and sends one reply with the next write, merging repeated requests (tls_process_key_update
     * in statem_lib.c, ssl3_write_bytes in rec_layer_s3.c). The budget is tested with a scripted engine
     * (ScriptedEngineTest).
     */
    @Test
    fun keyUpdateRepliesWhileSendingIsBlockedStayBounded() = runReactor {
        val (a, b) = memoryStreamPair(4 * 1024)
        val client = TlsContext(false, identity.certificate, minimumVersion = TlsVersion.TLS13, maximumVersion = TlsVersion.TLS13)
        val raw = RawTlsServer(b, identity)
        val engineBuffer = 4 * 1024
        val hs = async { raw.handshake() }
        val tls = tlsConnect(a, client, PeerIdentity.Dns("localhost"), engineBuffer)
        hs.await()
        tls.pendingLimit = 8 * 1024

        val data = ByteArray(256 * 1024) { (it * 13).toByte() }
        val writer = launch { tls.write(Buffer().also { it.writeBytes(data) }) }   // blocks: the peer is not reading
        val reader = launch { try { while (tls.read(Buffer()) >= 0) { } } catch (_: Throwable) { } }
        val flood = launch { repeat(5_000) { raw.requestKeyUpdate() } }
        delay(1_000)
        val bound = tls.pendingLimit + engineBuffer + 17 * 1024
        println("KeyUpdateTest: pending high water ${tls.pendingHighWater} bytes (bound $bound)")
        assertTrue(tls.pendingHighWater <= bound, "pending ciphertext reached ${tls.pendingHighWater} > $bound")

        // Let the peer read: the writer and the flood finish, the application data arrives intact, and the
        // peer keeps reading (our KeyUpdate replies) until its flood is done.
        val received = async { raw.readApplication(data.size) }
        withTimeout(20_000) { writer.join(); assertEquals(data.size, received.await()) }
        val sink = launch { raw.drainForever() }
        withTimeout(20_000) { flood.join() }
        println("KeyUpdateTest: final pending high water ${tls.pendingHighWater} bytes")
        assertTrue(tls.pendingHighWater <= bound, "pending ciphertext reached ${tls.pendingHighWater} > $bound")
        sink.cancel(); reader.cancel(); tls.close(); raw.free(); client.close()
    }
}
