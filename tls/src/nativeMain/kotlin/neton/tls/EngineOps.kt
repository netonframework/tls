package neton.tls

import neton.openssl.TlsEngine
import neton.openssl.TlsProgress

/**
 * The engine operations [TlsStream] uses (openssl-kotlin's [TlsEngine] in production). An internal seam so
 * tests can script an engine: conditions real OpenSSL 4.0 does not produce on demand (a reader that keeps
 * generating output, a write that returns WANT_READ) still get deterministic tests (SPEC §4).
 * Results follow [TlsEngine]: > 0 bytes, or [TlsEngine.NEED_READ] / [TlsEngine.NEED_WRITE] / [TlsEngine.PEER_CLOSED].
 */
internal interface EngineOps {
    fun handshake(): TlsProgress
    fun read(output: ByteArray, offset: Int, length: Int): Int
    fun write(input: ByteArray, offset: Int, length: Int): Int
    fun feedCiphertext(input: ByteArray, offset: Int, length: Int): Int
    fun drainCiphertext(output: ByteArray, offset: Int, length: Int): Int
    val pendingCiphertext: Int
    fun transportEof()
    fun closeNotify(): TlsProgress
    fun close()
    val negotiatedAlpn: String?
    val protocolVersion: String?
    val cipherSuite: String?
    val serverName: String?
    fun peerCertificateChainDer(): List<ByteArray>
    fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray)
}

/** Production: straight delegation to openssl-kotlin. */
internal class OpenSslEngineOps(private val e: TlsEngine) : EngineOps {
    override fun handshake() = e.handshake()
    override fun read(output: ByteArray, offset: Int, length: Int) = e.read(output, offset, length)
    override fun write(input: ByteArray, offset: Int, length: Int) = e.write(input, offset, length)
    override fun feedCiphertext(input: ByteArray, offset: Int, length: Int) = e.feedCiphertext(input, offset, length)
    override fun drainCiphertext(output: ByteArray, offset: Int, length: Int) = e.drainCiphertext(output, offset, length)
    override val pendingCiphertext: Int get() = e.pendingCiphertext
    override fun transportEof() = e.transportEof()
    override fun closeNotify() = e.closeNotify()
    override fun close() = e.close()
    override val negotiatedAlpn: String? get() = e.negotiatedAlpn
    override val protocolVersion: String? get() = e.protocolVersion
    override val cipherSuite: String? get() = e.cipherSuite
    override val serverName: String? get() = e.serverName
    override fun peerCertificateChainDer() = e.peerCertificateChainDer()
    override fun exportKeyingMaterial(label: String, context: ByteArray?, output: ByteArray) = e.exportKeyingMaterial(label, context, output)
}
