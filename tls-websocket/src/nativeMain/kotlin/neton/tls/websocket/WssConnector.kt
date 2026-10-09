package neton.tls.websocket

import neton.io.core.IoStream
import neton.openssl.TlsContext
import neton.tls.peerIdentityOf
import neton.tls.systemTrustRootsPem
import neton.tls.tlsConnect
import neton.websocket.TlsConnector

/**
 * TLS for `wss://` URLs in com.netonstream:websocket's `connect` (its [TlsConnector]): the TCP stream is wrapped in a
 * TLS session verified against [context]'s trust roots and the URL's host (DNS name with SNI, or IP address).
 *
 * ```
 * val (ws, response) = neton.websocket.connect("wss://example.com/socket", tlsConnector = WssConnector())
 * ```
 *
 * @param context the client TLS configuration; by default the system's trusted roots ([systemTrustRootsPem]) and ALPN
 *   `http/1.1` (a WebSocket handshake is HTTP/1.1). A context passed in stays the caller's.
 */
class WssConnector(context: TlsContext? = null) : TlsConnector, AutoCloseable {
    private val ownsContext = context == null
    private val context: TlsContext = context ?: defaultContext()

    // tlsConnect closes the TCP stream when the handshake fails
    override suspend fun connect(stream: IoStream, domain: String): IoStream = tlsConnect(stream, context, peerIdentityOf(domain))

    /** Releases the default TLS context (one passed in is left to its owner). */
    override fun close() {
        if (ownsContext) context.close()
    }

    companion object {
        /** The default client context: the system's trusted roots, ALPN `http/1.1`. */
        fun defaultContext(): TlsContext =
            TlsContext(server = false, trustRootsPem = systemTrustRootsPem(), alpnProtocols = listOf("http/1.1"))
    }
}
