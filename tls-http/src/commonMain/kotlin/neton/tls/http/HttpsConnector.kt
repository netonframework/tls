package neton.tls.http

import neton.http.client.ConnectError
import neton.http.client.Connected
import neton.http.client.Connector
import neton.http.client.HttpConnector
import neton.http.uri.Uri
import neton.openssl.TlsContext
import neton.tls.peerIdentityOf
import neton.tls.systemTrustRootsPem
import neton.tls.tlsConnect

/**
 * HTTPS (and plain HTTP) connections for com.netonstream:http's pooling client (hyper-rustls `HttpsConnector`):
 * TCP through [http], then for `https` a TLS session verified against [context]'s trust roots and the URL's host (DNS
 * name with SNI, or IP address). When the server picks `h2` by ALPN the client speaks HTTP/2 on the connection.
 *
 * ```
 * val client = neton.http.client.Client.builder().build(this, HttpsConnector())
 * val response = client.get("https://example.com/")
 * ```
 *
 * @param context the client TLS configuration; by default the system's trusted roots ([systemTrustRootsPem]) with
 *   ALPN `h2` and `http/1.1` (hyper-rustls `enable_http1().enable_http2()`). A context passed in stays the caller's.
 * @param httpsOnly refuse `http` URLs (hyper-rustls `https_only`).
 */
class HttpsConnector(
    context: TlsContext? = null,
    private val http: HttpConnector = HttpConnector(enforceHttp = false),
    private val httpsOnly: Boolean = false,
) : Connector, AutoCloseable {
    private val ownsContext = context == null
    private val context: TlsContext = context ?: defaultContext()

    override suspend fun connect(uri: Uri): Connected = when (uri.schemeStr) {
        "https" -> {
            val host = uri.host ?: throw ConnectError("invalid URL, missing host: $uri")
            val tcp = http.connect(uri).stream
            // tlsConnect closes the TCP stream when the handshake fails
            val tls = tlsConnect(tcp, context, peerIdentityOf(host))
            Connected(tls, negotiatedH2 = tls.alpn == "h2")
        }
        "http" -> {
            if (httpsOnly) throw ConnectError("invalid URL, scheme is not https: $uri")
            http.connect(uri)
        }
        else -> throw ConnectError("invalid URL, scheme is neither http nor https: $uri")
    }

    /** Releases the default TLS context (one passed in is left to its owner). */
    override fun close() {
        if (ownsContext) context.close()
    }

    companion object {
        /** The default client context: the system's trusted roots, ALPN `h2` then `http/1.1`. */
        fun defaultContext(alpnProtocols: List<String> = listOf("h2", "http/1.1")): TlsContext =
            TlsContext(server = false, trustRootsPem = systemTrustRootsPem(), alpnProtocols = alpnProtocols)
    }
}
