# tls

TLS for Kotlin/Native as a `com.netonstream:io` `IoStream`, built on `com.netonstream:openssl` (OpenSSL 4.0.2).
Package `neton.tls`. See [SPEC.md](SPEC.md).

Three artifacts, release 0.2.0 (Kotlin 2.4.20; the build refuses anything lower):

| Coordinate | What | Depends on |
|---|---|---|
| `com.netonstream:tls` | `tlsConnect` / `tlsAccept` → `TlsStream` (an `IoStream`); `systemTrustRootsPem()`; `peerIdentityOf(host)` | `io:0.3.2`, `openssl:4.0.2` |
| `com.netonstream:tls-http` | `HttpsConnector` for `com.netonstream:http`'s pooling client (hyper-rustls) | `tls`, `http:0.2.0` |
| `com.netonstream:tls-websocket` | `WssConnector` for `wss://` in `com.netonstream:websocket` | `tls`, `websocket:0.2.0` |

```kotlin
// HTTPS: system roots, ALPN h2 then http/1.1; HTTP/2 when the server picks it
val client = neton.http.client.Client.builder().build(this, neton.tls.http.HttpsConnector())
val response = client.get("https://example.com/")

// wss
val (ws, _) = neton.websocket.connect("wss://example.com/socket", tlsConnector = neton.tls.websocket.WssConnector())

// A server, or a client with its own roots
val context = neton.openssl.TlsContext(server = false, trustRootsPem = neton.tls.systemTrustRootsPem(), alpnProtocols = listOf("h2"))
val tls = neton.tls.tlsConnect(tcpStream, context, neton.tls.peerIdentityOf("example.com"))
```

`systemTrustRootsPem()` reads the operating system's trusted roots as rustls-native-certs does (`SSL_CERT_FILE` /
`SSL_CERT_DIR` override; Linux CA bundle, Android system CA directory, macOS Security framework anchors, Windows ROOT
store; iOS has no API for it and throws). Nothing uses the system store implicitly: trust roots are always given.

0.1.0 depended on `io:0.1.0` and on `openssl:0.1.0`, published by mistake (the same build as `openssl:4.0.2`; the
version follows upstream OpenSSL). Builds use Maven Central by default; `-PreleaseRepositories=<staging-directory>` is
an explicit release-verification override.
