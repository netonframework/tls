package neton.tls

// iOS offers no way to list the system's roots (SecTrustCopyAnchorCertificates is macOS only; rustls-native-certs does
// not support iOS either). systemTrustRootsPem() fails there; pass the trust anchors explicitly.
internal actual fun platformRootsDer(): List<ByteArray> =
    throw UnsupportedOperationException("iOS has no API to list the system's root certificates; pass trust anchors explicitly")
