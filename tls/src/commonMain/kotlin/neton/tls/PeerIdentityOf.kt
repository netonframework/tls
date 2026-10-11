package neton.tls

import neton.openssl.PeerIdentity

/**
 * The identity to verify for [host] as it appears in a URL: an IP literal (`127.0.0.1`, `::1`, `[::1]`) is checked
 * against the certificate's IP addresses, anything else against its DNS names (and sent as SNI).
 */
fun peerIdentityOf(host: String): PeerIdentity {
    val h = host.removeSurrounding("[", "]")
    return if (isIpLiteral(h)) PeerIdentity.Ip(h) else PeerIdentity.Dns(h)
}

private fun isIpLiteral(h: String): Boolean {
    if (':' in h) return h.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }
    val parts = h.split('.')
    return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } && p.toInt() <= 255 }
}
