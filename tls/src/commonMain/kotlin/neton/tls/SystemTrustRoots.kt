@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package neton.tls

import neton.openssl.QuicTlsCredentials
import kotlin.io.encoding.Base64

// The operating system's trusted root certificates (rustls-native-certs `load_native_certs`), for clients that verify
// servers on the public Internet: `TlsContext(server = false, trustRootsPem = systemTrustRootsPem(), ...)`. As
// rustls-native-certs, `SSL_CERT_FILE` (a PEM bundle) and `SSL_CERT_DIR` (directories of PEM files, ':'-separated)
// replace the platform's store when set. The same sources as com.netonstream:quic's `Certificates.system()`.

/**
 * The system's trusted roots as one PEM bundle (each certificate parsed and checked, duplicates once). Linux: the
 * distribution's CA bundle (or `/etc/ssl/certs`); Android: the system CA directory; macOS: the Security framework's
 * anchor certificates; Windows: the system ROOT store. Read on every call; keep the result.
 *
 * @throws UnsupportedOperationException on iOS, which has no API to list them.
 * @throws IllegalStateException when no certificate is found.
 */
fun systemTrustRootsPem(): ByteArray {
    val der = systemRootsDer()
    check(der.isNotEmpty()) { "no system root certificates found (set SSL_CERT_FILE or pass trust roots)" }
    val out = StringBuilder()
    for (cert in der) {
        out.append("-----BEGIN CERTIFICATE-----\n")
        Base64.Default.encode(cert).chunked(64).forEach { out.append(it).append('\n') }
        out.append("-----END CERTIFICATE-----\n")
    }
    return out.toString().encodeToByteArray()
}

/** The platform's trusted roots as DER, in no particular order; may contain duplicates. */
internal expect fun platformRootsDer(): List<ByteArray>

/** The names in [dir] other than `.` and `..`, or null when it cannot be opened (opendir differs per platform). */
internal expect fun listDirectory(dir: String): List<String>?

internal fun systemRootsDer(): List<ByteArray> {
    val file = environmentVariable("SSL_CERT_FILE")?.ifEmpty { null }
    val dirs = environmentVariable("SSL_CERT_DIR")?.ifEmpty { null }
    val found = if (file != null || dirs != null) {
        val out = ArrayList<ByteArray>()
        if (file != null) readFileOrNull(file)?.let { out += pemCertificates(it) }
        dirs?.split(':')?.filter { it.isNotEmpty() }?.forEach { out += pemDirectory(it) }
        out
    } else {
        platformRootsDer()
    }
    // Duplicates (hashed links in certificate directories) are kept once; anything that does not parse is dropped
    val seen = HashSet<List<Byte>>()
    return found.filter { isCertificate(it) && seen.add(it.asList()) }
}

private fun isCertificate(der: ByteArray): Boolean = QuicTlsCredentials.isCertificate(der)

/** Every CERTIFICATE block of a PEM document as DER; anything else (text, other blocks) is skipped. */
internal fun pemCertificates(pem: ByteArray): List<ByteArray> =
    if (pem.isEmpty()) emptyList() else QuicTlsCredentials.pemCertificates(pem)

/** The certificates of every PEM file in [dir] (no recursion); an unreadable directory gives none. */
internal fun pemDirectory(dir: String): List<ByteArray> =
    listDirectory(dir)?.flatMap { name -> readFileOrNull("$dir/$name")?.let { pemCertificates(it) } ?: emptyList() } ?: emptyList()

/** The whole file, or null when it cannot be opened. */
internal expect fun readFileOrNull(path: String): ByteArray?

/** The environment variable [name], or null. */
internal expect fun environmentVariable(name: String): String?
