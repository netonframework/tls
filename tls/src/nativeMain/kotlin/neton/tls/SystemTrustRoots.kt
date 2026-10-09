@file:OptIn(ExperimentalForeignApi::class)

package neton.tls

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import neton.openssl.c.BIO_free
import neton.openssl.c.BIO_new_mem_buf
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.PEM_read_bio_X509
import neton.openssl.c.X509_free
import neton.openssl.c.d2i_X509
import neton.openssl.c.i2d_X509
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.getenv
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
    val file = getenv("SSL_CERT_FILE")?.toKString()?.ifEmpty { null }
    val dirs = getenv("SSL_CERT_DIR")?.toKString()?.ifEmpty { null }
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

private fun isCertificate(der: ByteArray): Boolean = memScoped {
    if (der.isEmpty()) return@memScoped false
    val x = der.usePinned { pinned ->
        val p = alloc<CPointerVar<UByteVar>>()
        p.value = pinned.addressOf(0).reinterpret()
        d2i_X509(null, p.ptr, der.size.convert())
    }
    if (x == null) {
        ERR_clear_error()
        false
    } else {
        X509_free(x)
        true
    }
}

/** Every CERTIFICATE block of a PEM document as DER; anything else (text, other blocks) is skipped. */
internal fun pemCertificates(pem: ByteArray): List<ByteArray> {
    val out = ArrayList<ByteArray>()
    if (pem.isEmpty()) return out
    pem.usePinned { pinned ->
        val bio = BIO_new_mem_buf(pinned.addressOf(0), pem.size) ?: return out
        try {
            while (true) {
                val x = PEM_read_bio_X509(bio, null, null, null) ?: break
                try {
                    val len = i2d_X509(x, null)
                    if (len > 0) {
                        val der = ByteArray(len)
                        memScoped {
                            der.usePinned { d ->
                                val p = alloc<CPointerVar<UByteVar>>()
                                p.value = d.addressOf(0).reinterpret()
                                i2d_X509(x, p.ptr)
                            }
                        }
                        out += der
                    }
                } finally {
                    X509_free(x)
                }
            }
        } finally {
            BIO_free(bio)
        }
    }
    ERR_clear_error() // the "no start line" that ends the loop
    return out
}

/** The certificates of every PEM file in [dir] (no recursion); an unreadable directory gives none. */
internal fun pemDirectory(dir: String): List<ByteArray> =
    listDirectory(dir)?.flatMap { name -> readFileOrNull("$dir/$name")?.let { pemCertificates(it) } ?: emptyList() } ?: emptyList()

/** The whole file, or null when it cannot be opened. */
internal fun readFileOrNull(path: String): ByteArray? {
    val f = fopen(path, "rb") ?: return null
    try {
        val chunks = ArrayList<ByteArray>()
        memScoped {
            val buf = allocArray<ByteVar>(CHUNK)
            while (true) {
                val n = fread(buf, 1u, CHUNK.toULong(), f).toInt()
                if (n <= 0) break
                chunks += buf.readBytes(n)
            }
        }
        val all = ByteArray(chunks.sumOf { it.size })
        var at = 0
        for (c in chunks) { c.copyInto(all, at); at += c.size }
        return all
    } finally {
        fclose(f)
    }
}

private const val CHUNK = 64 * 1024
