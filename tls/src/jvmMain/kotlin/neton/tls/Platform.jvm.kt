package neton.tls

import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * The JVM's default trust anchors as DER: the system CA store on Android (through the default TrustManagerFactory),
 * the JDK's cacerts elsewhere.
 */
internal actual fun platformRootsDer(): List<ByteArray> {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(null as KeyStore?)
    return factory.trustManagers.filterIsInstance<X509TrustManager>()
        .flatMap { it.acceptedIssuers.toList() }
        .map(X509Certificate::getEncoded)
}

internal actual fun listDirectory(dir: String): List<String>? = File(dir).list()?.toList()

internal actual fun readFileOrNull(path: String): ByteArray? = try {
    File(path).readBytes()
} catch (_: IOException) {
    null
} catch (_: SecurityException) {
    null
}

internal actual fun environmentVariable(name: String): String? = System.getenv(name)
