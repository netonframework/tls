@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package neton.tls.bench

import kotlinx.cinterop.toKString
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.io.bytes.Buffer
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.net.connect
import neton.io.net.listen
import neton.io.net.runReactor
import neton.openssl.PeerIdentity
import neton.openssl.TlsContext
import neton.openssl.TlsVersion
import neton.tls.tlsAccept
import neton.tls.tlsConnect
import kotlin.time.TimeSource

/**
 * TLS echo benchmark (SPEC §5). One reactor per process.
 *   tlsEcho server PORT CERTDIR             raw byte echo over TLS 1.3; writes CERTDIR/cert.pem, key.pem
 *   tlsEcho client PORT CERTDIR CONNS SECS PAYLOAD
 *                                           closed loop, one request in flight per connection; prints requests
 * NETON_TLS_RUN_SECONDS=n stops the server after n seconds.
 */
fun main(args: Array<String>) {
    when (args.getOrNull(0)) {
        "server" -> server(args[1].toInt(), args[2])
        "client" -> client(args[1].toInt(), args[2], args[3].toInt(), args[4].toInt(), args[5].toInt())
        else -> println("usage: tlsEcho server PORT CERTDIR | client PORT CERTDIR CONNS SECS PAYLOAD")
    }
}

private fun readFile(path: String): ByteArray {
    val f = platform.posix.fopen(path, "rb") ?: error("cannot open $path")
    try {
        val out = ArrayList<Byte>()
        while (true) { val c = platform.posix.fgetc(f); if (c < 0) break; out.add(c.toByte()) }
        return out.toByteArray()
    } finally { platform.posix.fclose(f) }
}

private fun writeFile(path: String, data: ByteArray) {
    val f = platform.posix.fopen(path, "wb") ?: error("cannot write $path")
    try { data.forEach { platform.posix.fputc(it.toInt(), f) } } finally { platform.posix.fclose(f) }
}

private fun server(port: Int, dir: String) {
    val id = testIdentity()
    writeFile("$dir/cert.pem", id.certificate); writeFile("$dir/key.pem", id.key)
    val ctx = TlsContext(true, null, id.certificate, id.key, TlsVersion.TLS13, TlsVersion.TLS13)
    val runSeconds = platform.posix.getenv("NETON_TLS_RUN_SECONDS")?.toKString()?.toLongOrNull()
    println("tls-echo listening on 127.0.0.1:$port")
    runReactor {
        val l = listen("127.0.0.1", port)
        if (runSeconds != null) launch { delay(runSeconds * 1000); l.close() }
        try {
            while (true) {
                val raw = l.accept()
                launch { echo(raw, ctx) }
            }
        } catch (_: neton.io.core.ClosedException) {
        }
    }
    ctx.close()
}

private suspend fun echo(raw: IoStream, ctx: TlsContext) {
    val s = try { tlsAccept(raw, ctx) } catch (_: IoException) { return }
    val buf = Buffer()
    try {
        while (true) {
            buf.clear()
            if (s.read(buf) < 0) break
            s.write(buf)
        }
    } catch (_: IoException) {
    } finally { s.close() }
}

private fun client(port: Int, dir: String, conns: Int, secs: Int, payload: Int) {
    val ctx = TlsContext(false, readFile("$dir/cert.pem"), minimumVersion = TlsVersion.TLS13, maximumVersion = TlsVersion.TLS13)
    var total = 0L
    runReactor {
        val streams = List(conns) { tlsConnect(connect("127.0.0.1", port), ctx, PeerIdentity.Dns("localhost")) }
        val until = TimeSource.Monotonic.markNow()
        val jobs = streams.map { s ->
            launch {
                val out = ByteArray(payload) { 'x'.code.toByte() }
                val w = Buffer(); val r = Buffer()
                while (until.elapsedNow().inWholeSeconds < secs) {
                    w.writeBytes(out); s.write(w)
                    var got = 0
                    while (got < payload) { r.clear(); val n = s.read(r); if (n < 0) return@launch; got += n }
                    total++
                }
            }
        }
        jobs.forEach { it.join() }
        streams.forEach { runCatching { it.shutdownOutput() }; it.close() }
    }
    ctx.close()
    println("requests $total")
}
