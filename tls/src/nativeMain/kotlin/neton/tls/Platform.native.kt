@file:OptIn(ExperimentalForeignApi::class)

package neton.tls

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toKString
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.getenv

internal actual fun environmentVariable(name: String): String? = getenv(name)?.toKString()

/** The whole file, or null when it cannot be opened. */
internal actual fun readFileOrNull(path: String): ByteArray? {
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
