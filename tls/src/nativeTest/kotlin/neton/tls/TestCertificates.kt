@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package neton.tls

import kotlinx.cinterop.*
import neton.openssl.c.*

/** A self-signed test certificate (PEM) and its key. Test fixture only, never production trust (SPEC §4). */
class TestIdentity(val certificate: ByteArray, val key: ByteArray)

/** EC P-256, CN=localhost, SAN DNS:localhost + IP:127.0.0.1; [expired] makes it expire a minute ago. */
fun testIdentity(expired: Boolean = false): TestIdentity = memScoped {
    val keyContext = checkNotNull(EVP_PKEY_CTX_new_from_name(null, "EC", null))
    val out = alloc<CPointerVar<EVP_PKEY>>()
    out.value = null
    try {
        check(EVP_PKEY_keygen_init(keyContext) == 1)
        check(EVP_PKEY_CTX_set_group_name(keyContext, "prime256v1") == 1)
        check(EVP_PKEY_generate(keyContext, out.ptr) == 1)
    } finally { EVP_PKEY_CTX_free(keyContext) }
    val key = checkNotNull(out.value); val cert = checkNotNull(X509_new())
    try {
        check(X509_set_version(cert, 2) == 1)
        check(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1)
        checkNotNull(X509_gmtime_adj(X509_getm_notBefore(cert), -3600))
        checkNotNull(X509_gmtime_adj(X509_getm_notAfter(cert), if (expired) -60 else 3600))
        check(X509_set_pubkey(cert, key) == 1)
        val subject = checkNotNull(X509_get_subject_name(cert))
        check(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, "localhost".cstr.ptr.reinterpret(), -1, -1, 0) == 1)
        check(X509_set_issuer_name(cert, subject) == 1)
        val san = checkNotNull(X509V3_EXT_conf_nid(null, null, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1"))
        try { check(X509_add_ext(cert, san, -1) == 1) } finally { X509_EXTENSION_free(san) }
        check(X509_sign(cert, key, EVP_sha256()) > 0)
        fun encode(writer: (CPointer<BIO>) -> Int): ByteArray {
            val bio = checkNotNull(BIO_new(BIO_s_mem()))
            try {
                check(writer(bio) == 1)
                val bytes = ByteArray(BIO_ctrl_pending(bio).toInt())
                bytes.usePinned { check(BIO_read(bio, it.addressOf(0), bytes.size) == bytes.size) }
                return bytes
            } finally { BIO_free(bio) }
        }
        TestIdentity(encode { PEM_write_bio_X509(it, cert) }, encode { PEM_write_bio_PrivateKey(it, key, null, null, 0, null, null) })
    } finally { X509_free(cert); EVP_PKEY_free(key) }
}
