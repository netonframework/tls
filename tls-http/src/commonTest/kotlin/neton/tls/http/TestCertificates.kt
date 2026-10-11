package neton.tls.http

import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.fetchAndIncrement

/** A self-signed test certificate (PEM) and its key. Test fixture only, never production trust (SPEC §4). */
class TestIdentity(val certificate: ByteArray, val key: ByteArray)

/**
 * Test fixtures only, never part of production trust configuration: self-signed P-256 certificates for CN=localhost
 * with SAN DNS:localhost, IP:127.0.0.1, generated once with the OpenSSL command line (2026-10-11). Three valid until
 * 2125 and one expired in 2021, fixed so that native and JVM tests use the same ones (the JVM has no certificate
 * generation API). Consecutive [testIdentity] calls return different identities, as a fresh key each time did.
 */
@OptIn(ExperimentalAtomicApi::class)
private val next = AtomicInt(0)

@OptIn(ExperimentalAtomicApi::class)
fun testIdentity(expired: Boolean = false): TestIdentity =
    if (expired) EXPIRED else VALID[next.fetchAndIncrement() % VALID.size]

private val A = TestIdentity(
    """
-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUHadhZR7pWOWABVEMadujWaTbXOQwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjUxMjMx
MDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAT4ZJaDv/RojoRK7gjpxRVRTO9mAcCVr43ZSPuY0pohOcnl7YoBbSXi
TF5knCixhi6+zsyrXnHbMjIzUyZu4Kh4o28wbTAdBgNVHQ4EFgQUAvTeb4il7OFm
UWqdgj82R3H/1nYwHwYDVR0jBBgwFoAUAvTeb4il7OFmUWqdgj82R3H/1nYwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIgOWsLTQFLgx+wpXjCmCT2e+Z2ft7Vtjd60Ga/fj2Uc30CIQDt
ceKvfH4AFvwtlkLJmE5dFvu18S+Gj3k9I/f/hETnYg==
-----END CERTIFICATE-----
""".encodeToByteArray(),
    """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHT9ts3ea0fH0yImd
z+XykwC+YBn1NJh52BJIHzL/JBihRANCAAT4ZJaDv/RojoRK7gjpxRVRTO9mAcCV
r43ZSPuY0pohOcnl7YoBbSXiTF5knCixhi6+zsyrXnHbMjIzUyZu4Kh4
-----END PRIVATE KEY-----
""".encodeToByteArray(),
)

private val B = TestIdentity(
    """
-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUf0G2MKblio2Sq2QeyLivqOe58IUwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjUxMjMx
MDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQwAYElc3b9Rf+2q0JTxr3IJawFxadlwVnUMjc28RXAHYH02n6I+8zO
zTHZhMSabMiqLI4/qAQE2DoZlH2ow/Hwo28wbTAdBgNVHQ4EFgQU/fiDJD81sDD8
r8m/vPinOVrP8WcwHwYDVR0jBBgwFoAU/fiDJD81sDD8r8m/vPinOVrP8WcwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIgfTKGI0U4TMlDGxqASQl9qtwVWah7vb6mB6fDCXEOxUwCIQCR
bk5ESwVTK33oDgtMxAEisimr4LhDl+/CgOfibsjO5Q==
-----END CERTIFICATE-----
""".encodeToByteArray(),
    """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/YZoPEH98H01jfgK
QXJLU/J65gA4jkWOHwOCFd4sklChRANCAAQwAYElc3b9Rf+2q0JTxr3IJawFxadl
wVnUMjc28RXAHYH02n6I+8zOzTHZhMSabMiqLI4/qAQE2DoZlH2ow/Hw
-----END PRIVATE KEY-----
""".encodeToByteArray(),
)

private val C = TestIdentity(
    """
-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUT93GvkzbDg8APNiD9Fy9ntxoMYYwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjUxMjMx
MDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARXYbnuAbBTDcEVSj878FJHyxCjTfboQ0FsrrX8GaQ06cCIgA0S+xow
2tsYgpH+aSvcG9N1GYSzNKEl1mzHG9tpo28wbTAdBgNVHQ4EFgQUgu8TWs7BNSWT
aHM+0C5IJTU8rowwHwYDVR0jBBgwFoAUgu8TWs7BNSWTaHM+0C5IJTU8rowwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDRwAwRAIgXQlFInIUGPRGX/HGT++y64GXkMXCT3Jrb97+lNL6rtkCIAQM
w91hT1aFqcpMy4U4kupsrVo/osXBfMkT+Pwc5wUZ
-----END CERTIFICATE-----
""".encodeToByteArray(),
    """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKLfdCSWM87/QzY1D
A6swIP/U0iJs1gbabKeMH15JZnqhRANCAARXYbnuAbBTDcEVSj878FJHyxCjTfbo
Q0FsrrX8GaQ06cCIgA0S+xow2tsYgpH+aSvcG9N1GYSzNKEl1mzHG9tp
-----END PRIVATE KEY-----
""".encodeToByteArray(),
)

private val EXPIRED = TestIdentity(
    """
-----BEGIN CERTIFICATE-----
MIIBmTCCAT+gAwIBAgIUS38XVV6I15YKKoGRqafITgZ8p/YwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIwMDEwMTAwMDAwMFoXDTIxMDEwMTAw
MDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE8kqkHLWQs/MtXMJ9YmfIuWNb3NvI9uheREFC0S44eOYOGTQv1OwIDGU2
zzJMdM1BuYcQu5/cqlECBK6BAsN186NvMG0wHQYDVR0OBBYEFHGSeQjmjB9TtslN
qZOH9RcUG06XMB8GA1UdIwQYMBaAFHGSeQjmjB9TtslNqZOH9RcUG06XMA8GA1Ud
EwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49
BAMCA0gAMEUCIFee5DqKNbo4/EdBbyVnR26Ts4e7GlmQXS+14S6iTZDUAiEA1S6N
cBlQ37mSIzWABkzKdBcbpdq3AT+Dm6y8XLDzw/E=
-----END CERTIFICATE-----
""".encodeToByteArray(),
    """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5C+9z91dHiEMsUko
luNc9JXzaamcDq5G11/Umx5viI6hRANCAATySqQctZCz8y1cwn1iZ8i5Y1vc28j2
6F5EQULRLjh45g4ZNC/U7AgMZTbPMkx0zUG5hxC7n9yqUQIEroECw3Xz
-----END PRIVATE KEY-----
""".encodeToByteArray(),
)

private val VALID = listOf(A, B, C)
