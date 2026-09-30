# tls

TLS for Kotlin/Native as a `com.netonstream:io` `IoStream`, built on `com.netonstream:openssl` (OpenSSL 4.0.2).
Package `neton.tls`. See [SPEC.md](SPEC.md).

Release coordinate: `com.netonstream:tls:0.1.0`, which depends on `io:0.1.0` and `openssl:0.1.0`. That openssl
version was published by mistake; it is the same build as `openssl:4.0.2` (the version follows upstream OpenSSL),
and later tls releases depend on `openssl:4.0.2`. Builds use Maven Central by default;
`-PreleaseRepositories=<staging-directory>` is an explicit release-verification override.
