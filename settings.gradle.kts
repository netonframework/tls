pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    // com.netonstream:openssl comes from mavenLocal until it is on Maven Central.
    repositories { mavenLocal(); mavenCentral() }
}
rootProject.name = "tls-build"
include(":tls")
// com.netonstream:io and io-testkit from the sibling checkout.
includeBuild("../neton-io")
// Unpublished benchmark executables (SPEC §5).
include(":tls-bench")
