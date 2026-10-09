pluginManagement {
    repositories { gradlePluginPortal(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories {
        providers.gradleProperty("releaseRepositories").orNull?.split(",")?.forEach { path ->
            maven { url = uri(path) }
        }
        mavenCentral()
    }
}
rootProject.name = "tls-build"
include(":tls")
// HTTPS for com.netonstream:http and wss for com.netonstream:websocket on top of :tls.
include(":tls-http")
include(":tls-websocket")
// Unpublished benchmark executables (SPEC §5).
include(":tls-bench")
