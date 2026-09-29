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
// Unpublished benchmark executables (SPEC §5).
include(":tls-bench")
