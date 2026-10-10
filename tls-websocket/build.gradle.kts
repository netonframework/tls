plugins { kotlin("multiplatform"); `maven-publish` }

// com.netonstream:tls-websocket: wss for com.netonstream:websocket (its TlsConnector), the role of tokio-tungstenite's
// rustls / native-tls features. Kept out of websocket, which has no TLS of its own.
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api(project(":tls"))
            api("com.netonstream:websocket:0.2.0")
        }
        commonTest.dependencies { implementation(kotlin("test")) }
    }
}

// The cross-layer tests (CompositionTest, SPEC §10) check fixes in http / websocket after 0.2.0: run them against their
// main branches (--include-build); -PskipComposition leaves them out when building against the released versions.
if (providers.gradleProperty("skipComposition").isPresent) {
    tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest>().configureEach {
        filter.excludeTestsMatching("*CompositionTest*")
    }
}
