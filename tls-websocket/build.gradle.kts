plugins { kotlin("multiplatform"); `maven-publish` }

// com.netonstream:tls-websocket: wss for com.netonstream:websocket (its TlsConnector), the role of tokio-tungstenite's
// rustls / native-tls features. Kept out of websocket, which has no TLS of its own.
kotlin {
    // The JVM (desktop and Android apps): TLS through openssl-kotlin's JNI library; bytecode 1.8, API 2.2 and stdlib
    // 2.2.21 so Android hosts on Kotlin 2.1 can use it (as neton-io and openssl).
    coreLibrariesVersion = "2.2.21"
    // Language 2.2 for every source set the JVM compiles (KMP also requires a source set to be no older than the ones it
    // depends on, so native-only ones may stay newer): class metadata then says 2.2, which a Kotlin 2.1 compiler still
    // reads (one version ahead); with the 2.4 default it refuses to compile against these classes.
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
            apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
            languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        }
        compilations.configureEach { allKotlinSourceSets.forAll { it.languageSettings.languageVersion = "2.2" } }
    }
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api(project(":tls"))
            api("com.netonstream:websocket:0.3.0")
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
