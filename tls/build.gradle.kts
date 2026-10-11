plugins { kotlin("multiplatform"); `maven-publish` }

// The targets com.netonstream:openssl and com.netonstream:io both provide.
kotlin {
    // The JVM (desktop and Android apps): TLS through openssl-kotlin's JNI library; bytecode 1.8, API 2.2 and stdlib
    // 2.2.21 so Android hosts on Kotlin 2.1 can use it (as neton-io and openssl).
    coreLibrariesVersion = "2.2.21"
    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_1_8)
            apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        }
    }
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api("com.netonstream:io:0.3.2")
            api("com.netonstream:openssl:4.0.2-3")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("com.netonstream:io-testkit:0.3.2")
        }
    }
}
