plugins { kotlin("multiplatform"); `maven-publish` }

// com.netonstream:tls-http: HTTPS for com.netonstream:http's pooling client (the role of hyper-rustls for hyper-util).
// Kept out of http, which has no TLS of its own, and out of tls, which does not depend on http.
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api(project(":tls"))
            api("com.netonstream:http:0.2.0")
        }
        commonTest.dependencies { implementation(kotlin("test")) }
    }
}
