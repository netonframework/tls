plugins { kotlin("multiplatform") }

// The targets com.netonstream:openssl and com.netonstream:io both provide.
kotlin {
    linuxX64(); linuxArm64()
    macosArm64(); macosX64()
    mingwX64()
    iosArm64(); iosSimulatorArm64(); iosX64()
    androidNativeArm64(); androidNativeX64()

    sourceSets {
        commonMain.dependencies {
            api("com.netonstream:io:0.2.0-SNAPSHOT")
            api("com.netonstream:openssl:4.0.2")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
            implementation("com.netonstream:io-testkit:0.2.0-SNAPSHOT")
        }
    }
}
