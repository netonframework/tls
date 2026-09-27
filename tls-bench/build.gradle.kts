plugins { kotlin("multiplatform") }

kotlin {
    listOf(linuxX64(), linuxArm64(), macosArm64()).forEach { target ->
        target.binaries {
            executable("tlsEcho") { entryPoint = "neton.tls.bench.main" }
        }
    }
    sourceSets {
        commonMain.dependencies { implementation(project(":tls")) }
    }
}
