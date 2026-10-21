import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    explicitApi()
    compilerOptions {
        jvmTarget = JvmTarget.JVM_11
        allWarningsAsErrors = true
    }
}

dependencies {
    implementation(libs.bouncycastle)
    api(libs.kotlinx.serialization.json)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

val specDir: String = rootDir.resolve("../../spec").canonicalPath

// The BIP39 word list is shipped from spec/ so every client reads the same file; its SHA-256 is
// checked when it is loaded (spec/crypto.md §4).
val copyWordlist by tasks.registering(Copy::class) {
    from("$specDir/bip39-english.txt")
    into(layout.buildDirectory.dir("generated/wordlist/app/zk2fa/core/crypto"))
}
sourceSets.main {
    resources.srcDir(copyWordlist.map { layout.buildDirectory.dir("generated/wordlist").get() })
}

tasks.test {
    useJUnitPlatform()
    systemProperty("veilauth.specDir", specDir)
}
