// All Gradle plugins are put on the root build classpath so Kotlin's and Android's plugins share
// one classloader (KGP needs to see AGP's types). Android plugins come from Google Maven and are
// left out of a core-only build (-Pveilauth.coreOnly=true), which needs only Maven Central.
// Versions follow android/nowinandroid (checked 2026-10-21).
buildscript {
    val coreOnly = providers.gradleProperty("veilauth.coreOnly").orNull == "true"
    val kotlinVersion = "2.3.21"
    repositories {
        if (!coreOnly) google()
        mavenCentral()
        gradlePluginPortal()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
        classpath("org.jetbrains.kotlin:kotlin-serialization:$kotlinVersion")
        if (!coreOnly) {
            classpath("com.android.tools.build:gradle:9.3.2")
            classpath("org.jetbrains.kotlin:compose-compiler-gradle-plugin:$kotlinVersion")
            classpath("com.google.devtools.ksp:symbol-processing-gradle-plugin:2.3.12")
        }
    }
}
