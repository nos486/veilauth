plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

// Release builds get these from .github/workflows/release.yml; local builds use the defaults.
val appVersionName: String = providers.environmentVariable("VEILAUTH_VERSION_NAME").getOrElse("0.0.0-dev")
val appVersionCode: Int = providers.environmentVariable("VEILAUTH_VERSION_CODE").map(String::toInt).getOrElse(1)
val apiBaseUrl: String =
    providers
        .gradleProperty("veilauth.apiBaseUrl")
        .orElse(providers.environmentVariable("VEILAUTH_API_URL"))
        .getOrElse("https://veilauth.example.workers.dev")

// SPKI pins of the root CAs Cloudflare issues edge certificates from (Google Trust Services,
// Let's Encrypt, SSL.com, Sectigo). A self-hoster on another CA overrides them with
// -Pveilauth.certPins=sha256/…,sha256/… or turns pinning off with -Pveilauth.certPins=none.
// See docs/DECISIONS.md D-047.
val defaultPins =
    listOf(
        "sha256/hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=", // GTS Root R1
        "sha256/QXnt2YHvdHR3tJYmQIr0Paosp6t/nggsEGD4QJZ3Q0g=", // GTS Root R3
        "sha256/mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=", // GTS Root R4
        "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=", // ISRG Root X1
        "sha256/diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=", // ISRG Root X2
        "sha256/0cRTd+vc1hjNFlHcLgLCHXUeWqn80bNDH/bs9qMTSPo=", // SSL.com Root CA RSA
        "sha256/oyD01TTXvpfBro3QSZc1vIlcMjrdLTiL/M9mLCPX+Zo=", // SSL.com Root CA ECC
        "sha256/K89VOmb1cJAN3TK6bf4ezAbJGC1mLcG2Dh97dnwr3VQ=", // SSL.com TLS RSA Root CA 2022
        "sha256/G/ANXI8TwJTdF+AFBM8IiIUPEv0Gf6H5LA/b9guG4yE=", // SSL.com TLS ECC Root CA 2022
        "sha256/x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=", // USERTrust RSA (Sectigo)
        "sha256/ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=", // USERTrust ECC (Sectigo)
    ).joinToString(",")
val certPins: String = providers.gradleProperty("veilauth.certPins").getOrElse(defaultPins)

val keystoreFile: String? = providers.environmentVariable("VEILAUTH_KEYSTORE_FILE").orNull

android {
    namespace = "app.zk2fa"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.zk2fa"
        minSdk = 26
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersionName
        buildConfigField("String", "API_BASE_URL", "\"$apiBaseUrl\"")
        buildConfigField("String", "CERT_PINS", "\"$certPins\"")
        buildConfigField("String", "GITHUB_REPO", "\"nos486/veilauth\"")
    }

    flavorDimensions += "distribution"
    productFlavors {
        // In-app updater that installs signed APKs from GitHub Releases (D-019).
        create("github") { dimension = "distribution" }
        // No updater: F-Droid updates the app itself.
        create("fdroid") { dimension = "distribution" }
    }

    signingConfigs {
        if (keystoreFile != null) {
            create("release") {
                storeFile = file(keystoreFile)
                storePassword = providers.environmentVariable("VEILAUTH_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("VEILAUTH_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("VEILAUTH_KEY_PASSWORD").get()
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (keystoreFile != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += listOf("/META-INF/{AL2.0,LGPL2.1}", "META-INF/versions/9/OSGI-INF/MANIFEST.MF")
        }
    }

    lint {
        abortOnError = true
        checkDependencies = false
        disable += listOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

ksp {
    arg("room.generateKotlin", "true")
}

dependencies {
    implementation(project(":core:vault"))

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit4)
    testImplementation(libs.kotlinx.coroutines.test)
}
