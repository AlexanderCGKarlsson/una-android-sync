import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.una.android.sync"
    compileSdk = 36

    defaultConfig {
        minSdk = 28
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.fromTarget("17")
        allWarningsAsErrors = true
    }
}

dependencies {
    api(project(":crypto-core"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")

    // @dev This explicit JNA version provides Android 16 KB memory-page support instead of using
    // the older transitive version from the Convex client.
    implementation("net.java.dev.jna:jna:5.18.0@aar")

    // @notice Keep this aligned with the Convex client version verified in the Una Android app.
    // Upgrade only after the ciphertext adapter and Android release build pass together.
    implementation("dev.convex:android-convexmobile:0.8.0@aar") {
        isTransitive = true
    }

    testImplementation("junit:junit:4.13.2")
}
