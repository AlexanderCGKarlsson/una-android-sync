plugins {
    id("com.android.library") version "9.4.0" apply false
    id("org.jetbrains.kotlin.android") version "2.3.10" apply false
    id("org.jetbrains.kotlin.jvm") version "2.3.10" apply false
    id("org.jetbrains.kotlin.plugin.serialization") version "2.3.10" apply false
}

group = "app.una"
version = "0.1.0-SNAPSHOT"

allprojects {
    dependencyLocking {
        lockAllConfigurations()
    }
}
