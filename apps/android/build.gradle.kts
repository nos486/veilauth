// Plugins shared by several modules are loaded once here so every module sees the same
// classloader. Android plugins are applied in :app only, which is not part of a core-only build.
plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
}
