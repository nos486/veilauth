// `-Pveilauth.coreOnly=true` builds only the pure-JVM modules. They need nothing from Google
// Maven, so they build anywhere a JDK and Maven Central are reachable.
val coreOnly = providers.gradleProperty("veilauth.coreOnly").orNull == "true"

pluginManagement {
    repositories {
        if (providers.gradleProperty("veilauth.coreOnly").orNull != "true") {
            google {
                content {
                    includeGroupByRegex("com\\.android.*")
                    includeGroupByRegex("com\\.google.*")
                    includeGroupByRegex("androidx.*")
                }
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        if (!coreOnly) google()
        mavenCentral()
    }
}

rootProject.name = "veilauth"

include(":core:otp")
include(":core:crypto")
include(":core:api")
include(":core:vault")
if (!coreOnly) include(":app")
