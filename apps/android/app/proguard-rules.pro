# BouncyCastle: only the lightweight Argon2/HKDF classes are used; the provider's optional
# integrations (LDAP, JNDI, …) are not on Android.
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
# Generated serializers are kept by kotlinx-serialization's own consumer rules.
