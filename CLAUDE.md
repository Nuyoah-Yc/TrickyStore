# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TrickyStore is an Android Magisk/KernelSU module that intercepts Android Keystore attestation to spoof device integrity checks (Play Integrity). It works by injecting into the `keystore2` system process, hooking Binder transactions, and replacing or generating attestation certificate chains. Requires Android 12+ (SDK 31).

## Build Commands

```bash
# Build the full Magisk module ZIP (release)
./gradlew :module:zipRelease
# Output: module/release/TrickyStore-*.zip

# Build debug variant
./gradlew :module:zipDebug

# Build only the service APK
./gradlew :service:assembleRelease

# Deploy to device via ADB (push ZIP, then install)
./gradlew :module:installMagiskRelease    # Magisk
./gradlew :module:installKsuRelease       # KernelSU

# Hot-swap just the service APK on device (no reboot)
./gradlew :service:pushServiceRelease
./gradlew :service:pushAndRestartServiceRelease  # push + restart keystore2

# Clean
./gradlew Delete
```

The build requires: JDK 17, Android SDK 34, NDK 27.0.12077973, CMake 3.28.0+.

## Architecture

### Three Gradle Modules

- **`:module`** — Native C++ code (Binder interception, process injection, Zygisk). Produces the Magisk module ZIP containing native `.so` libraries, shell scripts, and the service APK.
- **`:service`** — Kotlin/Java background daemon APK. Runs as root, intercepts keystore operations, and performs certificate hacking/generation using BouncyCastle.
- **`:stub`** — Compile-only stubs for Android internal APIs (`android.system.keystore2.*`, `android.hardware.security.keymint.*`, `ServiceManager`, `SystemProperties`, `IPackageManager`) that are not in the public SDK.

### Data Flow

1. **Injection**: `libinject.so` ptrace-attaches to the `keystore2` process and loads `libtricky_store.so` via dlopen
2. **Binder Hooking**: `binder_interceptor.cpp` replaces the `BBinder` for `IKeystoreSecurityLevel` (TEE/StrongBox), intercepting `getKeyEntry()` and `generateKey()` transactions
3. **Service Coordination**: The Java/Kotlin service (`KeystoreInterceptor.kt`) registers interceptors and delegates to `CertHack.java` for certificate manipulation
4. **Certificate Modes**: Per-package config in `target.txt` — default "hack" mode patches the leaf cert; `!` suffix triggers full certificate chain generation from `keybox.xml`
5. **Zygisk** (optional): `libtszygisk.so` hooks app process startup to spoof `Build.*` fields from `/data/adb/tricky_store/spoof_build_vars`

### Key Source Files

**Service (Kotlin/Java):**
- `service/.../Main.kt` — Entry point; verifies module integrity via SHA-256 checksum of `module.prop`
- `service/.../KeystoreInterceptor.kt` — Registers Binder interceptors for TEE and StrongBox security levels
- `service/.../SecurityLevelInterceptor.kt` — Intercepts `generateKey()` for cert-generation mode packages
- `service/.../Config.kt` — FileObserver-based hot-reload of `target.txt` and `keybox.xml` from `/data/adb/tricky_store/`
- `service/.../keystore/CertHack.java` — Core logic: X.509 cert chain creation, ASN.1 attestation extensions, ECDSA/RSA key generation
- `service/.../keystore/XMLParser.java` — Custom parser for keybox.xml (XPath-like indexed tag access)

**Native C++:**
- `module/src/main/cpp/binder_interceptor.cpp` — BBinder subclass for pre/post Binder transaction hooking
- `module/src/main/cpp/inject/main.cpp` — ptrace-based injection into keystore2 process
- `module/src/main/cpp/zygisk/main.cpp` — Zygisk module for Build variable spoofing
- `module/src/main/cpp/external/` — LSPlt submodule (PLT hooking from LSPosed)

**Module Template** (`module/template/`):
- Shell scripts (`customize.sh`, `service.sh`, `post-fs-data.sh`, `daemon`) use `@TOKEN@` replacement at build time
- `module.prop` uses Gradle `expand()` for property substitution

### Build Configuration

All version info and module metadata is defined in root `build.gradle.kts` as `extra` properties (`moduleId`, `verName`, `verCode`, etc.). The `verCode` is derived from `git rev-list HEAD --count`. Supported ABIs: `arm64-v8a`, `x86_64`.

The service APK build (`service/build.gradle.kts`) computes a SHA-256 checksum from module metadata at build time, embedded as `BuildConfig.CHECKSUM` for runtime integrity verification.

### Runtime Configuration

All config lives at `/data/adb/tricky_store/` on device and hot-reloads without reboot:
- `target.txt` — Package names to intercept (append `!` for cert-generation mode)
- `keybox.xml` — Private keys + certificate chains in Android keybox XML format
- `spoof_build_vars` — Key=value pairs for Build.* field spoofing (requires Zygisk)
