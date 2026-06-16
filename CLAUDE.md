# CLAUDE.md

本文件为 Claude Code（claude.ai/code）在本仓库中工作时提供指引。

## 项目概述

TrickyStore 是一个 Android Magisk/KernelSU 模块，通过拦截 Android Keystore 认证（attestation）来伪装设备完整性校验（Play Integrity）。其工作方式是：注入 `keystore2` 系统进程、hook Binder 事务，并将认证请求转发到远端的干净设备（“proxy-only/纯代理”架构）。要求 Android 12+（SDK 31）。

## 构建命令

```bash
# 构建完整的 Magisk 模块 ZIP（release）
./gradlew :module:zipRelease
# 输出：module/release/TrickyStore-*.zip

# 构建 debug 变体
./gradlew :module:zipDebug

# 仅构建 service APK
./gradlew :service:assembleRelease

# 通过 ADB 部署到设备（推送 ZIP，然后安装）
./gradlew :module:installMagiskRelease    # Magisk
./gradlew :module:installKsuRelease       # KernelSU

# 仅热替换设备上的 service APK（无需重启）
./gradlew :service:pushServiceRelease
./gradlew :service:pushAndRestartServiceRelease  # 推送 + 重启 keystore2

# 清理
./gradlew Delete
```

构建环境要求：JDK 17、Android SDK 34、NDK 27.0.12077973、CMake 3.28.0+。

## 架构

### 三个 Gradle 模块

- **`:module`** — Native C++ 代码（Binder 拦截、进程注入、Zygisk）。产出 Magisk 模块 ZIP，内含 native `.so` 库、shell 脚本和 service APK。
- **`:service`** — Kotlin/Java 后台守护进程 APK。以 root 运行，拦截 keystore 操作，并将认证转发到远端代理中继（`ProxyClient`）。
- **`:stub`** — 仅编译期使用的 Android 内部 API 桩（`android.system.keystore2.*`、`android.hardware.security.keymint.*`、`ServiceManager`、`SystemProperties`、`IPackageManager`），这些不在公开 SDK 中。

### 数据流

1. **注入**：`libinject.so` 通过 ptrace attach 到 `keystore2` 进程，并用 dlopen 加载 `libtricky_store.so`
2. **Binder Hook**：`binder_interceptor.cpp` 替换 `IKeystoreSecurityLevel`（TEE/StrongBox）的 `BBinder`，拦截 `getKeyEntry()` 和 `generateKey()` 事务
3. **服务协调**：Java/Kotlin 服务（`KeystoreInterceptor.kt` / `SecurityLevelInterceptor.kt`）注册拦截器，并将 `generateKey()`/`createOperation()` 转发到远端代理
4. **代理转发**：`target.txt` 中列出的每个包都会经由 `ProxyClient` 转发到远端干净设备，由其返回真实的认证证书链。本地不做任何证书伪造或生成，也没有 `keybox.xml`。
5. **Zygisk**（可选）：`libtszygisk.so` 在应用进程启动时 hook，依据 `/data/adb/tricky_store/spoof_build_vars` 伪装 `Build.*` 字段

### 关键源文件

**服务（Kotlin/Java）：**
- `service/.../Main.kt` — 入口；通过 `module.prop` 的 SHA-256 校验和验证模块完整性
- `service/.../KeystoreInterceptor.kt` — 注册 Binder 拦截器；为 `getKeyEntry()` 提供缓存的代理响应，并转发 `deleteKey()`
- `service/.../SecurityLevelInterceptor.kt` — 拦截 `generateKey()`/`createOperation()` 并转发到代理
- `service/.../Config.kt` — 基于 FileObserver 的热重载，监听 `/data/adb/tricky_store/` 下的 `target.txt`、`proxy.txt`、`card.txt`
- `service/.../proxy/ProxyClient.kt` — 远端中继的 HTTP 客户端（generate/operation/update/finish/delete）
- `service/.../proxy/ProxyOperationBinder.kt` — 将 keystore 加密操作代理到远端设备的 Binder

**Native C++：**
- `module/src/main/cpp/binder_interceptor.cpp` — 用于 Binder 事务前/后 hook 的 BBinder 子类
- `module/src/main/cpp/inject/main.cpp` — 基于 ptrace 注入 keystore2 进程
- `module/src/main/cpp/zygisk/main.cpp` — 用于 Build 变量伪装的 Zygisk 模块
- `module/src/main/cpp/external/` — LSPlt 子模块（来自 LSPosed 的 PLT hook）

**模块模板**（`module/template/`）：
- Shell 脚本（`customize.sh`、`service.sh`、`post-fs-data.sh`、`daemon`）在构建时进行 `@TOKEN@` 替换
- `module.prop` 使用 Gradle 的 `expand()` 进行属性替换

### 构建配置

所有版本信息和模块元数据都在根目录的 `build.gradle.kts` 中以 `extra` 属性定义（`moduleId`、`verName`、`verCode` 等）。`verCode` 由 `git rev-list HEAD --count` 推导得出。支持的 ABI：`arm64-v8a`、`x86_64`。

service APK 构建（`service/build.gradle.kts`）会在构建时根据模块元数据计算 SHA-256 校验和，嵌入为 `BuildConfig.CHECKSUM` 用于运行时完整性校验。

### 运行时配置

所有配置位于设备的 `/data/adb/tricky_store/`，无需重启即可热重载：
- `target.txt` — 需要拦截的包名（每行一个；旧的 `@`/`!` 后缀会被去除/忽略）
- `proxy.txt` — 代理中继的基础 URL（缺失/为空时回退到内置默认值）
- `card.txt` — 可选的计费卡密，随每次代理请求发送
- `spoof_build_vars` — 用于 Build.* 字段伪装的 Key=value 键值对（需要 Zygisk）
