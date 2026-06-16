#include <android/log.h>
#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <jni.h>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tuple>
#include <unistd.h>
#include <utility>
#include <vector>

#include "logging.hpp"
#include "lsplt.hpp"
#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;
using namespace std::string_view_literals;

template <size_t N> struct FixedString {
    // NOLINTNEXTLINE(*-explicit-constructor)
    [[maybe_unused]] consteval inline FixedString(const char (&str)[N]) {
        std::copy_n(str, N, data);
    }
    consteval inline FixedString() = default;
    char data[N] = {};
};

using PropValue = std::array<char, 127>;
using PackageValue = std::array<char, 255>;

template<typename T, FixedString Field, bool Version=false>
struct Prop {
    using Type [[maybe_unused]] = T;
    bool has_value{false};
    PropValue value {};

    [[maybe_unused]] inline consteval static const char *getField() {
        return Field.data;
    }
    [[maybe_unused]] inline consteval static bool isVersion() {
        return Version;
    }
};

static_assert(sizeof(Prop<void, "", false>) % sizeof(void*) == 0);

using SpoofConfig = std::tuple<
    Prop<jstring, "MANUFACTURER">,
    Prop<jstring, "MODEL">,
    Prop<jstring, "FINGERPRINT">,
    Prop<jstring, "BRAND">,
    Prop<jstring, "PRODUCT">,
    Prop<jstring, "DEVICE">,
    Prop<jstring, "BRAND_FOR_ATTESTATION">,
    Prop<jstring, "PRODUCT_FOR_ATTESTATION">,
    Prop<jstring, "DEVICE_FOR_ATTESTATION">,
    Prop<jstring, "MANUFACTURER_FOR_ATTESTATION">,
    Prop<jstring, "MODEL_FOR_ATTESTATION">,
    Prop<jstring, "RELEASE", true>,
    Prop<jstring, "ID">,
    Prop<jstring, "INCREMENTAL", true>,
    Prop<jstring, "TYPE">,
    Prop<jstring, "TAGS">,
    Prop<jstring, "SECURITY_PATCH", true>,
    Prop<jstring, "BOARD">,
    Prop<jstring, "HARDWARE">,
    Prop<jint, "DEVICE_INITIAL_SDK_INT", true>
>;

// ------------------------------------------------------------------
// PIF-style native system property spoofing (ported from
// PlayIntegrityFix). The Zygisk Build-field spoofing above only covers
// reads via android.os.Build / Build.VERSION. DroidGuard and many
// integrity checks read ro.* properties natively through libc's
// __system_property_read_callback. We hook that symbol (via LSPlt PLT
// rewriting, the same engine the original PIF used) in every loaded
// library of the target process and rewrite the values that must stay
// consistent with the spoofed Build fields: security patch, build id and
// the device's initial/first API level. Values are derived entirely from
// the existing spoof_build_vars config — no extra config file.
// ------------------------------------------------------------------

struct prop_info;
using prop_read_callback_t = void (*)(void *cookie, const char *name, const char *value,
                                      uint32_t serial);
using system_property_read_callback_t = int (*)(const prop_info *, prop_read_callback_t, void *);

static system_property_read_callback_t orig_read_callback = nullptr;
// Set right before delegating to libc and consumed synchronously on the
// same thread inside the callback, so thread_local keeps it race-free.
static thread_local prop_read_callback_t saved_callback = nullptr;

namespace prop_spoof {
    static std::string security_patch;  // -> *.security_patch
    static std::string build_id;        // -> *.build.id
    static std::string first_api_level; // -> *api_level
}

static void spoof_prop_callback(void *cookie, const char *name, const char *value,
                                uint32_t serial) {
    if (cookie == nullptr || name == nullptr || value == nullptr || saved_callback == nullptr) {
        return;
    }
    std::string_view prop(name);
    const char *new_value = value;
    if (prop.ends_with("api_level")) {
        if (!prop_spoof::first_api_level.empty()) new_value = prop_spoof::first_api_level.c_str();
    } else if (prop.ends_with(".security_patch")) {
        if (!prop_spoof::security_patch.empty()) new_value = prop_spoof::security_patch.c_str();
    } else if (prop.ends_with(".build.id")) {
        if (!prop_spoof::build_id.empty()) new_value = prop_spoof::build_id.c_str();
    } else if (prop == "init.svc.adbd") {
        new_value = "stopped";
    } else if (prop == "sys.usb.state") {
        new_value = "mtp";
    }
    if (new_value != value) {
        LOGD("spoof prop %s: %s -> %s", name, value, new_value);
    }
    saved_callback(cookie, name, new_value, serial);
}

static int spoof_system_property_read_callback(const prop_info *pi, prop_read_callback_t callback,
                                               void *cookie) {
    if (pi == nullptr || callback == nullptr || cookie == nullptr) {
        return orig_read_callback(pi, callback, cookie);
    }
    saved_callback = callback;
    return orig_read_callback(pi, spoof_prop_callback, cookie);
}

// Pull a single field value out of the already-received SpoofConfig by name.
static std::string field_value(const SpoofConfig &cfg, std::string_view field) {
    std::string result;
    std::apply([&](auto &&... entry) {
        ((entry.has_value &&
          std::string_view(std::remove_cvref_t<decltype(entry)>::getField()) == field
              ? (result.assign(entry.value.data()), true)
              : false) || ...);
    }, cfg);
    return result;
}

// Install the property hook into every file-backed executable mapping of
// the current process. Returns true if libc's original was backed up,
// which means the module must stay loaded (callback code lives in it).
static bool install_property_hook() {
    if (prop_spoof::security_patch.empty() && prop_spoof::build_id.empty() &&
        prop_spoof::first_api_level.empty()) {
        return false;  // nothing to spoof
    }
    std::set<std::pair<dev_t, ino_t>> seen;
    bool registered = false;
    for (auto &map : lsplt::MapInfo::Scan()) {
        if (map.inode == 0 || map.dev == 0) continue;
        if ((map.perms & PROT_EXEC) == 0) continue;
        if (map.path.empty() || map.path.front() != '/') continue;
        if (!std::string_view(map.path).ends_with(".so")) continue;
        if (!seen.emplace(map.dev, map.inode).second) continue;
        if (lsplt::RegisterHook(map.dev, map.inode, "__system_property_read_callback",
                                reinterpret_cast<void *>(spoof_system_property_read_callback),
                                reinterpret_cast<void **>(&orig_read_callback))) {
            registered = true;
        }
    }
    if (registered && lsplt::CommitHook() && orig_read_callback != nullptr) {
        LOGI("property hook installed");
        return true;
    }
    LOGE("failed to install property hook");
    return false;
}


ssize_t xread(int fd, void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = read(fd, buf, count);
        if (ret <= 0) return total > 0 ? total : ret;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

ssize_t xwrite(int fd, const void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = write(fd, buf, count);
        if (ret <= 0) return total > 0 ? total : ret;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

void trim(std::string_view &str) {
    str.remove_prefix(std::min(str.find_first_not_of(" \t"), str.size()));
    str.remove_suffix(std::min(str.size() - str.find_last_not_of(" \t") - 1, str.size()));
}

class TrickyStore : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // NOTE: DLCLOSE_MODULE_LIBRARY is set lazily below. If we end up
        // installing the persistent native property hook, the module must
        // stay mapped (the hook callback lives in it), so we must NOT
        // request unload for that process.
        if (args->app_data_dir == nullptr) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto app_data_dir = env_->GetStringUTFChars(args->app_data_dir, nullptr);
        auto nice_name = env_->GetStringUTFChars(args->nice_name, nullptr);

        std::string_view dir(app_data_dir);
        std::string_view process(nice_name);

        bool isGms = dir.ends_with("/com.google.android.gms");
        std::string packageName;
        if (!dir.empty()) {
            auto lastSlash = dir.find_last_of('/');
            packageName = lastSlash == std::string_view::npos
                          ? std::string(dir)
                          : std::string(dir.substr(lastSlash + 1));
        }
        std::string processName(process);

        env_->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
        env_->ReleaseStringUTFChars(args->nice_name, nice_name);

        if (packageName.empty()) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        if (isGms) {
            api_->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);
        }
        
        int enabled = 0;
        int shouldSpoof = 0;
        SpoofConfig spoofConfig{};
        auto fd = api_->connectCompanion();
        if (fd >= 0) [[likely]] {
            PackageValue package{};
            PackageValue process{};
            strlcpy(package.data(), packageName.c_str(), package.size());
            strlcpy(process.data(), processName.c_str(), process.size());
            xwrite(fd, package.data(), package.size());
            xwrite(fd, process.data(), process.size());

            if (xread(fd, &enabled, sizeof(enabled)) == static_cast<ssize_t>(sizeof(enabled)) && enabled) {
                if (xread(fd, &shouldSpoof, sizeof(shouldSpoof)) ==
                    static_cast<ssize_t>(sizeof(shouldSpoof)) && shouldSpoof) {
                    xread(fd, &spoofConfig, sizeof(spoofConfig));
                }
            }
            close(fd);
        }
        bool keep_loaded = false;
        if (enabled && shouldSpoof) {
            LOGI("spoofing build vars in %s!", packageName.c_str());
            auto buildClass = env_->FindClass("android/os/Build");
            auto buildVersionClass = env_->FindClass("android/os/Build$VERSION");

            std::apply([this, &buildClass, &buildVersionClass](auto &&... args) {
                ((!args.has_value ||
                  (setField<typename std::remove_cvref_t<decltype(args)>::Type>(
                          std::remove_cvref_t<decltype(args)>::isVersion() ? buildVersionClass
                                                                           : buildClass,
                          std::remove_cvref_t<decltype(args)>::getField(),
                          args.value) &&
                   (LOGI("%s set %s to %s",
                         std::remove_cvref_t<decltype(args)>::isVersion() ? "VERSION" : "Build",
                         std::remove_cvref_t<decltype(args)>::getField(),
                         args.value.data()), true))
                  ? void(0)
                  : LOGE("%s failed to set %s to %s",
                         std::remove_cvref_t<decltype(args)>::isVersion() ? "VERSION" : "Build",
                         std::remove_cvref_t<decltype(args)>::getField(),
                         args.value.data())), ...);
            }, spoofConfig);

            // Keep ro.* native reads consistent with the spoofed Build
            // fields (PIF-style). Values come from the same spoof_build_vars.
            prop_spoof::security_patch = field_value(spoofConfig, "SECURITY_PATCH");
            prop_spoof::build_id = field_value(spoofConfig, "ID");
            prop_spoof::first_api_level = field_value(spoofConfig, "DEVICE_INITIAL_SDK_INT");
            keep_loaded = install_property_hook();
        }
        // Only request module unload when no persistent hook was installed.
        if (!keep_loaded) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api_{nullptr};
    JNIEnv *env_{nullptr};

    template<typename T>
    inline bool setField(jclass clazz, const char* field, const PropValue& value);

    template<>
    inline bool setField<jstring>(jclass clazz, const char* field, const PropValue& value) {
        auto id = env_->GetStaticFieldID(clazz, field, "Ljava/lang/String;");
        if (!id) return false;
        env_->SetStaticObjectField(clazz, id, env_->NewStringUTF(value.data()));
        return true;
    }

    template<>
    inline bool setField<jint>(jclass clazz, const char* field, const PropValue& value) {
        auto id = env_->GetStaticFieldID(clazz, field, "I");
        if (!id) return false;
        char *p = nullptr;
        jint x = static_cast<jint>(strtol(value.data(), &p, 10));
        if (p == value.data()) {
            return false;
        }
        env_->SetStaticIntField(clazz, id, x);
        return true;
    }

    template<>
    inline bool setField<jboolean>(jclass clazz, const char* field, const PropValue& value) {
        auto id = env_->GetStaticFieldID(clazz, field, "Z");
        if (!id) return false;
        auto x = std::string_view(value.data());
        if (x == "1" || x == "true") {
            env_->SetStaticBooleanField(clazz, id, JNI_TRUE);
        } else if (x == "0" || x == "false") {
            env_->SetStaticBooleanField(clazz, id, JNI_FALSE);
        } else {
            return false;
        }
        return true;
    }
};

void read_config(FILE *config, SpoofConfig &spoof_config) {
    char *l = nullptr;
    struct finally {
        char *(&l);

        ~finally() { free(l); }
    } finally{l};
    size_t len = 0;
    ssize_t n;
    while ((n = getline(&l, &len, config)) != -1) {
        if (n <= 1) continue;
        std::string_view line{l, static_cast<size_t>(n)};
        if (line.back() == '\n') {
            line.remove_suffix(1);
        }
        auto d = line.find_first_of('=');
        if (d == std::string_view::npos) {
            LOGW("Ignore invalid line %.*s", static_cast<int>(line.size()), line.data());
            continue;
        }
        auto key = line.substr(0, d);
        trim(key);
        auto value = line.substr(d + 1);
        trim(value);
        std::apply([&key, &value](auto &&... args) {
            ((key == std::remove_cvref_t<decltype(args)>::getField() &&
              (LOGD("Read config: %.*s = %.*s", static_cast<int>(key.size()), key.data(),
                    static_cast<int>(value.size()), value.data()),
                      args.value.size() >= value.size() + 1 ?
                      (args.has_value = true,
                              strlcpy(args.value.data(), value.data(),
                                      std::min(args.value.size(), value.size() + 1))) :
                      (LOGW("Config value %.*s for %.*s is too long, ignored",
                            static_cast<int>(value.size()), value.data(),
                            static_cast<int>(key.size()), key.data()), true))) || ...);
        }, spoof_config);
    }
}

bool target_contains_package(FILE *target, std::string_view package) {
    char *l = nullptr;
    struct finally {
        char *(&l);

        ~finally() { free(l); }
    } finally{l};
    size_t len = 0;
    ssize_t n;
    while ((n = getline(&l, &len, target)) != -1) {
        if (n <= 1) continue;
        std::string_view line{l, static_cast<size_t>(n)};
        if (!line.empty() && line.back() == '\n') {
            line.remove_suffix(1);
        }
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        if (line.back() == '@' || line.back() == '!') {
            line.remove_suffix(1);
            trim(line);
        }
        if (line == package) {
            return true;
        }
    }
    return false;
}

static void companion_handler(int fd) {
    constexpr auto kSpoofConfigFile = "/data/adb/tricky_store/spoof_build_vars"sv;
    constexpr auto kTargetConfigFile = "/data/adb/tricky_store/target.txt"sv;
    constexpr auto kDefaultSpoofConfig =
R"EOF(MANUFACTURER=Google
MODEL=Pixel 6
FINGERPRINT=google/oriole/oriole:16/CP1A.260305.018/14887507:user/release-keys
BRAND=google
PRODUCT=oriole
DEVICE=oriole
BRAND_FOR_ATTESTATION=google
PRODUCT_FOR_ATTESTATION=oriole
DEVICE_FOR_ATTESTATION=oriole
MANUFACTURER_FOR_ATTESTATION=Google
MODEL_FOR_ATTESTATION=Pixel 6
RELEASE=16
ID=CP1A.260305.018
INCREMENTAL=14887507
TYPE=user
TAGS=release-keys
SECURITY_PATCH=2026-03-05
DEVICE_INITIAL_SDK_INT=31
)EOF"sv;
    PackageValue package{};
    PackageValue process{};
    if (xread(fd, package.data(), package.size()) != static_cast<ssize_t>(package.size()) ||
        xread(fd, process.data(), process.size()) != static_cast<ssize_t>(process.size())) {
        return;
    }

    struct stat st{};
    int enabled = stat(kSpoofConfigFile.data(), &st) == 0;
    xwrite(fd, &enabled, sizeof(enabled));

    if (!enabled) {
        return;
    }

    std::string_view packageName(package.data());
    std::string_view processName(process.data());
    int shouldSpoof = 0;
    std::unique_ptr<FILE, decltype([](auto *f) { fclose(f); })> target{
        fopen(kTargetConfigFile.data(), "r")
    };
    if (target && target_contains_package(target.get(), packageName)) {
        shouldSpoof = 1;
    }
    if (!shouldSpoof &&
        packageName == "com.google.android.gms"sv &&
        processName == "com.google.android.gms.unstable"sv) {
        shouldSpoof = 1;
    }
    xwrite(fd, &shouldSpoof, sizeof(shouldSpoof));

    if (!shouldSpoof) {
        return;
    }

    int cfd = -1;
    if (st.st_size == 0) {
        cfd = open(kSpoofConfigFile.data(), O_RDWR);
        if (cfd > 0) {
            xwrite(cfd, kDefaultSpoofConfig.data(), kDefaultSpoofConfig.size());
            lseek(cfd, 0, SEEK_SET);
        }
    } else {
        cfd = open(kSpoofConfigFile.data(), O_RDONLY);
    }
    if (cfd < 0) {
        LOGE("[companion_handler] Failed to open spoof_build_vars");
        return;
    }

    SpoofConfig spoof_config{};
    std::unique_ptr<FILE, decltype([](auto *f) { fclose(f); })> config{fdopen(cfd, "r")};
    read_config(config.get(), spoof_config);

    xwrite(fd, &spoof_config, sizeof(spoof_config));
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(TrickyStore)
REGISTER_ZYGISK_COMPANION(companion_handler)
