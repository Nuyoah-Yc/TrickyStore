# Tricky Store

A trick of keystore. **Android 12 or above is required**.

## Usage

1. Flash this module and reboot.  
2. Customize target packages at `/data/adb/tricky_store/target.txt` (Optional).  
3. (Optional) Override the proxy relay endpoint at `/data/adb/tricky_store/proxy.txt`.  
4. Enjoy!  

**All configuration files will take effect immediately.**

## Proxy-only architecture

This build no longer performs any local certificate hacking or generation, and therefore
**does not use `keybox.xml`**. Every package listed in `target.txt` has its keystore
attestation forwarded to a remote clean device through the proxy relay, which returns a
genuine hardware-backed attestation chain.

- `proxy.txt` — relay base URL. If absent/empty the built-in default endpoint is used.
- `card.txt` — optional billing card key sent with each request.

## Build Vars Spoofing

> **Zygisk (or Zygisk Next) is needed for this feature to work.**

If you still do not pass you can try enabling/disabling Build variable spoofing by creating/deleting the file `/data/adb/tricky_store/spoof_build_vars`.

Tricky Store will automatically generate example config props inside `/data/adb/tricky_store/spoof_build_vars` once created, on next reboot, then you may manually edit your spoof config.

Here is an example of a spoof config:

```
MANUFACTURER=Google
MODEL=Pixel 8 Pro
FINGERPRINT=google/husky_beta/husky:15/AP31.240617.009/12094726:user/release-keys
BRAND=google
PRODUCT=husky_beta
DEVICE=husky
RELEASE=15
ID=AP31.240617.009
INCREMENTAL=12094726
TYPE=user
TAGS=release-keys
SECURITY_PATCH=2024-07-05
```

### Native property spoofing (PlayIntegrityFix-style)

In addition to spoofing the Java `android.os.Build` / `Build.VERSION` fields, the Zygisk module
now also hooks libc's `__system_property_read_callback` (via LSPlt) inside the target/GMS
processes, so native `ro.*` reads stay consistent with the spoofed Build fields. The values are
derived from the **same `spoof_build_vars`** file — no extra config:

- properties ending with `api_level`        → `DEVICE_INITIAL_SDK_INT`
- properties ending with `.security_patch`   → `SECURITY_PATCH`
- properties ending with `.build.id`         → `ID`
- `init.svc.adbd` → `stopped`, `sys.usb.state` → `mtp`

This covers most of what PlayIntegrityFix provided, so a separate PIF module is generally not
needed. Note: LSPlt rewrites the PLT of libraries already loaded at process start; the hook is
installed at app-specialize time. Set `DEVICE_INITIAL_SDK_INT` in `spoof_build_vars` to your
spoofed device's launch SDK for the first-API-level checks.

For Magisk users: if you don't need this feature and zygisk is disabled, please remove or rename the
folder `/data/adb/modules/tricky_store/zygisk` manually.

## Support TEE broken devices

TEE-broken devices are supported out of the box: since attestation is forwarded to a
remote clean device, no working local TEE/StrongBox attestation key is required. Just list
the package in `target.txt`.

For example:

```
# target.txt
io.github.vvb2060.keyattestation
com.google.android.gms
```

Legacy `@` / `!` suffixes are accepted but ignored — every listed package goes through proxy.

## TODO

- [Support Android 11 and below.](https://github.com/5ec1cff/TrickyStore/issues/25#issuecomment-2250588463)

PR is welcomed.

## Acknowledgement

- [PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix)
- [FrameworkPatch](https://github.com/chiteroman/FrameworkPatch)
- [BootloaderSpoofer](https://github.com/chiteroman/BootloaderSpoofer)
- [KeystoreInjection](https://github.com/aviraxp/Zygisk-KeystoreInjection)
- [LSPosed](https://github.com/LSPosed/LSPosed)
