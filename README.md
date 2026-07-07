# Tricky Store（远程转发 TEE 版）

基于 [Tricky Store](https://github.com/5ec1cff/TrickyStore) 魔改的**远程转发 TEE**方案：本机不再需要可用的 TEE/StrongBox，把 Keystore 认证转发到远端干净设备出证，**稳过 Play Integrity 三层（STRONG / DEVICE / BASIC）**。

**支持范围**：Android 12 ~ Android 17；Magisk、SukiSU Ultra、定制 ROM、虚拟机、云机模拟器等。

## 免费测试卡密

```
2WWPJLDLUPAJBUM5WV49
```

此卡密可直接**免费使用 / 压测**，填入下方 `card.txt` 即可。

## 使用

1. Magisk / SukiSU Ultra 刷入模块 ZIP，重启。
2. 在 KernelSU / SukiSU / Magisk 管理器打开本模块 WebUI，勾选要过检的应用、填入卡密即可；也可直接编辑下方配置文件。
3. 配置即时生效，无需重启。

## 配置文件

目录：`/data/adb/tricky_store/`

| 文件 | 作用 |
|---|---|
| `target.txt` | 需要过检的包名，每行一个（`#` 开头为注释） |
| `card.txt` | 卡密，把上面的测试卡密填进去 |
| `proxy.txt` | 远端服务地址，留空用默认 |

`target.txt` 示例：

```
com.google.android.gms
io.github.vvb2060.keyattestation
```

## 签发统计

> **当前已累计完成超过 12 万次签发认证。**

<p align="center">
  <img width="1666" height="802" alt="签发统计总览" src="https://github.com/user-attachments/assets/860af899-f57a-41c9-8799-b45bd6f7021b" />
</p>

<p align="center">
  <img width="346" height="770" alt="Play Integrity 检测结果" src="https://github.com/user-attachments/assets/900f762d-492e-4979-8546-407319e3993e" />
  &nbsp;&nbsp;
  <img width="345" height="768" alt="Key Attestation 检测结果" src="https://github.com/user-attachments/assets/d32973a0-b484-4ade-98be-17cd3b150874" />
</p>


## 致谢

- [Tricky Store](https://github.com/5ec1cff/TrickyStore)
- [PlayIntegrityFix](https://github.com/chiteroman/PlayIntegrityFix)
- [LSPosed / LSPlt](https://github.com/LSPosed/LSPlt)
