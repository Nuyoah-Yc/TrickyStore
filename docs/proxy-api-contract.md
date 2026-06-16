# TrickyStore Proxy 远端 API 契约

本文档描述 TrickyStore proxy 模式下，设备端（`ProxyClient.kt`）与远端中继服务之间的 HTTP 接口契约。
远端服务需按本契约实现这些接口，才能为设备代理 keystore 密钥的生成、运算与认证。

> 来源：`service/src/main/java/io/github/a13e300/tricky_store/proxy/ProxyClient.kt`

---

## 1. 通用约定

### 基址（Base URL）
- 配置项：设备端 `/data/adb/tricky_store/proxy.txt` 的内容（去除首尾空白）。
- 默认值：`https://tk.cyymzy.com/api/relay`（`proxy.txt` 为空/缺失时使用）。
- 所有接口路径都拼接在基址之后，例如 `POST {baseUrl}/generate`。

### 方法与编码
- 所有接口均为 **POST**，请求体 `Content-Type: application/json; charset=utf-8`。
- 响应体为 JSON，HTTP 状态码必须为 **200** 表示成功。
- 所有二进制字段（证书、challenge、entropy、密文、签名等）在 JSON 中以 **Base64** 字符串传输。
  - 设备端 → 远端：编码用 `NO_WRAP`（无换行）。
  - 远端 → 设备端：设备端用 `Base64.DEFAULT` 解码（兼容标准 Base64，允许换行）。

### 公共请求头
每个请求都会带上以下头部（值可能为空，空则不发送）：

| Header | 含义 | 来源 |
|---|---|---|
| `X-Card-Key` | 卡密，按次计费凭证 | `/data/adb/tricky_store/card.txt` |
| `X-Device-Id` | 设备指纹（UUID），用于 server 端统计/区分设备 | `/data/adb/tricky_store/device_id`（首次自动生成） |

> 远端可基于 `X-Card-Key` 做计费与鉴权，基于 `X-Device-Id` 做设备维度统计/风控。

### 超时
| 接口 | 连接超时 | 读取超时 |
|---|---|---|
| `/generate` | 10s | 30s |
| 其余接口 | 10s | 10s |

### 错误约定
- 任何非 200 的响应都被设备端视为失败并抛出 `IOException`。
- 失败响应体（`errorStream`）会被原样读出并拼进异常信息，建议返回可读的错误描述（纯文本或 JSON 均可）。
- 建议远端用合适的 HTTP 状态码区分错误类型（如 401 卡密无效、402 余额不足、400 参数错误、500 内部错误）。

---

## 2. 接口列表

一把密钥的完整生命周期：

```
POST /generate   → 生成密钥，返回 alias + 证书链
POST /operation  → 用密钥开启一次运算，返回 opId
POST /update     → 分段喂数据（可多次）
POST /finish     → 收尾，返回签名/密文
POST /abort      → 中止运算
POST /delete     → 删除密钥
```

---

### 2.1 `POST /generate` — 生成密钥并签发认证证书

设备端拦截到 App 的 `generateKey` 时调用。远端需在自身可信环境（干净设备/HSM）中生成密钥对，并产出带 Android Key Attestation 扩展的 X.509 证书链。

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `targetPackage` | string | 是 | 目标 App 包名 |
| `securityLevel` | int | 是 | 1 = TEE，2 = StrongBox |
| `attestKeyAlias` | string | 否 | 指定用作签发的已存在密钥的远端 alias（链式 attestation）。缺省则用远端默认认证根 |
| `signingCert` | string(b64) | 否 | App 签名证书（DER，Base64） |
| `signingCertHash` | string | 否 | App 签名证书的 SHA-256 十六进制串 |
| `versionCode` | long | 是 | App 的 longVersionCode |
| `challenge` | string(b64) | 否 | attestation challenge 原始字节 |
| `params` | array | 是 | KeyMint 参数数组，见 [§3 ParamEntry](#3-paramentry-格式) |
| `flags` | int | 是 | 生成 flags |
| `entropy` | string(b64) | 否 | 额外熵 |

**响应体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `alias` | string | 是 | 该密钥在远端的别名；设备端持久化此映射，后续 operation/attestKey 引用 |
| `leafCert` | string(b64) | 是 | 叶子证书（DER） |
| `certChain` | string(b64) | 是 | 叶子之上的证书链（DER，可含多张证书拼接） |

> 设备端会本地校验链上每张证书的签名连续性（leaf ← 中间 ← 自签根），请确保 `leafCert` + `certChain` 构成一条签名自洽的链。

---

### 2.2 `POST /operation` — 开启一次密码学运算

设备端拦截到 `createOperation` 时调用。

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `alias` | string | 是 | 密钥的远端 alias（来自 `/generate` 返回） |
| `params` | array | 是 | 运算参数（purpose/digest/padding 等），见 [§3](#3-paramentry-格式) |

**响应体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `opId` | string | 是 | 运算句柄，后续 update/finish/abort 引用 |

---

### 2.3 `POST /update` — 分段输入数据

可多次调用，向运算追加数据。

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `opId` | string | 是 | 运算句柄 |
| `data` | string(b64) | 是 | 本段输入数据 |

**响应体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `output` | string(b64) | 否 | 本段产生的输出；无输出时返回空串或省略 |

---

### 2.4 `POST /finish` — 结束运算

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `opId` | string | 是 | 运算句柄 |
| `data` | string(b64) | 否 | 最后一段输入数据 |
| `signature` | string(b64) | 否 | 验签场景下待验证的签名 |

**响应体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `output` | string(b64) | 否 | 最终输出（签名/密文/明文）；无输出时返回空串或省略 |

---

### 2.5 `POST /abort` — 中止运算

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `opId` | string | 是 | 运算句柄 |

**响应体**：无要求（设备端不读取返回内容，仅要求 200）。

---

### 2.6 `POST /delete` — 删除密钥

**请求体**

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `alias` | string | 是 | 密钥的远端 alias |

**响应体**：无要求（设备端不读取返回内容，仅要求 200）。

---

## 3. ParamEntry 格式

`params` 数组的每一项表示一个 KeyMint 参数（`KeyParameter`），结构：

```json
{ "tag": <int>, "type": "<string>", "value": <见下> }
```

- `tag`：KeyMint Tag 的整型值（Android `android.hardware.security.keymint.Tag` 常量）。
- `type`：值的类别，决定 `value` 的 JSON 类型。
- `value`：除 `blob` 为 Base64 字符串外，其余均为对应的 JSON 原生类型。

| `type` | `value` 的 JSON 类型 | 含义 |
|---|---|---|
| `algorithm` | int | 算法枚举（RSA/EC/AES/...） |
| `blockMode` | int | 分组模式枚举 |
| `paddingMode` | int | 填充模式枚举 |
| `digest` | int | 摘要算法枚举 |
| `ecCurve` | int | EC 曲线枚举 |
| `origin` | int | 密钥来源枚举 |
| `keyPurpose` | int | 用途枚举（sign/verify/encrypt/decrypt/...） |
| `hardwareAuthenticatorType` | int | 硬件认证类型枚举 |
| `securityLevel` | int | 安全级别枚举 |
| `boolValue` | bool | 布尔标志（`true` 表示该 Tag 存在/启用） |
| `integer` | int | 32 位整数 |
| `longInteger` | long | 64 位整数 |
| `dateTime` | long | 时间戳（毫秒） |
| `blob` | string(b64) | 二进制数据，Base64 编码 |

> 说明：设备端转发参数时会**剔除** `ATTESTATION_CHALLENGE` 和 `ATTESTATION_APPLICATION_ID` 两个 Tag（challenge 走顶层 `challenge` 字段）。其余 Tag 原样透传。各枚举的具体整型取值以 Android KeyMint AIDL 定义为准。

---

## 4. 设备端行为备注（供远端实现参考）

- **alias 持久化**：`/generate` 返回的 `alias` 会被设备端保存在 `proxy_aliases.txt`（映射「本地 uid+alias → 远端 alias」），重启后用于 `attestKeyAlias` 的链式认证。**因此同一把远端密钥可能被多次按 alias 引用，远端需长期保留该密钥，直到收到 `/delete`。**
- **当前实现的已知缺口**：`createOperation` 拦截目前只查设备端**内存**映射，未从 `proxy_aliases.txt` 回退；keystore2 进程重启后，旧密钥的 operation 路径会暂时失效（直到下次重新 generate）。远端无需为此特殊处理。
- **未使用的 GET 帮助方法**：`ProxyClient` 中存在一个 `get()` 私有方法，但当前 6 个接口全为 POST，无 GET 调用方。远端无需实现任何 GET 接口。
