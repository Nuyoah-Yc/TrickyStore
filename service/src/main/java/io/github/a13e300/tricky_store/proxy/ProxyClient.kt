package io.github.a13e300.tricky_store.proxy

import android.util.Base64
import io.github.a13e300.tricky_store.Logger
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

object ProxyClient {
    // 默认调度地址（生产）。proxy.txt 非空时覆盖；为空/缺失时回退此默认值。
    const val DEFAULT_BASE_URL = "https://tk.cyymzy.com/api/relay"

    @Volatile
    var baseUrl: String? = DEFAULT_BASE_URL

    // 卡密（按次计费）与设备指纹：由 Config 从 card.txt / device_id 注入，随每次请求带上
    @Volatile
    var cardKey: String? = null

    @Volatile
    var deviceId: String? = null

    /** 注入卡密 / 设备指纹头，供 server 计费与统计。 */
    private fun HttpURLConnection.applyAuthHeaders() {
        cardKey?.let { setRequestProperty("X-Card-Key", it) }
        deviceId?.let { setRequestProperty("X-Device-Id", it) }
    }

    private fun post(path: String, body: JSONObject): JSONObject {
        val url = URL("${baseUrl ?: throw IOException("proxy not configured")}$path")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            conn.applyAuthHeaders()
            conn.doOutput = true
            conn.connectTimeout = 10_000
            conn.readTimeout = 30_000
            val bytes = body.toString().toByteArray(Charsets.UTF_8)
            conn.setFixedLengthStreamingMode(bytes.size)
            conn.outputStream.use { it.write(bytes); it.flush() }
            if (conn.responseCode != 200) {
                val err = conn.errorStream?.bufferedReader()?.readText() ?: "unknown"
                throw IOException("proxy $path returned ${conn.responseCode}: $err")
            }
            return JSONObject(conn.inputStream.bufferedReader().readText())
        } finally {
            conn.disconnect()
        }
    }

    private fun get(path: String): JSONObject {
        val url = URL("${baseUrl ?: throw IOException("proxy not configured")}$path")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "GET"
            conn.applyAuthHeaders()
            conn.connectTimeout = 10_000
            conn.readTimeout = 10_000
            if (conn.responseCode != 200) {
                throw IOException("proxy $path returned ${conn.responseCode}")
            }
            return JSONObject(conn.inputStream.bufferedReader().readText())
        } finally {
            conn.disconnect()
        }
    }

    data class GenerateResult(
        val alias: String,
        val leafCert: ByteArray,
        val certChain: ByteArray
    )

    fun generate(
        targetPackage: String,
        signingCertHash: String?,
        signingCert: ByteArray?,
        versionCode: Long,
        challenge: ByteArray?,
        params: List<ParamEntry>,
        flags: Int,
        entropy: ByteArray?,
        attestKeyAlias: String?,
        securityLevel: Int = 1
    ): GenerateResult {
        val body = JSONObject().apply {
            put("targetPackage", targetPackage)
            // 1 = TEE, 2 = StrongBox
            put("securityLevel", securityLevel)
            if (attestKeyAlias != null) {
                put("attestKeyAlias", attestKeyAlias)
            }
            if (signingCert != null) {
                put("signingCert", Base64.encodeToString(signingCert, Base64.NO_WRAP))
            }
            if (signingCertHash != null) {
                put("signingCertHash", signingCertHash)
            }
            put("versionCode", versionCode)
            if (challenge != null) {
                put("challenge", Base64.encodeToString(challenge, Base64.NO_WRAP))
            }
            put("params", JSONArray().apply {
                for (p in params) {
                    put(p.toJson())
                }
            })
            put("flags", flags)
            if (entropy != null) {
                put("entropy", Base64.encodeToString(entropy, Base64.NO_WRAP))
            }
        }
        Logger.d("proxy generate: $targetPackage")
        val resp = post("/generate", body)
        // When an app-supplied attest key is used, the relay may return only the new
        // leaf and omit certChain (the chain is the attest key's own chain, which the
        // caller already holds). Tolerate its absence instead of throwing.
        val certChainStr = resp.optString("certChain", "")
        return GenerateResult(
            alias = resp.getString("alias"),
            leafCert = Base64.decode(resp.getString("leafCert"), Base64.DEFAULT),
            certChain = if (certChainStr.isEmpty()) ByteArray(0)
            else Base64.decode(certChainStr, Base64.DEFAULT)
        )
    }

    fun createOperation(alias: String, params: List<ParamEntry>): String {
        val body = JSONObject().apply {
            put("alias", alias)
            put("params", JSONArray().apply {
                for (p in params) put(p.toJson())
            })
        }
        val resp = post("/operation", body)
        return resp.getString("opId")
    }

    fun update(opId: String, data: ByteArray): ByteArray? {
        val body = JSONObject().apply {
            put("opId", opId)
            put("data", Base64.encodeToString(data, Base64.NO_WRAP))
        }
        val resp = post("/update", body)
        val out = resp.optString("output", "")
        return if (out.isNotEmpty()) Base64.decode(out, Base64.DEFAULT) else null
    }

    fun finish(opId: String, data: ByteArray?, signature: ByteArray?): ByteArray? {
        val body = JSONObject().apply {
            put("opId", opId)
            if (data != null) put("data", Base64.encodeToString(data, Base64.NO_WRAP))
            if (signature != null) put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
        }
        val resp = post("/finish", body)
        val out = resp.optString("output", "")
        return if (out.isNotEmpty()) Base64.decode(out, Base64.DEFAULT) else null
    }

    fun abort(opId: String) {
        post("/abort", JSONObject().apply { put("opId", opId) })
    }

    fun delete(alias: String) {
        post("/delete", JSONObject().apply { put("alias", alias) })
    }

    data class ParamEntry(val tag: Int, val type: String, val value: Any) {
        fun toJson() = JSONObject().apply {
            put("tag", tag)
            put("type", type)
            when (value) {
                is ByteArray -> put("value", Base64.encodeToString(value, Base64.NO_WRAP))
                else -> put("value", value)
            }
        }
    }
}
