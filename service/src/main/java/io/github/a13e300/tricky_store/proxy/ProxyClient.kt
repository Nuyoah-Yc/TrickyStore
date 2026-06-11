package io.github.a13e300.tricky_store.proxy

import android.util.Base64
import io.github.a13e300.tricky_store.Logger
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

object ProxyClient {
    @Volatile
    var baseUrl: String? = null

    private fun post(path: String, body: JSONObject): JSONObject {
        val url = URL("${baseUrl ?: throw IOException("proxy not configured")}$path")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
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
        return GenerateResult(
            alias = resp.getString("alias"),
            leafCert = Base64.decode(resp.getString("leafCert"), Base64.DEFAULT),
            certChain = Base64.decode(resp.getString("certChain"), Base64.DEFAULT)
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
