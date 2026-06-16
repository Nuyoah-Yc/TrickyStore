package io.github.a13e300.tricky_store

import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.Authorization
import android.system.keystore2.CreateOperationResponse
import android.system.keystore2.IKeystoreSecurityLevel
import android.system.keystore2.KeyDescriptor
import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import io.github.a13e300.tricky_store.binder.BinderInterceptor
import io.github.a13e300.tricky_store.proxy.ProxyClient
import io.github.a13e300.tricky_store.proxy.ProxyOperationBinder
import java.util.concurrent.ConcurrentHashMap

class SecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val level: Int
) : BinderInterceptor() {
    companion object {
        private val generateKeyTransaction =
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val createOperationTransaction by lazy {
            getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")
        }
        // Maps local key alias → proxy alias for proxy-generated keys
        private val proxyAliases = ConcurrentHashMap<Key, ProxyKeyInfo>()

        // Tags a remote device cannot satisfy on behalf of this device:
        //  - ATTESTATION_ID_*: a device can only attest its OWN IDs → CANNOT_ATTEST_IDS.
        //  - INCLUDE_UNIQUE_ID: needs the unique-ID-attestation permission the remote
        //    proxy app lacks → PERMISSION_DENIED. Strip them before forwarding.
        private val nonProxyableTags = setOf(
            Tag.ATTESTATION_ID_BRAND, Tag.ATTESTATION_ID_DEVICE, Tag.ATTESTATION_ID_PRODUCT,
            Tag.ATTESTATION_ID_SERIAL, Tag.ATTESTATION_ID_IMEI, Tag.ATTESTATION_ID_MEID,
            Tag.ATTESTATION_ID_MANUFACTURER, Tag.ATTESTATION_ID_MODEL, Tag.ATTESTATION_ID_SECOND_IMEI,
            Tag.INCLUDE_UNIQUE_ID
        )

        fun getProxyKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            proxyAliases[Key(uid, alias)]?.response

        fun isProxyKey(uid: Int, alias: String): Boolean =
            proxyAliases.containsKey(Key(uid, alias)) || Config.getProxyAlias(uid, alias) != null

        fun removeProxyKey(uid: Int, alias: String): Boolean {
            val removedMemory = proxyAliases.remove(Key(uid, alias)) != null
            val removedPersisted = Config.removeProxyAlias(uid, alias)
            return removedMemory || removedPersisted
        }

        fun getProxyAlias(uid: Int, alias: String): String? =
            proxyAliases[Key(uid, alias)]?.proxyAlias ?: Config.getProxyAlias(uid, alias)
    }

    data class Key(val uid: Int, val alias: String)
    data class ProxyKeyInfo(val proxyAlias: String, val response: KeyEntryResponse)

    override fun onPreTransact(
        target: IBinder,
        code: Int,
        flags: Int,
        callingUid: Int,
        callingPid: Int,
        data: Parcel
    ): Result {
        if (code == generateKeyTransaction) {
            if (Config.needProxy(callingUid)) {
                return handleProxyGenerateKey(callingUid, callingPid, data)
            }
        }
        if (code == createOperationTransaction) {
            return handleCreateOperation(callingUid, data)
        }
        return Skip
    }

    private fun handleProxyGenerateKey(callingUid: Int, callingPid: Int, data: Parcel): Result {
        Logger.i("intercept proxy key gen uid=$callingUid pid=$callingPid")
        kotlin.runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
            val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val aFlags = data.readInt()
            val entropy = data.createByteArray()

            // Find attestation challenge in params
            var challenge: ByteArray? = null
            for (kp in params) {
                if (kp.tag == Tag.ATTESTATION_CHALLENGE) {
                    challenge = kp.value.getBlob()
                    break
                }
            }
            if (challenge == null) return@runCatching // Not an attestation request

            // Get target package info
            val packageName = Config.getProxyPackageName(callingUid) ?: return@runCatching
            val pm = Config.getPm() ?: return@runCatching
            @Suppress("DEPRECATION")
            val pkgInfo = pm.getPackageInfoCompat(
                packageName, android.content.pm.PackageManager.GET_SIGNATURES.toLong(),
                callingUid / 100000
            )

            var signingCertHash: String? = null
            var versionCode = 1L
            if (pkgInfo != null) {
                versionCode = pkgInfo.longVersionCode
                if (pkgInfo.signatures != null && pkgInfo.signatures.isNotEmpty()) {
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(pkgInfo.signatures[0].toByteArray())
                    signingCertHash = digest.joinToString("") { "%02x".format(it) }
                }
            }

            // Convert KeyParameter[] to proxy param entries
            var strippedIds = 0
            val paramEntries = params.mapNotNull { kp ->
                if (kp.tag == Tag.ATTESTATION_CHALLENGE || kp.tag == Tag.ATTESTATION_APPLICATION_ID)
                    return@mapNotNull null
                if (kp.tag in nonProxyableTags) {
                    strippedIds++
                    return@mapNotNull null
                }
                keyParamToEntry(kp)
            }
            if (strippedIds > 0)
                Logger.i("stripped $strippedIds non-proxyable attestation tag(s) for uid=$callingUid (ID/unique-ID cannot be attested by a remote device)")
            val attestLocalAlias = attestationKeyDescriptor?.alias
            val attestKeyAlias = attestLocalAlias?.let { localAlias ->
                getProxyAlias(callingUid, localAlias).also { proxyAlias ->
                    if (proxyAlias == null) {
                        Logger.i("no proxy alias mapped for attestation key uid=$callingUid alias=$localAlias")
                    } else {
                        Logger.i("use proxy attestation key alias=$proxyAlias for uid=$callingUid alias=$localAlias")
                    }
                }
            }

            fun doGenerate(ak: String?) = ProxyClient.generate(
                targetPackage = packageName,
                signingCertHash = signingCertHash,
                signingCert = null,
                versionCode = versionCode,
                challenge = challenge,
                params = paramEntries,
                flags = aFlags,
                entropy = entropy,
                attestKeyAlias = ak,
                securityLevel = level
            )

            // 自愈：代理机换机 / 会话过期后，缓存里的 attestKeyAlias 在新机 keystore 已不存在，
            // 远端出证回 KEY_NOT_FOUND(errorCode=7)。此时把这条悬空缓存作废（内存+文件），并改为
            // 不带 attest key 重试一次——本次请求直接由代理机自身的 TEE 根出证，不再硬失败 500。
            // 后续对该别名的请求也不会再复用死映射（getProxyAlias 已返回 null）。
            var attestKeyUsed = attestKeyAlias != null
            val result = try {
                doGenerate(attestKeyAlias)
            } catch (e: Exception) {
                if (attestKeyAlias != null && isKeyNotFound(e)) {
                    Logger.e("proxy attest key alias=$attestKeyAlias gone on remote (stale after agent/session change) uid=$callingUid; evict cache + retry without attest key", e)
                    removeProxyKey(callingUid, attestLocalAlias)
                    attestKeyUsed = false
                    doGenerate(null)
                } else throw e
            }

            Logger.i("proxy generated key alias=${result.alias} for uid=$callingUid pkg=$packageName")

            // Debug: verify cert chain signatures locally to detect byte corruption
            run {
                val factory = java.security.cert.CertificateFactory.getInstance("X.509")
                val leaf = factory.generateCertificate(java.io.ByteArrayInputStream(result.leafCert)) as java.security.cert.X509Certificate
                val chainCerts = factory.generateCertificates(java.io.ByteArrayInputStream(result.certChain))
                    .map { it as java.security.cert.X509Certificate }
                val allCerts = listOf(leaf) + chainCerts
                Logger.i("proxy chain (${allCerts.size} certs):")
                for (i in allCerts.indices) {
                    val c = allCerts[i]
                    val issuerCert = if (i + 1 < allCerts.size) allCerts[i + 1] else c // self-signed root
                    val ok = try {
                        c.verify(issuerCert.publicKey)
                        "OK"
                    } catch (e: Exception) {
                        "FAIL: ${e.message}"
                    }
                    Logger.i("  [$i] ${c.subjectX500Principal} signed_by=${issuerCert.subjectX500Principal} -> $ok")
                    // Also check if encoded bytes match original raw bytes
                    if (i > 0) {
                        val reEncoded = allCerts[i].encoded
                        Logger.i("  [$i] encoded=${reEncoded.size} bytes, matches_original=${reEncoded.contentEquals(chainCerts[i-1].encoded)}")
                    } else {
                        Logger.i("  [0] leafCert raw=${result.leafCert.size} encoded=${leaf.encoded.size} match=${result.leafCert.contentEquals(leaf.encoded)}")
                    }
                }
            }
            // When an app-supplied attest key is used, the relay returns only the new
            // leaf (signed by that attest key) and omits certChain. Rebuild the chain
            // from the attest key's own chain that we cached when it was generated.
            var effectiveChain = result.certChain
            if (effectiveChain.isEmpty() && attestKeyUsed && attestLocalAlias != null) {
                val attestMeta = proxyAliases[Key(callingUid, attestLocalAlias)]?.response?.metadata
                val attestLeaf = attestMeta?.certificate
                if (attestLeaf != null) {
                    val attestRest = attestMeta.certificateChain ?: ByteArray(0)
                    effectiveChain = attestLeaf + attestRest
                    Logger.i("rebuilt certChain from attest key (${attestLeaf.size}+${attestRest.size} bytes) for uid=$callingUid")
                } else {
                    Logger.e("attest key chain not cached for uid=$callingUid alias=$attestLocalAlias; certChain stays empty")
                }
            }
            val metadata = KeyMetadata()
            metadata.keySecurityLevel = level
            metadata.certificate = result.leafCert
            metadata.certificateChain = effectiveChain
            val d = KeyDescriptor()
            d.domain = keyDescriptor.domain
            d.nspace = keyDescriptor.nspace
            metadata.key = d
            metadata.authorizations = buildAuthorizationsFromParams(params)

            val response = KeyEntryResponse()
            response.metadata = metadata
            response.iSecurityLevel = original

            proxyAliases[Key(callingUid, keyDescriptor.alias)] =
                ProxyKeyInfo(result.alias, response)
            Config.putProxyAlias(callingUid, keyDescriptor.alias, result.alias)

            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(metadata, 0)
            return OverrideReply(0, p)
        }.onFailure {
            Logger.e("proxy key gen failed uid=$callingUid", it)
        }
        return Skip
    }

    // 远端出证失败是否为 keystore2 KEY_NOT_FOUND(ResponseCode=7)——典型为缓存的 attestKeyAlias
    // 指向的密钥在代理机已不存在（换机/会话过期）。ProxyClient 把代理机 500 的响应体放进异常
    // message，里面形如 ServiceSpecificException(errorCode=7)。逐层查 cause 链以防被包裹。
    private fun isKeyNotFound(t: Throwable): Boolean {
        val msg = generateSequence(t as Throwable?) { it.cause }
            .mapNotNull { it.message }
            .joinToString(" ")
        return msg.contains("errorCode=7)") || msg.contains("KEY_NOT_FOUND", ignoreCase = true)
    }

    private fun handleCreateOperation(callingUid: Int, data: Parcel): Result {
        kotlin.runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            // val forced = data.readInt() != 0

            val alias = keyDescriptor.alias ?: return@runCatching
            val key = Key(callingUid, alias)

            val proxyInfo = proxyAliases[key] ?: return@runCatching

            Logger.i("intercept createOperation for proxy key uid=$callingUid alias=$alias")

            val paramEntries = params.mapNotNull { keyParamToEntry(it) }
            val opId = ProxyClient.createOperation(proxyInfo.proxyAlias, paramEntries)

            Logger.i("proxy operation created opId=$opId")

            val operationBinder = ProxyOperationBinder(opId)

            val response = CreateOperationResponse()
            response.iOperation = operationBinder
            response.operationChallenge = 0
            response.outParams = null

            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(response, 0)
            return OverrideReply(0, p)
        }.onFailure {
            Logger.e("proxy createOperation failed uid=$callingUid", it)
        }
        return Skip
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun keyParamToEntry(kp: KeyParameter): ProxyClient.ParamEntry? {
        val v = kp.value ?: return null
        val tag = kp.tag
        return when (v.getTag()) {
            KeyParameterValue.algorithm ->
                ProxyClient.ParamEntry(tag, "algorithm", v.getAlgorithm())
            KeyParameterValue.blockMode ->
                ProxyClient.ParamEntry(tag, "blockMode", v.getBlockMode())
            KeyParameterValue.paddingMode ->
                ProxyClient.ParamEntry(tag, "paddingMode", v.getPaddingMode())
            KeyParameterValue.digest ->
                ProxyClient.ParamEntry(tag, "digest", v.getDigest())
            KeyParameterValue.ecCurve ->
                ProxyClient.ParamEntry(tag, "ecCurve", v.getEcCurve())
            KeyParameterValue.origin ->
                ProxyClient.ParamEntry(tag, "origin", v.getOrigin())
            KeyParameterValue.keyPurpose ->
                ProxyClient.ParamEntry(tag, "keyPurpose", v.getKeyPurpose())
            KeyParameterValue.hardwareAuthenticatorType ->
                ProxyClient.ParamEntry(tag, "hardwareAuthenticatorType", v.getHardwareAuthenticatorType())
            KeyParameterValue.securityLevel ->
                ProxyClient.ParamEntry(tag, "securityLevel", v.getSecurityLevel())
            KeyParameterValue.boolValue ->
                ProxyClient.ParamEntry(tag, "boolValue", v.getBoolValue())
            KeyParameterValue.integer ->
                ProxyClient.ParamEntry(tag, "integer", v.getInteger())
            KeyParameterValue.longInteger ->
                ProxyClient.ParamEntry(tag, "longInteger", v.getLongInteger())
            KeyParameterValue.dateTime ->
                ProxyClient.ParamEntry(tag, "dateTime", v.getDateTime())
            KeyParameterValue.blob ->
                ProxyClient.ParamEntry(tag, "blob", v.getBlob())
            else -> null
        }
    }

    /**
     * The proxy certChain contains the full chain (leaf → intermediates → root).
     * KeyMetadata expects certificate=leaf and certificateChain=intermediates+root only.
     * Always strip the first cert from certChain since leafCert is set separately.
     */
    private fun stripLeafFromChain(leafCert: ByteArray, certChain: ByteArray): ByteArray {
        if (certChain.isEmpty()) return certChain
        try {
            val factory = java.security.cert.CertificateFactory.getInstance("X.509")
            val certs = factory.generateCertificates(java.io.ByteArrayInputStream(certChain)).toList()
            Logger.i("certChain has ${certs.size} certs, raw size=${certChain.size}")
            if (certs.size <= 1) return ByteArray(0)

            // Always drop the first cert (the leaf), keep only intermediates + root
            val remaining = certs.drop(1)
            val out = java.io.ByteArrayOutputStream()
            for (c in remaining) {
                out.write(c.encoded)
            }
            Logger.i("stripped leaf from proxy certChain (${certs.size} -> ${remaining.size} certs)")
            return out.toByteArray()
        } catch (t: Throwable) {
            Logger.e("failed to parse certChain for leaf stripping", t)
        }
        return certChain
    }

    private fun buildAuthorizationsFromParams(params: Array<KeyParameter>): Array<Authorization> {
        val authorizations = ArrayList<Authorization>()
        for (kp in params) {
            if (kp.tag == Tag.ATTESTATION_CHALLENGE || kp.tag == Tag.ATTESTATION_APPLICATION_ID)
                continue
            val a = Authorization()
            a.keyParameter = kp
            a.securityLevel = level
            authorizations.add(a)
        }
        return authorizations.toTypedArray()
    }
}
