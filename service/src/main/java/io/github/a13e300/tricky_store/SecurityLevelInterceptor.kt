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
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.keystore.CertHack.KeyGenParameters
import io.github.a13e300.tricky_store.keystore.Utils
import io.github.a13e300.tricky_store.proxy.ProxyClient
import io.github.a13e300.tricky_store.proxy.ProxyOperationBinder
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.Certificate
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
        private val keys = ConcurrentHashMap<Key, Info>()
        // Maps local key alias → proxy alias for proxy-generated keys
        private val proxyAliases = ConcurrentHashMap<Key, ProxyKeyInfo>()

        fun getKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            keys[Key(uid, alias)]?.response

        fun getProxyKeyResponse(uid: Int, alias: String): KeyEntryResponse? =
            proxyAliases[Key(uid, alias)]?.response

        fun isProxyKey(uid: Int, alias: String): Boolean =
            proxyAliases.containsKey(Key(uid, alias))

        fun removeProxyKey(uid: Int, alias: String): Boolean =
            proxyAliases.remove(Key(uid, alias)) != null

        fun getProxyAlias(uid: Int, alias: String): String? =
            proxyAliases[Key(uid, alias)]?.proxyAlias
    }

    data class Key(val uid: Int, val alias: String)
    data class Info(val keyPair: KeyPair, val response: KeyEntryResponse)
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
            // Proxy mode takes priority
            if (Config.needProxy(callingUid)) {
                return handleProxyGenerateKey(callingUid, callingPid, data)
            }
            if (Config.needGenerate(callingUid)) {
                return handleLocalGenerateKey(callingUid, callingPid, data)
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
            val paramEntries = params.mapNotNull { kp ->
                if (kp.tag == Tag.ATTESTATION_CHALLENGE || kp.tag == Tag.ATTESTATION_APPLICATION_ID)
                    return@mapNotNull null
                keyParamToEntry(kp)
            }

            val result = ProxyClient.generate(
                targetPackage = packageName,
                signingCertHash = signingCertHash,
                signingCert = null,
                versionCode = versionCode,
                challenge = challenge,
                params = paramEntries,
                flags = aFlags,
                entropy = entropy,
                securityLevel = level
            )

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
            // Pass the raw certChain bytes through untouched.
            val metadata = KeyMetadata()
            metadata.keySecurityLevel = level
            metadata.certificate = result.leafCert
            metadata.certificateChain = result.certChain
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

            val p = Parcel.obtain()
            p.writeNoException()
            p.writeTypedObject(metadata, 0)
            return OverrideReply(0, p)
        }.onFailure {
            Logger.e("proxy key gen failed uid=$callingUid", it)
        }
        return Skip
    }

    private fun handleLocalGenerateKey(callingUid: Int, callingPid: Int, data: Parcel): Result {
        Logger.i("intercept key gen uid=$callingUid pid=$callingPid")
        kotlin.runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor =
                data.readTypedObject(KeyDescriptor.CREATOR) ?: return@runCatching
            val attestationKeyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
            val params = data.createTypedArray(KeyParameter.CREATOR)!!
            val kgp = KeyGenParameters(params)
            if (kgp.attestationChallenge != null) {
                if (attestationKeyDescriptor != null) {
                    Logger.e("warn: attestation key not supported now")
                } else {
                    val pair = CertHack.generateKeyPair(callingUid, keyDescriptor, kgp)
                        ?: return@runCatching
                    val response = buildResponse(pair.second, kgp, keyDescriptor)
                    keys[Key(callingUid, keyDescriptor.alias)] = Info(pair.first, response)
                    val p = Parcel.obtain()
                    p.writeNoException()
                    p.writeTypedObject(response.metadata, 0)
                    return OverrideReply(0, p)
                }
            }
        }.onFailure {
            Logger.e("parse key gen request", it)
        }
        return Skip
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

    private fun buildResponse(
        chain: List<Certificate>,
        params: KeyGenParameters,
        descriptor: KeyDescriptor
    ): KeyEntryResponse {
        val response = KeyEntryResponse()
        val metadata = KeyMetadata()
        metadata.keySecurityLevel = level
        Utils.putCertificateChain(metadata, chain.toTypedArray<Certificate>())
        val d = KeyDescriptor()
        d.domain = descriptor.domain
        d.nspace = descriptor.nspace
        metadata.key = d
        val authorizations = ArrayList<Authorization>()
        var a: Authorization
        for (i in params.purpose) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.PURPOSE
            a.keyParameter.value = KeyParameterValue.keyPurpose(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        for (i in params.digest) {
            a = Authorization()
            a.keyParameter = KeyParameter()
            a.keyParameter.tag = Tag.DIGEST
            a.keyParameter.value = KeyParameterValue.digest(i)
            a.securityLevel = level
            authorizations.add(a)
        }
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.ALGORITHM
        a.keyParameter.value = KeyParameterValue.algorithm(params.algorithm)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.KEY_SIZE
        a.keyParameter.value = KeyParameterValue.integer(params.keySize)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.EC_CURVE
        a.keyParameter.value = KeyParameterValue.ecCurve(params.ecCurve)
        a.securityLevel = level
        authorizations.add(a)
        a = Authorization()
        a.keyParameter = KeyParameter()
        a.keyParameter.tag = Tag.NO_AUTH_REQUIRED
        a.keyParameter.value = KeyParameterValue.boolValue(true)
        a.securityLevel = level
        authorizations.add(a)
        metadata.authorizations = authorizations.toTypedArray<Authorization>()
        response.metadata = metadata
        response.iSecurityLevel = original
        return response
    }
}
