package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.os.FileObserver
import android.os.ServiceManager
import io.github.a13e300.tricky_store.keystore.CertHack
import io.github.a13e300.tricky_store.proxy.ProxyClient
import java.io.File

object Config {
    private val hackPackages = mutableSetOf<String>()
    private val generatePackages = mutableSetOf<String>()
    private val proxyPackages = mutableSetOf<String>()

    private fun updateTargetPackages(f: File?) = runCatching {
        hackPackages.clear()
        generatePackages.clear()
        proxyPackages.clear()
        f?.readLines()?.forEach {
            if (it.isNotBlank() && !it.startsWith("#")) {
                val n = it.trim()
                when {
                    n.endsWith("@") -> proxyPackages.add(n.removeSuffix("@").trim())
                    n.endsWith("!") -> generatePackages.add(n.removeSuffix("!").trim())
                    else -> hackPackages.add(n)
                }
            }
        }
        Logger.i("update hack packages: $hackPackages, generate packages=$generatePackages, proxy packages=$proxyPackages")
    }.onFailure {
        Logger.e("failed to update target files", it)
    }

    private fun updateKeyBox(f: File?) = runCatching {
        CertHack.readFromXml(f?.readText())
    }.onFailure {
        Logger.e("failed to update keybox", it)
    }

    private fun updateProxy(f: File?) = runCatching {
        val url = f?.readText()?.trim()
        ProxyClient.baseUrl = if (url.isNullOrBlank()) null else url
        Logger.i("update proxy: ${ProxyClient.baseUrl ?: "disabled"}")
    }.onFailure {
        Logger.e("failed to update proxy config", it)
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val KEYBOX_FILE = "keybox.xml"
    private const val PROXY_FILE = "proxy.txt"
    private val root = File(CONFIG_PATH)

    object ConfigObserver : FileObserver(root, CLOSE_WRITE or DELETE or MOVED_FROM or MOVED_TO) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            val f = when (event) {
                CLOSE_WRITE, MOVED_TO -> File(root, path)
                DELETE, MOVED_FROM -> null
                else -> return
            }
            when (path) {
                TARGET_FILE -> updateTargetPackages(f)
                KEYBOX_FILE -> updateKeyBox(f)
                PROXY_FILE -> updateProxy(f)
            }
        }
    }

    fun initialize() {
        root.mkdirs()
        val scope = File(root, TARGET_FILE)
        if (scope.exists()) {
            updateTargetPackages(scope)
        } else {
            Logger.e("target.txt file not found, please put it to $scope !")
        }
        val keybox = File(root, KEYBOX_FILE)
        if (!keybox.exists()) {
            Logger.e("keybox file not found, please put it to $keybox !")
        } else {
            updateKeyBox(keybox)
        }
        val proxy = File(root, PROXY_FILE)
        if (proxy.exists()) {
            updateProxy(proxy)
        }
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            iPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"))
        }
        return iPm
    }

    fun needHack(callingUid: Int) = kotlin.runCatching {
        if (hackPackages.isEmpty()) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in hackPackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun needGenerate(callingUid: Int) = kotlin.runCatching {
        if (generatePackages.isEmpty()) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in generatePackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun needProxy(callingUid: Int) = kotlin.runCatching {
        if (proxyPackages.isEmpty() || ProxyClient.baseUrl == null) return false
        val ps = getPm()?.getPackagesForUid(callingUid)
        ps?.any { it in proxyPackages }
    }.onFailure { Logger.e("failed to get packages", it) }.getOrNull() ?: false

    fun getProxyPackageName(callingUid: Int): String? = kotlin.runCatching {
        val ps = getPm()?.getPackagesForUid(callingUid) ?: return null
        ps.firstOrNull { it in proxyPackages }
    }.getOrNull()
}
