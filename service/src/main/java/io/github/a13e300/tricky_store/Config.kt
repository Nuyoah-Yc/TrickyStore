package io.github.a13e300.tricky_store

import android.content.pm.IPackageManager
import android.os.FileObserver
import android.os.ServiceManager
import io.github.a13e300.tricky_store.proxy.ProxyClient
import java.io.File
import java.util.UUID

object Config {
    private val proxyPackages = mutableSetOf<String>()

    private fun updateTargetPackages(f: File?) = runCatching {
        // proxy-only：target.txt 里列出的每个包都转发到远程 proxy 认证。
        // 兼容历史写法，去掉旧的 @ / ! 后缀（不再有语义区别）。
        proxyPackages.clear()
        f?.readLines()?.forEach {
            if (it.isNotBlank() && !it.startsWith("#")) {
                val n = it.trim().removeSuffix("@").removeSuffix("!").trim()
                if (n.isNotEmpty()) proxyPackages.add(n)
            }
        }
        Logger.i("update proxy packages: $proxyPackages")
    }.onFailure {
        Logger.e("failed to update target files", it)
    }

    private fun updateProxy(f: File?) = runCatching {
        // proxy.txt 为空/缺失时回退默认调度地址，与 ProxyClient.DEFAULT_BASE_URL 注释一致
        val url = f?.readText()?.trim()
        ProxyClient.baseUrl = if (url.isNullOrBlank()) ProxyClient.DEFAULT_BASE_URL else url
        Logger.i("update proxy: ${ProxyClient.baseUrl ?: "disabled"}")
    }.onFailure {
        Logger.e("failed to update proxy config", it)
    }

    private fun updateCard(f: File?) = runCatching {
        val key = f?.readText()?.trim()
        ProxyClient.cardKey = if (key.isNullOrBlank()) null else key
        Logger.i("update card: ${if (ProxyClient.cardKey != null) "set" else "empty"}")
    }.onFailure {
        Logger.e("failed to update card config", it)
    }

    /** 读取设备指纹；首次缺失/为空时生成 UUID 并落盘，供 server 端设备维度统计。 */
    private fun loadOrCreateDeviceId() = runCatching {
        val f = File(root, DEVICE_ID_FILE)
        val existing = if (f.exists()) f.readText().trim() else ""
        val id = if (existing.isNotEmpty()) existing else UUID.randomUUID().toString().also {
            f.writeText(it)
            Logger.i("generated device_id: $it")
        }
        ProxyClient.deviceId = id
    }.onFailure {
        Logger.e("failed to load device id", it)
    }

    private const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_FILE = "target.txt"
    private const val PROXY_FILE = "proxy.txt"
    private const val CARD_FILE = "card.txt"
    private const val DEVICE_ID_FILE = "device_id"
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
                PROXY_FILE -> updateProxy(f)
                CARD_FILE -> updateCard(f)
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
        val proxy = File(root, PROXY_FILE)
        if (proxy.exists()) {
            updateProxy(proxy)
        }
        val card = File(root, CARD_FILE)
        if (card.exists()) {
            updateCard(card)
        }
        loadOrCreateDeviceId()
        ConfigObserver.startWatching()
    }

    private var iPm: IPackageManager? = null

    fun getPm(): IPackageManager? {
        if (iPm == null) {
            iPm = IPackageManager.Stub.asInterface(ServiceManager.getService("package"))
        }
        return iPm
    }

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
