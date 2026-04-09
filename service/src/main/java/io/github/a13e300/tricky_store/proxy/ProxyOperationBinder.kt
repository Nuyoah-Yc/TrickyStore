package io.github.a13e300.tricky_store.proxy

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.IKeystoreOperation
import io.github.a13e300.tricky_store.Logger
import io.github.a13e300.tricky_store.getTransactCode

/**
 * A Binder that impersonates IKeystoreOperation and forwards
 * update/finish/abort calls to the remote proxy server.
 */
class ProxyOperationBinder(private val opId: String) : Binder() {
    companion object {
        private val TRANSACTION_updateAad by lazy {
            getTransactCode(IKeystoreOperation.Stub::class.java, "updateAad")
        }
        private val TRANSACTION_update by lazy {
            getTransactCode(IKeystoreOperation.Stub::class.java, "update")
        }
        private val TRANSACTION_finish by lazy {
            getTransactCode(IKeystoreOperation.Stub::class.java, "finish")
        }
        private val TRANSACTION_abort by lazy {
            getTransactCode(IKeystoreOperation.Stub::class.java, "abort")
        }
    }

    init {
        attachInterface(null, IKeystoreOperation.DESCRIPTOR)
    }

    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        return when (code) {
            TRANSACTION_update -> handleUpdate(data, reply)
            TRANSACTION_updateAad -> handleUpdateAad(data, reply)
            TRANSACTION_finish -> handleFinish(data, reply)
            TRANSACTION_abort -> handleAbort(data, reply)
            else -> super.onTransact(code, data, reply, flags)
        }
    }

    override fun getInterfaceDescriptor(): String = IKeystoreOperation.DESCRIPTOR

    override fun queryLocalInterface(descriptor: String): android.os.IInterface? {
        return if (descriptor == IKeystoreOperation.DESCRIPTOR) {
            // Return null so the caller gets a proxy that calls onTransact
            // (we handle it ourselves)
            null
        } else null
    }

    private fun handleUpdate(data: Parcel, reply: Parcel?): Boolean {
        data.enforceInterface(IKeystoreOperation.DESCRIPTOR)
        val input = data.createByteArray()
        // authToken and timeStampToken - read but not forwarded
        data.createByteArray() // authToken
        data.createByteArray() // timeStampToken
        return try {
            val result = if (input != null) {
                ProxyClient.update(opId, input)
            } else null
            reply?.writeNoException()
            reply?.writeByteArray(result)
            true
        } catch (t: Throwable) {
            Logger.e("proxy update failed", t)
            reply?.writeException(RuntimeException("proxy update failed: ${t.message}"))
            true
        }
    }

    private fun handleUpdateAad(data: Parcel, reply: Parcel?): Boolean {
        data.enforceInterface(IKeystoreOperation.DESCRIPTOR)
        val aadInput = data.createByteArray()
        data.createByteArray() // authToken
        data.createByteArray() // timeStampToken
        return try {
            // AAD update: forward as regular update
            val result = if (aadInput != null) {
                ProxyClient.update(opId, aadInput)
            } else null
            reply?.writeNoException()
            reply?.writeByteArray(result)
            true
        } catch (t: Throwable) {
            Logger.e("proxy updateAad failed", t)
            reply?.writeException(RuntimeException("proxy updateAad failed: ${t.message}"))
            true
        }
    }

    private fun handleFinish(data: Parcel, reply: Parcel?): Boolean {
        data.enforceInterface(IKeystoreOperation.DESCRIPTOR)
        val input = data.createByteArray()
        val signature = data.createByteArray()
        data.createByteArray() // authToken
        data.createByteArray() // timeStampToken
        return try {
            val result = ProxyClient.finish(opId, input, signature)
            reply?.writeNoException()
            reply?.writeByteArray(result)
            true
        } catch (t: Throwable) {
            Logger.e("proxy finish failed", t)
            reply?.writeException(RuntimeException("proxy finish failed: ${t.message}"))
            true
        }
    }

    private fun handleAbort(data: Parcel, reply: Parcel?): Boolean {
        data.enforceInterface(IKeystoreOperation.DESCRIPTOR)
        return try {
            ProxyClient.abort(opId)
            reply?.writeNoException()
            true
        } catch (t: Throwable) {
            Logger.e("proxy abort failed", t)
            reply?.writeException(RuntimeException("proxy abort failed: ${t.message}"))
            true
        }
    }
}
