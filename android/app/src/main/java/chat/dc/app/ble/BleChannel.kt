package chat.dc.app.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.Build
import java.util.ArrayDeque
import java.util.UUID

/** 蓝牙承载帧类型（一字节头）。 */
object Wire {
    const val MSG = 1           // 信封：[type][sigMsgType:1][ct...]
    const val HS = 2            // 首条握手：[type][nameLen:1][name][mac:32][sigMsgType:1][ct...]
    const val SAS_OK = 3        // 本端 SAS 比对通过：[type]
    const val AUTH_CAND = 5     // 回连认证①：[type][initiatorIdentity:32][count:1][slotId:4×n]
    const val AUTH_CHA = 6      // 回连认证②：[type][nonce:16][responderIdentity:32]
    const val AUTH_RSP = 7      // 回连认证③：[type][hmac:16]（initiator 按候选算，命中定身份）
    const val AUTH_B_CHA = 8    // 反向认证①：[type][nonce:16]（initiator 出 nonce）
    const val AUTH_B_RSP = 9    // 反向认证②：[type][hmac:16]（responder 证明持有 S_i）

    const val HEADER_LEN = 3    // [type:1][bodyLen:2 BE]
    // 单帧 body 上限：真实最大帧 = HS（name+MAC+PreKeyBundle ≈2.6KB），留余量取 4KB。
    // 必须远小于 len 域的 65535：FrameSink 靠「声明长度超限」识别恶意/坏头并立即
    // 丢弃缓冲，否则对端可用 0xFFFF 假头让重组缓冲无限挂起。
    const val MAX_BODY = 4096
}

/** GATT 服务与特征 UUID（client/server 共用）。 */
object LinkUuids {
    val SERVICE_UUID: UUID = UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e5f")
    val RX_UUID: UUID = UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e60") // 写入 server 的方向
    val TX_UUID: UUID = UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e61") // server 通知方向
    val CCC_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    const val WANT_MTU = 517
}

/** 组一帧：头 + 体。 */
fun wireFrame(type: Int, body: ByteArray): ByteArray {
    require(body.size <= Wire.MAX_BODY) { "frame body too large: ${body.size}" }
    return byteArrayOf(
        type.toByte(),
        (body.size ushr 8).toByte(),
        body.size.toByte(),
    ) + body
}

/** 字节流 → 完整帧重组（GATT 写/通知按 MTU 分片到达，链路层保序可靠）。纯逻辑可测。 */
class FrameSink {
    private var buf = ByteArray(0)

    fun feed(chunk: ByteArray): List<ByteArray> {
        buf += chunk
        val out = mutableListOf<ByteArray>()
        while (buf.size >= Wire.HEADER_LEN) {
            val len = ((buf[1].toInt() and 0xFF) shl 8) or (buf[2].toInt() and 0xFF)
            val total = Wire.HEADER_LEN + len
            if (total > Wire.HEADER_LEN + Wire.MAX_BODY) {
                // 声明超大 body 的坏头：立即丢弃缓冲（否则真帧被假头吞掉）
                buf = ByteArray(0)
                break
            }
            if (buf.size < total) break
            out += buf.copyOf(total)
            buf = buf.copyOfRange(total, buf.size)
        }
        if (buf.size > Wire.HEADER_LEN + Wire.MAX_BODY) buf = ByteArray(0) // 无头垃圾兜底
        return out
    }

    fun reset() { buf = ByteArray(0) }
}

/** 帧 → ≤chunkSize 分片。纯逻辑可测。 */
fun splitForChunk(frame: ByteArray, chunkSize: Int): List<ByteArray> =
    if (frame.size <= chunkSize) listOf(frame)
    else frame.asList().asIterable().chunked(chunkSize).map { it.toByteArray() }

/** 单链路发送队列：一次只在途一分片，写/通知确认回调驱动下一片。 */
private class SendPump {
    private val queue = ArrayDeque<ByteArray>()

    /** @return true 表示队列原本空闲，调用方应立即泵第一片。 */
    @Synchronized
    fun enqueue(chunks: List<ByteArray>): Boolean {
        val wasIdle = queue.isEmpty()
        queue.addAll(chunks)
        return wasIdle
    }

    @Synchronized
    fun next(): ByteArray? = queue.poll()

    @Synchronized
    fun clear() = queue.clear()
}

/** 收到完整帧 / 链路断开（回调线程不定，UI 侧自切）。 */
interface LinkEvents {
    fun onFrame(frame: ByteArray)
    fun onClosed()
}

/** minSdk26 兼容写特征（API33 起新签名返回 status int，0=SUCCESS）。 */
@Suppress("DEPRECATION")
private fun writeCharacteristicCompat(g: BluetoothGatt, char: BluetoothGattCharacteristic, value: ByteArray): Boolean =
    if (Build.VERSION.SDK_INT >= 33) {
        g.writeCharacteristic(char, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) ==
            android.bluetooth.BluetoothStatusCodes.SUCCESS
    } else {
        char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        char.value = value
        g.writeCharacteristic(char)
    }

/**
 * GATT client 链路（发起方）：连接 → 协商 MTU → 订阅 TX → 写 RX。一次性使用。
 */
class BleClientLink(
    private val context: Context,
    private val device: BluetoothDevice,
    private val events: LinkEvents,
) : BluetoothGattCallback() {

    private val pump = SendPump()
    private val sink = FrameSink()
    @Volatile private var chunkSize = 20
    @Volatile private var rxChar: BluetoothGattCharacteristic? = null
    @Volatile var connected = false; private set
    private val readyWaiters = mutableListOf<(Boolean) -> Unit>()

    @SuppressLint("MissingPermission")
    fun connect() {
        device.connectGatt(context, false, this, BluetoothDevice.TRANSPORT_LE)
    }

    /** 订阅就绪（CCC 写成功）后回调一次；已就绪立即回 true。 */
    fun whenReady(cb: (Boolean) -> Unit) {
        val already = rxChar != null
        if (already) cb(true) else synchronized(readyWaiters) { readyWaiters += cb }
    }

    fun send(frame: ByteArray) {
        val shouldPump = pump.enqueue(splitForChunk(frame, chunkSize))
        if (shouldPump) pumpOnce()
    }

    @SuppressLint("MissingPermission")
    private fun pumpOnce() {
        val chunk = pump.next() ?: return
        val char = rxChar ?: run { pump.clear(); return }
        val g = gatt ?: run { pump.clear(); return }
        runCatching { writeCharacteristicCompat(g, char, chunk) }.onFailure { pump.clear() }
    }

    @SuppressLint("MissingPermission")
    fun close() {
        pump.clear()
        runCatching { gatt?.close() }
    }

    @Volatile private var gatt: BluetoothGatt? = null

    override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
        gatt = g
        if (newState == BluetoothProfile.STATE_CONNECTED) {
            connected = true
            runCatching { g.requestMtu(LinkUuids.WANT_MTU) }
        } else {
            connected = false
            sink.reset()
            flushWaiters(false)
            events.onClosed()
            runCatching { g.close() }
        }
    }

    override fun onMtuChanged(g: BluetoothGatt, mtu: Int, status: Int) {
        chunkSize = (mtu - Wire.HEADER_LEN).coerceIn(23, LinkUuids.WANT_MTU - Wire.HEADER_LEN)
        runCatching { g.discoverServices() }
    }

    @SuppressLint("MissingPermission")
    override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
        val svc = g.getService(LinkUuids.SERVICE_UUID) ?: return failSetup()
        val tx = svc.getCharacteristic(LinkUuids.TX_UUID) ?: return failSetup()
        rxChar = svc.getCharacteristic(LinkUuids.RX_UUID) ?: return failSetup()
        runCatching { g.setCharacteristicNotification(tx, true) }
        val ccc = tx.getDescriptor(LinkUuids.CCC_UUID) ?: return failSetup()
        runCatching {
            if (Build.VERSION.SDK_INT >= 33) {
                g.writeDescriptor(ccc, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            } else {
                @Suppress("DEPRECATION")
                run { ccc.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE; g.writeDescriptor(ccc) }
            }
        }.onFailure { failSetup() }
    }

    @SuppressLint("MissingPermission")
    override fun onDescriptorWrite(g: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
        if (descriptor.uuid == LinkUuids.CCC_UUID) {
            if (status == BluetoothGatt.GATT_SUCCESS) flushWaiters(true) else failSetup()
        }
    }

    private fun failSetup() {
        rxChar = null
        flushWaiters(false)
        events.onClosed()
    }

    private fun flushWaiters(ok: Boolean) {
        val waiters = synchronized(readyWaiters) { readyWaiters.toList().also { readyWaiters.clear() } }
        waiters.forEach { it(ok) }
    }

    override fun onCharacteristicWrite(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) pump.clear()
        pumpOnce()
    }

    @Suppress("DEPRECATION")
    override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        // API<33 路径；33+ 框架走三参重载，此处双保险防漏
        if (Build.VERSION.SDK_INT >= 33) return
        if (characteristic.uuid != LinkUuids.TX_UUID) return
        sink.feed(characteristic.value ?: ByteArray(0)).forEach { events.onFrame(it) }
    }

    override fun onCharacteristicChanged(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        if (Build.VERSION.SDK_INT < 33) return // 已走二参回调
        if (characteristic.uuid != LinkUuids.TX_UUID) return
        sink.feed(value).forEach { events.onFrame(it) }
    }
}

/**
 * GATT server 链路（广播方常驻）：单例服务，多客户端；
 * 每已连设备一条 ServerLink。
 */
class BleServer(private val context: Context) : BluetoothGattServerCallback() {

    interface NewClient { fun onClient(link: ServerLink) }

    inner class ServerLink internal constructor(internal val device: BluetoothDevice) {
        private val pump = SendPump()
        internal val sink = FrameSink()
        @Volatile var chunkSize = 20
        var events: LinkEvents? = null

        fun send(frame: ByteArray) {
            val shouldPump = pump.enqueue(splitForChunk(frame, chunkSize))
            if (shouldPump) pumpOnce()
        }

        @SuppressLint("MissingPermission")
        private fun pumpOnce() {
            val chunk = pump.next() ?: return
            val s = server ?: run { pump.clear(); return }
            runCatching {
                @Suppress("DEPRECATION")
                if (Build.VERSION.SDK_INT >= 33) {
                    s.notifyCharacteristicChanged(device, txChar, false, chunk)
                } else {
                    txChar.value = chunk
                    s.notifyCharacteristicChanged(device, txChar, false)
                }
            }.onFailure { pump.clear() }
        }

        internal fun pumpContinue() = pumpOnce()
        internal fun drop() { pump.clear(); sink.reset() }
    }

    private val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private var server: BluetoothGattServer? = null
    private val txChar = BluetoothGattCharacteristic(
        LinkUuids.TX_UUID,
        BluetoothGattCharacteristic.PROPERTY_NOTIFY,
        BluetoothGattCharacteristic.PERMISSION_READ,
    )
    private val rxChar = BluetoothGattCharacteristic(
        LinkUuids.RX_UUID,
        BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
        BluetoothGattCharacteristic.PERMISSION_WRITE,
    )
    private val links = mutableMapOf<String, ServerLink>()
    var onNewClient: NewClient? = null

    @SuppressLint("MissingPermission")
    fun start() {
        if (server != null) return
        val s = manager.openGattServer(context, this) ?: return
        val service = BluetoothGattService(LinkUuids.SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        txChar.addDescriptor(
            BluetoothGattDescriptor(
                LinkUuids.CCC_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
            ),
        )
        service.addCharacteristic(txChar)
        service.addCharacteristic(rxChar)
        s.addService(service)
        server = s
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        runCatching { server?.clearServices() }
        runCatching { server?.close() }
        server = null
        links.values.forEach { it.drop() }
        links.clear()
    }

    override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
        if (newState == BluetoothProfile.STATE_CONNECTED) {
            val link = ServerLink(device)
            links[device.address] = link
            onNewClient?.onClient(link)
        } else {
            links.remove(device.address)?.let { it.drop(); it.events?.onClosed() }
        }
    }

    override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
        links[device.address]?.chunkSize = (mtu - Wire.HEADER_LEN).coerceIn(23, LinkUuids.WANT_MTU - Wire.HEADER_LEN)
    }

    @SuppressLint("MissingPermission")
    override fun onCharacteristicWriteRequest(
        device: BluetoothDevice,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray,
    ) {
        val link = links[device.address] ?: return
        if (characteristic.uuid == LinkUuids.RX_UUID) {
            link.sink.feed(value).forEach { frame -> link.events?.onFrame(frame) }
        }
        if (responseNeeded) {
            runCatching { server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null) }
        }
    }

    @SuppressLint("MissingPermission")
    override fun onDescriptorWriteRequest(
        device: BluetoothDevice,
        requestId: Int,
        descriptor: BluetoothGattDescriptor,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray,
    ) {
        if (responseNeeded) {
            runCatching { server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null) }
        }
    }

    @SuppressLint("MissingPermission")
    override fun onNotificationSent(device: BluetoothDevice, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            links[device.address]?.drop()
        }
        links[device.address]?.pumpContinue()
    }
}
