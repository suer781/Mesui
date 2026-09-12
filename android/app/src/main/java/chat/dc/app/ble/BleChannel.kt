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
    const val AUTH_CAND = 5     // 回连认证①：[type][initiatorIdentity:33][count:1][slotId:4×n]
    const val AUTH_CHA = 6      // 回连认证②：[type][nonce:16][responderIdentity:33]
    const val AUTH_RSP = 7      // 回连认证③：[type][hmac:16]（initiator 按候选算，命中定身份）
    const val AUTH_B_CHA = 8    // 反向认证①：[type][nonce:16]（initiator 出 nonce）
    const val AUTH_B_RSP = 9    // 反向认证②：[type][hmac:16]（responder 证明持有 S_i）

    // QR 快连（SP-3 蓝牙搭线）：扫码端读到 f=2 帧即回连，完整身份经加密通道交换
    const val QR_DIAL = 10      // 快连①（扫码端→出示端）：[type][challenge:16]——f=2 帧挑战原样回传
    const val QR_OFFER = 11     // 快连②（出示端→扫码端）：[type][nameLen:1][name][bundle...]（PreKeyBundle 公开材料，明文）
    const val QR_REQ = 12       // 快连③（扫码端→出示端）：[type][nameLen:1][name][sigMsgType:1][Signal密文 "dc-idreq"]
    const val QR_ID = 13        // 快连④（出示端→扫码端）：[type][sigMsgType:1][Signal密文 完整身份 dc://add URI——token 只走密文]

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

/** GATT 单次写/通知的物理预算下界：BLE 最小 MTU=23，减 ATT 头 3 字节 = 20。
 *  旧码下界钳 23 会把 MTU=23 时的真实预算 20 抬到 23——写 23 字节必失败（P2）。 */
internal const val MIN_CHUNK_SIZE = 20

/**
 * MTU → 分片尺寸（纯逻辑可测）：mtu − 3（ATT 头），钳制到 [MIN_CHUNK_SIZE, WANT_MTU]。
 * [negotiated] = onMtuChanged 的 status 是否 GATT_SUCCESS——协商失败时报告的 mtu
 * 不可信，回退保守最小预算 20（实际链路保持默认 MTU 23，20 字节写恒可行）。
 */
internal fun chunkSizeFor(mtu: Int, negotiated: Boolean): Int =
    if (negotiated) (mtu - Wire.HEADER_LEN).coerceIn(MIN_CHUNK_SIZE, LinkUuids.WANT_MTU)
    else MIN_CHUNK_SIZE

/** 单链路发送队列：一次只在途一分片，写/通知确认回调驱动下一片。
 *  GATT 单操作限制：writeCharacteristic/notifyCharacteristicChanged 必须等
 *  回调后才能发起下一次。仅靠「队列空」判定在途有竞态——写进行中、队列已空时
 *  再 send() 会并发下发；显式 inFlight 标志在 poll/settle 间串起整个在途窗口。 */
private class SendPump {
    private val queue = ArrayDeque<ByteArray>()
    // 写进行中标志：poll 置位，settle（写回调确认或写入被拒）复位。
    // volatile 供 send()（任意线程）与回调线程无锁读，翻转本身都在锁内
    @Volatile private var inFlight = false

    @Synchronized
    fun enqueue(chunks: List<ByteArray>) {
        queue.addAll(chunks)
    }

    /** 取下一片并发起一次写；在途或队列空返回 null（绝不并发下发）。 */
    @Synchronized
    fun poll(): ByteArray? {
        if (inFlight) return null
        val chunk = queue.poll() ?: return null
        inFlight = true
        return chunk
    }

    /** 在途写已落定（写回调确认 / 写入被拒未接受）：解锁泵，允许下一片。 */
    @Synchronized
    fun settle() {
        inFlight = false
    }

    /** 当前排队未发的分片数（诊断日志用）。 */
    @Synchronized
    fun pendingCount(): Int = queue.size

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
        // 判空与登记必须同一把锁内完成（P3 check-then-act）：旧码先在锁外读
        // rxChar 再进锁登记——就绪瞬间恰好在两步之间时，flushWaiters 已跑完、
        // 本回调登记进永远不会再 flush 的列表，握手静默挂死
        var ready = false
        synchronized(readyWaiters) {
            ready = rxChar != null
            if (!ready) readyWaiters += cb
        }
        if (ready) cb(true)
    }

    fun send(frame: ByteArray) {
        pump.enqueue(splitForChunk(frame, chunkSize))
        pumpOnce()
    }

    /** 泵下一片。poll() 内部有 inFlight 门闩：写进行中本次调用是空转，
     *  分片由写回调驱动续发——任何时刻至多一个在途 writeCharacteristic。 */
    @SuppressLint("MissingPermission")
    private fun pumpOnce() {
        val chunk = pump.poll() ?: return
        val char = rxChar ?: run { pump.clear(); pump.settle(); return }
        val g = gatt ?: run { pump.clear(); pump.settle(); return }
        val ok = try {
            writeCharacteristicCompat(g, char, chunk)
        } catch (_: Exception) {
            false
        }
        if (!ok) {
            // 写入未被协议栈接受（忙/资源异常）：分片不得静默丢（P1），
            // 也不会再有写回调来驱动队列——断链让上层按链路重建处理
            android.util.Log.w("BleChannel", "GATT 写特征失败，断链（丢 ${queueDepth()} 片）")
            pump.clear()
            pump.settle()
            events.onClosed()
        }
    }

    private fun queueDepth() = pump.pendingCount()

    @SuppressLint("MissingPermission")
    fun close() {
        pump.clear()
        pump.settle()
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
        // 协商失败（status≠GATT_SUCCESS）时 mtu 报告值不可信：按保守预算 20 走，
        // 绝不拿失败回调里的 mtu 抬高写预算（P2）
        chunkSize = chunkSizeFor(mtu, status == BluetoothGatt.GATT_SUCCESS)
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
        // 先释放在途标志再驱动下一片（P1：inFlight 窗口只在单次写期间闭合）
        pump.settle()
        if (status != BluetoothGatt.GATT_SUCCESS) {
            // 分片写失败：剩余队列作废并断链——旧码只清队列不断链，上层仍把
            // 链路当健康，后续帧继续走死链静默丢失
            android.util.Log.w("BleChannel", "onCharacteristicWrite status=$status，断链（丢 ${pump.pendingCount()} 片）")
            pump.clear()
            events.onClosed()
            return
        }
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
            pump.enqueue(splitForChunk(frame, chunkSize))
            pumpOnce()
        }

        /** 诊断日志用：当前排队未发的分片数。 */
        internal fun pendingChunks(): Int = pump.pendingCount()

        @SuppressLint("MissingPermission")
        private fun pumpOnce() {
            // poll() 内部 inFlight 门闩：notify 单操作限制，一次只在途一个通知
            val chunk = pump.poll() ?: return
            val s = server ?: run { pump.clear(); pump.settle(); return }
            val ok = try {
                @Suppress("DEPRECATION")
                if (Build.VERSION.SDK_INT >= 33) {
                    s.notifyCharacteristicChanged(device, txChar, false, chunk) ==
                        android.bluetooth.BluetoothStatusCodes.SUCCESS
                } else {
                    txChar.value = chunk
                    s.notifyCharacteristicChanged(device, txChar, false)
                }
            } catch (_: Exception) {
                false
            }
            if (!ok) {
                // 通知未被协议栈接受：不会再来 onNotificationSent 驱动队列——
                // 分片不得静默丢（P1），清队列并断链让上层按断线处理
                android.util.Log.w("BleChannel", "GATT notify 失败，断链（丢 ${pump.pendingCount()} 片）")
                pump.clear()
                pump.settle()
                events?.onClosed()
            }
        }

        /** 写回调驱动：释放在途标志后泵下一片。 */
        internal fun pumpContinue() {
            pump.settle()
            pumpOnce()
        }
        internal fun drop() { pump.clear(); pump.settle(); sink.reset() }
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

    /** @return 打开的 BluetoothGattServer；蓝牙未开（openGattServer 返回 null）
     *  时返回 null——调用方（BleMesh.refreshRadios）稍后重建，不再永久放弃（P1）。 */
    @SuppressLint("MissingPermission")
    fun start(): BluetoothGattServer? {
        server?.let { return it }
        val s = manager.openGattServer(context, this) ?: return null
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
        return s
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
            // K2-13：server 侧重连（同地址二次 CONNECTED，如对端断开重连）覆盖
            // links[address] 前必须先关闭旧链路并回调 onClosed——旧 ServerLink 不
            // drop 不回调会让发送泵/事件监听孤儿化（旧链路队列残留、上层永不清理）
            val old = links.put(device.address, link)
            old?.let { it.drop(); it.events?.onClosed() }
            onNewClient?.onClient(link)
        } else {
            links.remove(device.address)?.let { it.drop(); it.events?.onClosed() }
        }
    }

    override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
        // server 侧回调无 status 参数：能到达即协商完成，按成功钳制（同 client 侧下界 20）
        links[device.address]?.chunkSize = chunkSizeFor(mtu, true)
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
        val link = links[device.address] ?: return
        if (status != BluetoothGatt.GATT_SUCCESS) {
            // 通知分片失败：与 client 侧 onCharacteristicWrite 对称（P2）——
            // 只清队列不断链会让上层把链路当健康，后续帧继续走死链静默丢失
            android.util.Log.w("BleChannel", "onNotificationSent status=$status，断链（丢 ${link.pendingChunks()} 片）")
            link.drop()
            link.events?.onClosed()
            return
        }
        link.pumpContinue()
    }
}
