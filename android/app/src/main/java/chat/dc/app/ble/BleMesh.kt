package chat.dc.app.ble

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.AdvertisingSetParameters
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import chat.dc.app.addfriend.AddFriendPayload
import chat.dc.app.addfriend.FrameCodec
import chat.dc.app.core.SignalCore
import chat.dc.app.friendlink.FriendLink
import chat.dc.core.Contact
import chat.dc.core.DcException
import chat.dc.core.SasCode
import chat.dc.core.WireMessage
import chat.dc.core.firstMessageMac
import chat.dc.core.prekeySenderIdentity
import chat.dc.core.verifyFirstMessageMac
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.security.SecureRandom
import java.util.UUID

private val SERVICE_PU = ParcelUuid(LinkUuids.SERVICE_UUID)
private val PAIR_UUID = ParcelUuid(UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e70"))

/** QR 快连③的 Signal 密文标记：扫码端用它向出示端索要完整身份（含 token）。 */
private const val QR_ID_REQ = "dc-idreq"

/** 链路事件转接（构造期回填）。 */
private class LinkAdapter : LinkEvents {
    var onFrame: ((ByteArray) -> Unit)? = null
    var onClosed: (() -> Unit)? = null
    override fun onFrame(frame: ByteArray) { onFrame?.invoke(frame) }
    override fun onClosed() { onClosed?.invoke() }
}

enum class PeerState { ONLINE, OFFLINE }

/** 配对状态的不可变快照（StateFlow 按相等去重，UI 必须收快照而非可变实例）。 */
data class PairingSnap(
    val asHost: Boolean,
    val peerName: String?,
    val sas: SasCode?,
    val localConfirmed: Boolean,
    val peerConfirmed: Boolean,
    val waitingLink: Boolean,
    val finished: Boolean,
    /** QR 快连错误：0 无 / 1 失败（重扫） / 2 对方身份已变更（拒绝）。仅扫码端。 */
    val dialError: Int = 0,
)

/** 统一链路句柄。 */
internal sealed class LinkHandle {
    abstract fun send(frame: ByteArray)
    abstract fun closeLink()
}

internal class ServerLinkHandle(val link: BleServer.ServerLink) : LinkHandle() {
    override fun send(frame: ByteArray) = link.send(frame)
    override fun closeLink() = link.drop()
}

internal class ClientLinkHandle(val link: BleClientLink) : LinkHandle() {
    override fun send(frame: ByteArray) = link.send(frame)
    override fun closeLink() = link.close()
}

/** 已解密的入站聊天消息。 */
data class Incoming(val peerName: String, val text: String)

private class AuthState {
    @Volatile var initiatorIdentity: ByteArray? = null
    @Volatile var nonce: ByteArray? = null
    @Volatile var nonceB: ByteArray? = null
    @Volatile var secret: ByteArray? = null
    @Volatile var peerHex: String? = null
    @Volatile var peerName: String? = null
}

private class PairingInternal(val asHost: Boolean) {
    @Volatile var peerName: String? = null
    @Volatile var peerIdentity: ByteArray? = null
    @Volatile var token: ByteArray? = null
    @Volatile var bucket: ByteArray? = null
    @Volatile var bleId: ByteArray? = null
    @Volatile var naddr: String = ""
    @Volatile var sas: SasCode? = null
    @Volatile var localConfirmed = false
    @Volatile var peerConfirmed = false
    @Volatile var link: LinkHandle? = null
    @Volatile var finished = false

    // QR 快连（SP-3 蓝牙搭线）。challenge 非空 = 快连模式：
    // 出示端持有 qrPayload（答 QR_DIAL/QR_REQ 用）；扫码端 QR_OFFER 收到的
    // bundle 存 offerBundle，QR_ID 到达时做绑定校验（防换包）。
    @Volatile var challenge: ByteArray? = null
    @Volatile var qrPayload: AddFriendPayload? = null
    @Volatile var offerBundle: ByteArray? = null
    @Volatile var dialError = 0 // 0 无 / 1 快连失败 / 2 对方身份变更（仅扫码端）
    // token 时效界（红队 R2-7）：QR 载荷携带，进首条消息 token-MAC 输入。
    // 旧数据帧路径经 startPairingAsJoiner 传入；0 = 未知（验方 fail-closed 拒绝）
    @Volatile var expiresAtMs = 0L
    // 出示端：配对开始时刻（QR_REQ 时长门槛——偷拍者拍单帧+回连同样要等满
    // 3 秒才能拿到 token，与拍全数据帧的门槛等价）。扫码端：identityReadyAtMs
    // = 本端时长门槛到期时刻，到点才发 QR_REQ。
    @Volatile var startedAtMs = -1L
    @Volatile var identityReadyAtMs = -1L
    // 扫码端上次回连发起时刻：常驻扫描回调高频到达（LOW_LATENCY 下每秒十余次），
    // 配对广播在链路建立前一直在场——不去重会叠出成片的并发 GATT 连接互相踩踏
    @Volatile var lastDialAtMs = 0L

    fun snap() = PairingSnap(
        asHost = asHost,
        peerName = peerName,
        sas = sas,
        localConfirmed = localConfirmed,
        peerConfirmed = peerConfirmed,
        waitingLink = link == null,
        finished = finished,
        dialError = dialError,
    )
}

/**
 * 常驻 BLE mesh 编排：广播（布隆过滤器，10 分钟槽轮换 + 配对期临时 id）、
 * 占空比扫描、命中才回连 + 双向 HMAC 挑战应答、配对状态机（HS/SAS/S_i）、
 * 聊天收发。蓝牙射频行为留真机验证（阶段 4）；本文件保证编译与逻辑正确。
 */
object BleMesh {

    private const val TAG = "BleMesh"

    // 身份公钥长度契约 = 33 字节（libsignal IdentityKey::serialize()：1 字节类型前缀 + 32）。
    // AUTH 全流程统一引用此常量，勿再手写 32——旧码 32/33 混用导致回连握手
    // 两端都建不起来（P0-1）
    private const val IDENTITY_LEN = 33

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val security = SecureRandom()

    @Volatile private var appContext: Context? = null
    @Volatile private var advertiser: BluetoothLeAdvertiser? = null
    @Volatile private var scanner: BluetoothLeScanner? = null
    @Volatile private var server: BleServer? = null

    private val _peers = MutableStateFlow<Map<String, PeerState>>(emptyMap())
    val peers = _peers.asStateFlow()

    private val _pairing = MutableStateFlow<PairingSnap?>(null)
    val pairing = _pairing.asStateFlow()

    private val _incoming = MutableSharedFlow<Incoming>(extraBufferCapacity = 64)
    val incoming = _incoming.asSharedFlow()

    // 主线程（UI 登记配对）写、binder 扫描/GATT 回调线程读：必须 volatile
    // 保证可见性（P1），否则扫描线程可能永远看不到新登记的配对对象
    @Volatile private var pairingObj: PairingInternal? = null
    private val links = mutableMapOf<String, LinkHandle>()
    private val connectingAddr = mutableSetOf<String>()
    private var advJob: Job? = null
    private var scanJob: Job? = null
    @Volatile private var advCallback: AdvertisingSetCallback? = null
    // legacy 回退路径的回调：与扩展广播的 advCallback 分开持有——两条 API 的
    // 回调类型互不通用，对应的 stop API 也不同（stopAdvertising vs stopAdvertisingSet），
    // 混用既编不过也无法正确停掉在播的 legacy 广播
    @Volatile private var legacyAdvCallback: android.bluetooth.le.AdvertiseCallback? = null

    // 红队 R2-1：QR_OFFER 同名限频台账（name → (bundle hash, 上次处理时刻)）。
    // QR_OFFER 在 token 门禁之前，进程生命周期内持久存在——配对态下攻击者可
    // 无认证高频灌入。30s 窗 + 软上限时机清扫。
    private const val QR_OFFER_PER_NAME_WINDOW_MS = 30_000L
    private const val QR_OFFER_SEEN_SOFT_CAP = 256
    private val qrOfferSeen = java.util.concurrent.ConcurrentHashMap<String, Pair<Int, Long>>()

    @SuppressLint("MissingPermission")
    fun init(context: Context) {
        if (appContext != null) return
        appContext = context.applicationContext
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bt = manager.adapter ?: return
        advertiser = bt.bluetoothLeAdvertiser
        scanner = bt.bluetoothLeScanner
        newBleServer(context).also { srv -> if (srv.start() != null) server = srv }
        startAdvertiseLoop()
        startScanLoop()
    }

    /** 统一组装 GATT server（server 方向链路的 onNewClient 转接）。 */
    private fun newBleServer(context: Context): BleServer = BleServer(context).apply {
        onNewClient = object : BleServer.NewClient {
            override fun onClient(link: BleServer.ServerLink) = handleIncomingLink(link)
        }
    }

    /** NodeService.onDestroy：停回路、停广播/扫描、关 server 与全部链路。 */
    @SuppressLint("MissingPermission")
    fun shutdown() {
        advJob?.cancel()
        scanJob?.cancel()
        advJob = null
        scanJob = null
        advCallback?.let { runCatching { advertiser?.stopAdvertisingSet(it) } }
        advCallback = null
        legacyAdvCallback?.let { runCatching { advertiser?.stopAdvertising(it) } }
        legacyAdvCallback = null
        runCatching { server?.stop() }
        server = null
        synchronized(links) { links.values.forEach { runCatching { it.closeLink() } }; links.clear() }
        synchronized(connectingAddr) { connectingAddr.clear() }
        _peers.value = emptyMap()
        // 配对态一并作废：UI 收到 null 快照回到未配对态，扫描线程也不再匹配
        // 已死配对的 bleId 去回连（P3）
        pairingObj = null
        _pairing.value = null
        scanCache = null
        appContext = null
    }

    /** K2-9：shutdown() 后返回 null（不再 error() 抛 IllegalStateException）——
     *  迟到的 GATT/扫描回调在各入口判空静默退出，绝不于 binder 线程炸进程。 */
    private fun ctx(): Context? = appContext
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun publishPairing() { _pairing.value = pairingObj?.snap() }

    /** 蓝牙可能在服务冷启动（init）之后才被打开/授权：射频句柄不能只在 init
     *  抓一次——蓝牙未开时 adapter 返回 null，旧码把 null 存死，扫描协程
     *  `?: return` 直接熄火、广播每轮空转，之后蓝牙再开也无人重启。
     *  每轮广播/扫描回路开始时重新解析即可自愈。 */
    @SuppressLint("MissingPermission")
    private fun refreshRadios() {
        val context = appContext ?: return
        val bt = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter ?: return
        if (!bt.isEnabled) {
            // 关着时置空：下一轮蓝牙打开后再解析（持有失效句柄 startScan 会持续抛）
            advertiser = null
            scanner = null
            // 蓝牙关闭时系统会回收 GATT server：丢弃旧实例，开回来后重建
            server?.let { runCatching { it.stop() } }
            server = null
            return
        }
        if (advertiser == null) advertiser = runCatching { bt.bluetoothLeAdvertiser }.getOrNull()
        if (scanner == null) scanner = runCatching { bt.bluetoothLeScanner }.getOrNull()
        // GATT server 同样自愈（P1）：init 时蓝牙未开，openGattServer 返回 null
        // 即永久放弃——server 方向链路（被回连方的应答通道）从此缺失。每轮检查，
        // 缺失且蓝牙已就绪就重建；start 失败（仍返回 null）下一轮再试。
        if (server == null) {
            newBleServer(context).also { srv -> if (srv.start() != null) server = srv }
        }
    }

    // ---------------- 广播回路 ----------------

    private fun startAdvertiseLoop() {
        advJob?.cancel()
        advJob = scope.launch {
            while (true) {
                runCatching { publishAdvOnce() }
                val now = System.currentTimeMillis()
                val slot = FriendLink.currentSlot(now)
                delay((slot + 1) * FriendLink.SLOT_MS - now + security.nextInt(3000))
            }
        }
    }

    /** 配对开始/结束时立刻重播（附带/摘除配对 id）。 */
    fun republishAdv() = scope.launch { runCatching { publishAdvOnce() } }

    @SuppressLint("MissingPermission")
    private suspend fun publishAdvOnce() {
        refreshRadios()
        val adv = advertiser ?: return
        val bloom = runCatching { currentBloom() }.getOrNull() ?: return
        val p = pairingObj?.takeIf { it.asHost && !it.finished && it.link == null }

        advCallback?.let { runCatching { adv.stopAdvertisingSet(it) } }
        legacyAdvCallback?.let { runCatching { adv.stopAdvertising(it) } }
        advCallback = null
        legacyAdvCallback = null
        delay(250) // stop→start 栈内序列化留量

        // 红队盲审 P0-B 修复：扩展广播不支持的机型回退 legacy API。
        // adapter 与 refreshRadios() 同源解析（经 BluetoothManager 动态获取）：
        // 本对象不持有 adapter 句柄，蓝牙开关随时可能变更，不能只抓一次
        val bt = (appContext?.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        val useExtended = bt?.isLeExtendedAdvertisingSupported == true
        if (useExtended) {
            val data = AdvertiseData.Builder()
                .addServiceUuid(SERVICE_PU)
                .addServiceData(SERVICE_PU, FriendLink.advertisePayload(bloom))
                .setIncludeDeviceName(false)
                .apply { p?.bleId?.let { addServiceUuid(PAIR_UUID); addServiceData(PAIR_UUID, it) } }
                .build()
            val params = AdvertisingSetParameters.Builder()
                .setLegacyMode(false)
                .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
                .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_LOW)
                .build()
            val cb = object : AdvertisingSetCallback() {
                override fun onAdvertisingSetStarted(
                    set: android.bluetooth.le.AdvertisingSet?, txPower: Int, status: Int,
                ) {
                    if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                        android.util.Log.w("BleMesh", "ext adv failed status=$status")
                    }
                }
            }
            advCallback = cb
            runCatching { adv.startAdvertisingSet(params, data, null, null, null, cb) }
        } else {
            // legacy 回退：31B 上限内只放 service UUID + bleId（bloom 省略）
            val legacyData = AdvertiseData.Builder()
                .addServiceUuid(SERVICE_PU)
                .apply { p?.bleId?.let { addServiceUuid(PAIR_UUID); addServiceData(PAIR_UUID, it) } }
                .setIncludeDeviceName(false)
                .build()
            val settings = android.bluetooth.le.AdvertiseSettings.Builder()
                .setAdvertiseMode(android.bluetooth.le.AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
                .setConnectable(true)
                .build()
            val cb = object : android.bluetooth.le.AdvertiseCallback() {
                override fun onStartFailure(errorCode: Int) {
                    android.util.Log.w("BleMesh", "legacy adv failed errorCode=$errorCode")
                }
            }
            legacyAdvCallback = cb
            runCatching { adv.startAdvertising(settings, legacyData, cb) }
        }
    }

    private fun currentBloom(): ByteArray? {
        val context = ctx() ?: return null // K2-9：shutdown 后静默跳过本轮广播
        val secrets = SignalCore.contactStore(context).listContacts()
            .filter { it.verified }
            .map { it.linkSecret }
            .take(FriendLink.CAP_FRIENDS)
        return FriendLink.buildBloom(secrets, FriendLink.currentSlot(), ByteArray(2048).also(security::nextBytes))
    }

    // ---------------- 扫描回路 ----------------

    /** K2-6：本机是否支持 LE Extended Advertising——与广播端 publishAdvOnce 的
     *  useExtended 判定同源（经 BluetoothManager 动态解析 adapter）。 */
    private fun leExtendedAdvertisingSupported(): Boolean = runCatching {
        (appContext?.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
            ?.adapter?.isLeExtendedAdvertisingSupported == true
    }.getOrDefault(false)

    private fun startScanLoop() {
        scanJob?.cancel()
        scanJob = scope.launch {
            val cb = object : ScanCallback() {
                // K2-6：extended 扫描的回调层失败标记（onScanFailed 在 binder 线程回调）
                @Volatile var failed = false
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    runCatching { handleScanResult(result) }
                }
                override fun onScanFailed(errorCode: Int) {
                    android.util.Log.w(TAG, "BLE scan failed errorCode=$errorCode")
                    failed = true
                }
            }
            val filters = listOf(ScanFilter.Builder().setServiceUuid(SERVICE_PU).build())
            // 红队盲审 P0-A 修复：必须 setLegacy(false) 才能收到扩展广播（bloom 129B 超 legacy 31B 上限）。
            // 不设此标志 = 扫描器永远收不到配对广播 = 加好友 100% 不可用。
            // K2-6 修复：但 setLegacy(false) 只在本机支持 LE Extended Advertising 时合法——
            // 不支持的机型上 extended 扫描启动失败且被 runCatching 吞掉 → 永远收不到任何
            // 广播，mesh 发现/快连静默死亡。按适配器能力决定初始模式；extended 失败
            // （startScan 抛异常或 onScanFailed）自动降级 legacy 重试一次并保持（不来回抖动）。
            var legacy = !leExtendedAdvertisingSupported()
            var downgraded = false
            while (true) {
                refreshRadios()
                val sc = scanner
                if (sc == null) {
                    // 蓝牙未就绪：不熄火，稍后重试（旧码在此 return@launch 永久退出）
                    delay(2000)
                    continue
                }
                val settings = ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setLegacy(legacy)
                    .build()
                val started = runCatching { sc.startScan(filters, settings, cb) }.isSuccess
                if (!started && !legacy && !downgraded) {
                    // extended 启动即失败：降级 legacy 重试一次
                    legacy = true
                    downgraded = true
                    continue
                }
                delay(1000)
                runCatching { sc.stopScan(cb) }
                delay(1000)
                if (!legacy && !downgraded && cb.failed) {
                    // extended 已启动但回调层失败：同样降级 legacy 重试一次
                    legacy = true
                    downgraded = true
                    cb.failed = false
                }
            }
        }
    }

    /**
     * 扫描端每槽缓存（P2）：LOW_LATENCY 下扫描回调每秒十余条，旧码每条都跑
     * listContacts（SQLCipher 全表查询）+ 每位好友 2 槽位 × 2 轮 HKDF。按 10 分钟
     * 槽缓存「联系人 + 双槽派生 ID」，联系人集变动经 [invalidateScanCache] 作废，
     * 下一轮扫描结果触发重建。
     */
    private class ScanCache(
        val slot: Long,
        val contacts: List<Contact>,
        /** 与 contacts 对齐：[本槽 ID, 前一槽 ID]（槽边界时钟偏差容忍窗口）。 */
        val slotIds: List<List<ByteArray>>,
    )

    @Volatile private var scanCache: ScanCache? = null

    /** 联系人增删改后调用：作废扫描端每槽缓存（删除联系人等场景由
     *  SignalCore 的 store 钩子代调）。 */
    @Synchronized
    fun invalidateScanCache() {
        scanCache = null
    }

    private fun buildScanCache(slot: Long): ScanCache {
        val contacts = ctx()
            ?.let { runCatching { SignalCore.contactStore(it).listContacts().filter { c -> c.verified } }.getOrDefault(emptyList()) }
            ?: emptyList() // K2-9：shutdown 后按空联系人处理，调用方自然放弃
        return ScanCache(
            slot,
            contacts,
            contacts.map {
                listOf(FriendLink.slotId(it.linkSecret, slot), FriendLink.slotId(it.linkSecret, slot - 1))
            },
        )
    }

    @SuppressLint("MissingPermission")
    private fun handleScanResult(result: ScanResult) {
        val record = result.scanRecord ?: return
        val device = result.device
        val p = pairingObj?.takeIf { !it.finished }

        if (p != null && !p.asHost && p.link == null) {
            val target = p.bleId
            val seen = record.serviceData[PAIR_UUID]
            if (target != null && seen != null && seen.contentEquals(target)) {
                // 回连限频（1 次/秒）：扫描回调远快于 GATT 连接建立，去重缺失
                // 会并发拉起十几条 connectGatt——失败链接的 onClosed 会把在用
                // 链路的 p.link 打掉并误标 dialError，握手必死
                val now = System.currentTimeMillis()
                if (now - p.lastDialAtMs >= 1_000) {
                    p.lastDialAtMs = now
                    connectJoiner(device, p)
                }
                return
            }
        }

        val bloom = FriendLink.parseAdvertisePayload(record.serviceData[SERVICE_PU]) ?: return
        val slot = FriendLink.currentSlot()
        val cache = scanCache?.takeIf { it.slot == slot } ?: buildScanCache(slot).also { scanCache = it }
        if (cache.contacts.isEmpty()) return
        // 与 FriendLink.candidates 同语义（本槽→前一槽窗口），但派生 ID 走缓存
        val cands = cache.contacts.mapIndexed { i, c ->
            cache.slotIds[i].firstOrNull { FriendLink.bloomHit(bloom, it) }?.let { c to it }
        }.filterNotNull()
        if (cands.isEmpty()) return
        synchronized(links) {
            if (cache.contacts.any { links.containsKey(hex(it.identity)) }) return
        }
        synchronized(connectingAddr) { if (!connectingAddr.add(device.address)) return }
        connectInitiator(device, cands.map { it.second }, cache.contacts)
    }

    // ---------------- 回连发起方（client） ----------------

    @SuppressLint("MissingPermission")
    private fun connectInitiator(device: BluetoothDevice, candidateIds: List<ByteArray>, contacts: List<Contact>) {
        val context = ctx() ?: return // K2-9：shutdown 后迟到回调静默退出
        val adapter = LinkAdapter()
        val link = BleClientLink(context, device, adapter)
        val handle = ClientLinkHandle(link)
        val st = AuthState()
        adapter.onFrame = { frame -> onInitiatorFrame(handle, frame, st, contacts, device) }
        adapter.onClosed = {
            st.peerHex?.let { h ->
                val removed = synchronized(links) { if (links[h] === handle) links.remove(h) != null else false }
                // K2-7：StateFlow 读改写必须走 update{}（原子），多 binder/扫描线程
                // 并发下 `_peers.value = _peers.value + …` 会互相覆盖丢更新
                if (removed) _peers.update { it + (h to PeerState.OFFLINE) }
            }
            synchronized(connectingAddr) { connectingAddr.remove(device.address) }
        }
        link.connect()
        link.whenReady { ok ->
            if (!ok) { link.close(); return@whenReady }
            val me = runCatching { SignalCore.session(context).identityKey() }
                .onFailure { android.util.Log.w(TAG, "本端身份密钥读取失败，回连放弃", it) }
                .getOrNull() ?: run { link.close(); return@whenReady }
            val body = me + byteArrayOf(candidateIds.size.toByte()) +
                candidateIds.fold(ByteArray(0)) { a, b -> a + b }
            link.send(wireFrame(Wire.AUTH_CAND, body))
        }
    }

    private fun onInitiatorFrame(handle: ClientLinkHandle, frame: ByteArray, st: AuthState, contacts: List<Contact>, device: BluetoothDevice) {
        if (frame.size < Wire.HEADER_LEN) return
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        when (frame[0].toInt()) {
            Wire.AUTH_CHA -> {
                // 挑战体 = nonce(16) + 对方身份公钥(33)。旧码断言 16+32 且切片
                // copyOfRange(16, 48) 只取 32 字节，与 contact.identity(33) 永不匹配
                // → 回连握手发起端建不起来（P0-1）
                if (body.size != 16 + IDENTITY_LEN) return
                val nonce = body.copyOfRange(0, 16)
                val theirId = body.copyOfRange(16, 16 + IDENTITY_LEN)
                // 候选集已在扫描层（布隆命中）过滤，identity 命中本地联系人即定身份
                val contact = contacts.firstOrNull { it.identity.contentEquals(theirId) } ?: return
                st.secret = contact.linkSecret
                st.nonce = nonce
                st.peerHex = hex(theirId)
                st.peerName = contact.name
                // K2-9：shutdown 后 ctx() 为 null——回调入口静默退出
                val context = ctx() ?: return
                // K2-8：close 与替换合并进同一锁域——Map.put 原子返回被替换的旧链路，
                // 消除两段 synchronized 间并发线程注册新链路却被旧引用误关的 TOCTOU；
                // closeLink 在锁外调用，避免持锁触发 GATT 回调再入 links 锁
                val previous = synchronized(links) { links.put(st.peerHex!!, handle) }
                previous?.closeLink()
                // K2-7：update{} 原子读改写（多线程并发注册/摘除不丢更新）
                _peers.update { it + (st.peerHex!! to PeerState.ONLINE) }
                synchronized(connectingAddr) { connectingAddr.remove(device.address) }
                handle.send(wireFrame(Wire.AUTH_RSP, FriendLink.hmac(contact.linkSecret, nonce)))
                runCatching { SignalCore.contactStore(context).setVerified(contact.name, true) }
                invalidateScanCache()
            }
            Wire.AUTH_B_CHA -> {
                // 反向认证①：能走到这里说明响应端已验证我们的 AUTH_RSP（HMAC(S_i,
                // nonce)）并进入 B 轮——对端至少是协议兼容方。用 AUTH_CHA 时命中的
                // 联系人 S_i（st.secret）对响应端的 nonceB 再算一次截断 HMAC 回
                // AUTH_B_RSP，响应端验签通过才算双向认证闭环（P1：旧码无此分支，
                // else 吞帧——AUTH_B_RSP 永远不回，响应端反向校验永远悬空）
                val secret = st.secret ?: return
                if (body.size != 16) return
                handle.send(wireFrame(Wire.AUTH_B_RSP, FriendLink.hmac(secret, body)))
            }
            Wire.MSG -> dispatchIncoming(handle, frame, st.peerName)
            else -> Unit
        }
    }

    // ---------------- 回连应答方（server link） ----------------

    private fun handleIncomingLink(link: BleServer.ServerLink) {
        val adapter = LinkAdapter()
        val handle = ServerLinkHandle(link)
        val st = AuthState()
        adapter.onFrame = { frame -> onResponderFrame(handle, link, frame, st) }
        adapter.onClosed = {
            st.peerHex?.let { h ->
                val removed = synchronized(links) { if (links[h] === handle) links.remove(h) != null else false }
                // K2-7：StateFlow 读改写必须走 update{}（原子），多 binder/扫描线程
                // 并发下 `_peers.value = _peers.value + …` 会互相覆盖丢更新
                if (removed) _peers.update { it + (h to PeerState.OFFLINE) }
            }
        }
        link.events = adapter
    }

    @SuppressLint("MissingPermission")
    private fun onResponderFrame(handle: ServerLinkHandle, link: BleServer.ServerLink, frame: ByteArray, st: AuthState) {
        if (frame.size < Wire.HEADER_LEN) return
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        when (frame[0].toInt()) {
            Wire.AUTH_CAND -> {
                // 体 = 发起方身份公钥(33) + 候选数(1) + n 个槽位 id。旧码按 32 解析
                // 身份、count/ids 全部错位 → 回连握手应答端建不起来（P0-1）
                if (body.size < IDENTITY_LEN + 1) return
                val theirId = body.copyOfRange(0, IDENTITY_LEN)
                val n = body[IDENTITY_LEN].toInt() and 0xFF
                // K2-1（P0）：n 无上界时恶意帧可让 copyOfRange(from > to) 抛
                // IllegalArgumentException——本分支跑在 GATT binder 回调线程，
                // 范围内任意设备未认证直连 GATT server 写 RX 特征即可远程崩溃。
                // 严格长度匹配（33 + 1 + n*4），不符一律丢帧
                if (body.size != IDENTITY_LEN + 1 + n * FriendLink.ID_LEN) return
                val ids = (0 until n).map { body.copyOfRange(IDENTITY_LEN + 1 + it * FriendLink.ID_LEN, IDENTITY_LEN + 1 + (it + 1) * FriendLink.ID_LEN) }
                val contacts = ctx()
                    ?.let { runCatching { SignalCore.contactStore(it).listContacts().filter { c -> c.verified } }.getOrDefault(emptyList()) }
                    ?: emptyList() // K2-9：shutdown 后按空联系人处理（假阳性入连对端超时自断）
                val slot = FriendLink.currentSlot()
                val hit = contacts.firstOrNull { c ->
                    ids.any { id -> FriendLink.slotId(c.linkSecret, slot).contentEquals(id) || FriendLink.slotId(c.linkSecret, slot - 1).contentEquals(id) }
                } ?: return // 假阳性入连：不回话，对端超时自断
                // 自报身份必须与槽位 ID 命中的联系人一致（P2）：槽位 ID 只证
                // 「对端持有某位好友的 S_i」，自报的 identity 未经证实——两者
                // 不一致即冒充/张冠李戴，沉默拒绝
                if (!theirId.contentEquals(hit.identity)) return
                st.secret = hit.linkSecret
                st.peerHex = hex(hit.identity)
                st.peerName = hit.name
                st.initiatorIdentity = theirId
                val nonce = ByteArray(16).also(security::nextBytes)
                st.nonce = nonce
                val myId = ctx()?.let { runCatching { SignalCore.session(it).identityKey() }.getOrNull() } ?: return // K2-9
                link.send(wireFrame(Wire.AUTH_CHA, nonce + myId))
            }
            Wire.AUTH_RSP -> {
                val secret = st.secret ?: return
                val nonce = st.nonce ?: return
                val expected = FriendLink.hmac(secret, nonce)
                if (body.size != FriendLink.HMAC_TRUNC || !FriendLink.constantTimeEquals(body, expected)) {
                    link.drop(); return
                }
                // K2-8：同上——close 与替换同一锁域（put 原子取旧链路），锁外 close
                val previous = synchronized(links) { links.put(st.peerHex!!, handle) }
                previous?.closeLink()
                // K2-7：update{} 原子读改写（多线程并发注册/摘除不丢更新）
                _peers.update { it + (st.peerHex!! to PeerState.ONLINE) }
                val nonceB = ByteArray(16).also(security::nextBytes)
                st.nonceB = nonceB
                link.send(wireFrame(Wire.AUTH_B_CHA, nonceB))
            }
            Wire.AUTH_B_RSP -> {
                val expected = FriendLink.hmac(st.secret ?: return, st.nonceB ?: return)
                val ok = body.size == FriendLink.HMAC_TRUNC && FriendLink.constantTimeEquals(body, expected)
                if (!ok) link.drop()
            }
            Wire.HS -> onHostHandshake(handle, body)
            Wire.QR_DIAL -> onHostQrDial(link, body)
            Wire.QR_REQ -> onHostQrReq(handle, link, body)
            Wire.SAS_OK -> pairingObj?.takeIf { it.asHost && !it.finished }?.let {
                it.peerConfirmed = true
                publishPairing()
            }
            Wire.MSG -> dispatchIncoming(handle, frame, st.peerName)
            else -> Unit
        }
    }

    // ---------------- 配对 ----------------

    /** QR 快连①：扫码端读到 f=2 蓝牙帧后经常驻扫描回连，原样回传挑战。
     *  挑战对上 + 本端正在出示配对 + 尚无配对链路，才回 QR_OFFER（把 GATT
     *  连接与当前出示的动态码绑定）；其余一律不回话，对端超时自断。 */
    @SuppressLint("MissingPermission")
    private fun onHostQrDial(link: BleServer.ServerLink, body: ByteArray) {
        val p = pairingObj?.takeIf { it.asHost && !it.finished && it.link == null } ?: return
        val challenge = p.challenge ?: return // 非 QR 快连配对：不回话
        if (body.size != challenge.size || !body.contentEquals(challenge)) return
        val payload = p.qrPayload ?: return
        if (payload.bundle.size > Wire.MAX_BODY - 66) return // 异常大 bundle：放弃快连，扫码端走数据帧回退
        val nameBytes = payload.name.toByteArray(Charsets.UTF_8)
        link.send(wireFrame(Wire.QR_OFFER, byteArrayOf(nameBytes.size.toByte()) + nameBytes + payload.bundle))
    }

    /** QR 快连③：扫码端已用 bundle 建会话，经 Signal 加密通道索要完整身份。
     *  两道门：①本端配对已进行 ≥[FrameCodec.MIN_COLLECT_MS]——偷拍者拍单帧+
     *  回连拿不到 token，须与拍全数据帧同样在场 3 秒（SP-3 时长门槛双端执行；
     *  合法扫码端的门槛计时必然包含在出示时长内——码都看不见就无从扫起）；
     *  ②请求标记在 Signal 密文里（会话由出示端 bundle 建立，密文只有持会话的
     *  QR 对端能造）。token 只在密文里过空。 */
    @SuppressLint("MissingPermission")
    private fun onHostQrReq(handle: ServerLinkHandle, link: BleServer.ServerLink, body: ByteArray) {
        val p = pairingObj?.takeIf { it.asHost && !it.finished } ?: return
        if (p.link != null && p.link !== handle) return // 配对链路已被别的连接占用
        val payload = p.qrPayload ?: return
        val startedAt = p.startedAtMs
        if (startedAt < 0 || System.currentTimeMillis() - startedAt < FrameCodec.MIN_COLLECT_MS) return
        if (body.isEmpty()) return
        val nameLen = body[0].toInt() and 0xFF
        if (nameLen == 0 || body.size < 1 + nameLen + 1) return
        val name = String(body.copyOfRange(1, 1 + nameLen), Charsets.UTF_8)
        val session = ctx()?.let { runCatching { SignalCore.session(it) }.getOrNull() } ?: return // K2-9
        val plain = runCatching {
            session.decrypt(name, WireMessage(body[1 + nameLen].toUByte(), body.copyOfRange(2 + nameLen, body.size)))
        }.getOrNull() ?: return
        if (plain.size != QR_ID_REQ.length || String(plain, Charsets.US_ASCII) != QR_ID_REQ) return
        val wm = runCatching { session.encrypt(name, payload.encode().toByteArray(Charsets.UTF_8)) }.getOrNull() ?: return
        link.send(wireFrame(Wire.QR_ID, byteArrayOf(wm.msgType.toByte()) + wm.ciphertext))
    }

    private fun onHostHandshake(handle: ServerLinkHandle, body: ByteArray) {
        val p = pairingObj?.takeIf { it.asHost && !it.finished } ?: return
        if (body.size < 1 + 1 + 32 + 1) return
        val nameLen = body[0].toInt() and 0xFF
        if (body.size < 1 + nameLen + 32 + 1) return
        val name = String(body.copyOfRange(1, 1 + nameLen), Charsets.UTF_8)
        // K2-4：对端名必须过 NAME_RE（含 1..64 长度界，与 QR 载荷/deviceName 同源
        // 约束）——恶意名（含 / ? & 等）不过校验即断链，否则落库后
        // MainActivity 的 navigate("chat/$name") 路由不匹配抛 IllegalArgumentException
        if (!SignalCore.NAME_RE.matches(name)) { handle.closeLink(); return }
        val rest = body.copyOfRange(1 + nameLen, body.size)
        val mac = rest.copyOfRange(0, 32)
        val sigType = rest[32]
        val ct = rest.copyOfRange(33, rest.size)
        val token = p.token ?: return
        val bucket = p.bucket ?: return
        // 红队 R2-7：token-MAC 绑定会话名 + 时效界（出示端 QR 载荷给出的 exp）。
        // 过期 / 未知时效（旧版载荷 exp 缺省 0）一律 fail-closed 拒绝——
        // 完整拍摄的载荷只在窗口内、只对本次配对会话有效。
        val expiry = p.qrPayload?.expiresAtMs ?: 0L
        // 绑定签名带 now_ms（Rust 侧一并做过期判定）：双保险，调用前先本地判一次
        val now = System.currentTimeMillis()
        val verified = expiry > 0 && now <= expiry &&
            runCatching { verifyFirstMessageMac(token, bucket, name, expiry.toULong(), ct, mac, now.toULong()) }.getOrDefault(false)
        if (!verified) { handle.closeLink(); return }
        val context = ctx() ?: return // K2-9：shutdown 后迟到握手静默退出（链路已随 shutdown 关闭）
        val session = SignalCore.session(context)
        val plain = runCatching { session.decrypt(name, WireMessage(sigType.toUByte(), ct)) }.getOrNull() ?: return
        // 明文 = "dc-hs"（旧版，无节点快照）或 "dc-hs" + 0x00 + dc://node 快照（跨网直连入口）
        if (!(plain.size == 5 && String(plain, Charsets.US_ASCII) == "dc-hs") &&
            !(plain.size > 6 && plain[5] == 0.toByte() && String(plain.copyOfRange(6, plain.size), Charsets.US_ASCII).startsWith("dc://node"))
        ) return
        p.naddr = if (plain.size > 6) String(plain.copyOfRange(6, plain.size), Charsets.US_ASCII) else ""
        val theirId = runCatching { prekeySenderIdentity(ct) }.getOrNull() ?: return
        p.peerName = name
        p.peerIdentity = theirId
        p.link = handle
        p.sas = runCatching { session.sasWith(SignalCore.deviceName(context), name, theirId) }.getOrNull()
        val hexKey = hex(theirId)
        synchronized(links) { links[hexKey] = handle }
        // K2-7：update{} 原子读改写（同上）
        _peers.update { it + (hexKey to PeerState.ONLINE) }
        publishPairing()
    }

    @SuppressLint("MissingPermission")
    private fun connectJoiner(device: BluetoothDevice, p: PairingInternal) {
        val context = ctx() ?: return // K2-9：shutdown 后迟到回连静默退出
        val adapter = LinkAdapter()
        val link = BleClientLink(context, device, adapter)
        val handle = ClientLinkHandle(link)
        val name = p.peerName ?: return
        adapter.onFrame = { frame ->
            if (frame.size >= Wire.HEADER_LEN) {
                when (frame[0].toInt()) {
                    Wire.SAS_OK -> { p.peerConfirmed = true; publishPairing() }
                    Wire.MSG -> onJoinerBusiness(handle, frame, p)
                    Wire.QR_OFFER -> onJoinerQrOffer(handle, frame, p)
                    Wire.QR_ID -> onJoinerQrId(handle, frame, p)
                    else -> Unit
                }
            }
        }
        adapter.onClosed = {
            // 只清本链路持有的配对链路：重试产生的失败链接不得把在用链路打掉
            // （旧码无条件 p.link = null，握手进行中被并发失败链接误判为断链）
            val wasActive = p.link === handle
            if (wasActive) p.link = null
            // QR 快连中途断链且未完成：标记失败（UI 提示重扫；完整身份仍可
            // 经数据帧全集回退）。已完成/旧路径（无 challenge）不打扰；
            // 仅「已搭线在用」的链路断开才算失败——连接尝试本身失败只等
            // 下轮限频重试，不算错
            if (wasActive && !p.finished && p.challenge != null && p.dialError == 0) p.dialError = 1
            publishPairing()
        }
        link.connect()
        link.whenReady { ok ->
            if (!ok || p.finished) { link.close(); return@whenReady }
            val challenge = p.challenge
            if (challenge != null) {
                // QR 快连：身份尚未到手，先原样回传挑战搭线（出示端比对通过
                // 才回 QR_OFFER）；QR_OFFER/QR_ID 到齐后再走既有 token-MAC 握手
                p.link = handle
                publishPairing()
                link.send(wireFrame(Wire.QR_DIAL, challenge))
                return@whenReady
            }
            sendJoinerHandshake(handle, p)
        }
    }

    /** 身份就绪（旧路径 startPairingAsJoiner 直接就绪 / QR 快连 QR_ID 到齐）后：
     *  发 token-MAC 握手（SP-3 第 4 条：首条消息必须携带 token 派生确认），
     *  随后进入 SAS 比对。
     *  在自有协程里发（P1）：旧码 runBlocking(Dispatchers.IO) 直接跑在 GATT
     *  binder 回调线程，等 iroh 快照最长 4 秒会卡死同一 server 上所有设备的
     *  GATT 回调。 */
    private fun sendJoinerHandshake(handle: ClientLinkHandle, p: PairingInternal) {
        scope.launch {
            // 链路已被其他连接接替 / 配对已完成：本次握手作废
            if (p.finished || (p.link != null && p.link !== handle)) return@launch
            withContext(Dispatchers.IO) {
                val context = ctx() ?: return@withContext // K2-9：shutdown 后握手作废
                val name = p.peerName ?: return@withContext
                val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return@withContext
                val token = p.token ?: return@withContext
                val bucket = p.bucket ?: return@withContext
                // 等 iroh 节点快照就绪（冷启动 onReady 可能滞后于 BLE 配对）。超时则降级
                // 沿用当前快照（可能为空 → 退化为纯 BLE 握手），绝不因此阻塞 BLE 配对；
                // 不静默把 naddr 写成空，否则联系人 node_naddr 被永久置空、跨网不可达（缺陷 D）
                val myNaddr = withTimeoutOrNull(4000L) {
                    chat.dc.app.core.IrohNodeManager.state.first { it.naddr.isNotBlank() }
                }?.naddr ?: chat.dc.app.core.IrohNodeManager.state.value.naddr
                val plainPayload = if (myNaddr.isEmpty()) {
                    "dc-hs".toByteArray()
                } else {
                    "dc-hs".toByteArray(Charsets.US_ASCII) + byteArrayOf(0) + myNaddr.toByteArray(Charsets.US_ASCII)
                }
                val wm = runCatching { session.encrypt(name, plainPayload) }.getOrNull() ?: return@withContext
                // 红队 R2-7：token-MAC 绑定会话名（本帧的收件方名，与出示端验方
                // 同源）+ 时效界（QR 载荷携带的 exp）；未知时效 fail-closed 不发
                val expiry = p.expiresAtMs
                if (expiry <= 0L || System.currentTimeMillis() > expiry) {
                    android.util.Log.w(TAG, "token 已过期或缺时效界（exp=$expiry），握手放弃")
                    return@withContext
                }
                val mac = runCatching { firstMessageMac(token, bucket, name, expiry.toULong(), wm.ciphertext) }.getOrNull() ?: return@withContext
                // 等待期间链路可能已被接替/配对完成：复查再发
                if (p.finished || (p.link != null && p.link !== handle)) return@withContext
                val nameBytes = name.toByteArray()
                val body = byteArrayOf(nameBytes.size.toByte()) + nameBytes + mac + byteArrayOf(wm.msgType.toByte()) + wm.ciphertext
                handle.send(wireFrame(Wire.HS, body))
                p.link = handle
                val idHex = p.peerIdentity?.let { hex(it) }
                if (idHex != null) synchronized(links) { links[idHex] = handle }
                publishPairing()
            }
        }
    }

    /** QR 快连②：出示端回 PreKeyBundle（公开材料，明文与旧版二维码数据帧等价）。
     *  本端 PQXDH 建会话，再经 Signal 加密通道索要完整身份（QR_REQ，到时长门槛
     *  才发——与出示端门槛共同维持「偷拍需持续在场 3 秒」）。
     *
     *  红队 R2-1 修复：QR_OFFER 是 token 门禁前的明文帧，攻击者可无认证高频
     *  灌入 bundle 制造 trusted_identities/sessions 行并抢注真实联系人名字。
     *  同一 name 的 processBundle 每 [QR_OFFER_PER_NAME_WINDOW_MS] 最多 1 次
     *  （同 bundle 字节的重试放行——链路抖动后的合法重连是幂等的，不损伤可用性）；
     *  配合 signal_store 的覆盖保护（同名异钥需用户确认），抢注不再是永久伤害。 */
    private fun onJoinerQrOffer(handle: ClientLinkHandle, frame: ByteArray, p: PairingInternal) {
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        if (body.size < 2 + 256) return // nameLen:1 + name:≥1 + bundle:≥256（载荷契约）
        val nameLen = body[0].toInt() and 0xFF
        if (nameLen == 0 || body.size < 1 + nameLen + 256) return
        val name = String(body.copyOfRange(1, 1 + nameLen), Charsets.UTF_8)
        // K2-4 同类防御：QR_OFFER 是 token 门禁前的明文帧，该名经 processBundle
        // 建会话、最终可随配对落库为联系人——非法名（路由不安全字符）直接断链
        if (!SignalCore.NAME_RE.matches(name)) { handle.closeLink(); return }
        val bundle = body.copyOfRange(1 + nameLen, body.size)
        val context = ctx() ?: return // K2-9：shutdown 后迟到回调静默退出
        // 同名限频（轻量台账操作，留在回调线程即时拒绝高频灌帧）：30s 窗内同名异 bundle 一律拒绝
        val now = System.currentTimeMillis()
        val seen = qrOfferSeen[name]
        if (seen != null && now - seen.second < QR_OFFER_PER_NAME_WINDOW_MS && seen.first != bundle.contentHashCode()) {
            p.dialError = 1
            publishPairing()
            handle.closeLink()
            return
        }
        qrOfferSeen[name] = bundle.contentHashCode() to now
        if (qrOfferSeen.size > QR_OFFER_SEEN_SOFT_CAP) {
            qrOfferSeen.entries.removeIf { now - it.value.second >= QR_OFFER_PER_NAME_WINDOW_MS }
        }
        // K2-14（P3）：首次取会话（dlopen native + SQLCipher KDF）、processBundle
        // （Kyber-1024 + X25519）与 encrypt 都是重活——旧码直接跑在 GATT binder
        // 回调线程，会卡死同一 GATT server 上所有设备的回调。挪自有协程（IO），
        // 回调线程立即返回。
        scope.launch(Dispatchers.IO) {
            val session = runCatching { SignalCore.session(context) }.getOrNull() ?: run {
                p.dialError = 1
                publishPairing()
                handle.closeLink()
                return@launch
            }
            try {
                session.processBundle(name, bundle)
            } catch (_: DcException.RemoteIdentityChanged) {
                p.dialError = 2
                publishPairing()
                handle.closeLink()
                return@launch
            } catch (_: Exception) {
                p.dialError = 1
                publishPairing()
                handle.closeLink()
                return@launch
            }
            p.peerName = name
            p.offerBundle = bundle
            val wm = runCatching { session.encrypt(name, QR_ID_REQ.toByteArray(Charsets.US_ASCII)) }.getOrNull() ?: run {
                p.dialError = 1
                publishPairing()
                handle.closeLink()
                return@launch
            }
            // 时长门槛到期才索要完整身份（token 只走密文）；到期前先挂在加密会话上等
            val wait = (p.identityReadyAtMs - System.currentTimeMillis()).coerceAtLeast(0)
            if (wait > 0) delay(wait)
            if (p.finished || p.link !== handle || p.challenge == null) return@launch
            val myName = SignalCore.deviceName(context)
            val myNameBytes = myName.toByteArray(Charsets.UTF_8)
            handle.send(
                wireFrame(
                    Wire.QR_REQ,
                    byteArrayOf(myNameBytes.size.toByte()) + myNameBytes +
                        byteArrayOf(wm.msgType.toByte()) + wm.ciphertext,
                ),
            )
        }
    }

    /** QR 快连④：出示端经 Signal 加密通道回完整身份（含 bootstrap token——
     *  token 只走密文，SP-3 第 4 条不变）。与 QR_OFFER 绑定校验（同名同 bundle，
     *  防换包）后填齐配对状态并走既有 token-MAC 握手 + SAS。 */
    private fun onJoinerQrId(handle: ClientLinkHandle, frame: ByteArray, p: PairingInternal) {
        val offerBundle = p.offerBundle ?: return
        val name = p.peerName ?: return
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        if (body.isEmpty()) return
        val context = ctx() ?: return // K2-9：shutdown 后迟到回调静默退出
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val plain = runCatching {
            session.decrypt(name, WireMessage(body[0].toUByte(), body.copyOfRange(1, body.size)))
        }.getOrNull() ?: return
        val payload = runCatching { AddFriendPayload.parse(String(plain, Charsets.UTF_8)) }.getOrNull()
        if (payload == null || payload.name != name || !payload.bundle.contentEquals(offerBundle)) {
            p.dialError = 1
            publishPairing()
            handle.closeLink()
            return
        }
        p.token = payload.token
        p.bucket = payload.bucket
        p.bleId = payload.ble
        p.peerIdentity = payload.identity
        p.naddr = payload.naddr
        p.expiresAtMs = payload.expiresAtMs
        p.challenge = null
        // 快连路径 SAS 由 BleMesh 直接算好（与出示端 onHostHandshake 对称）
        p.sas = runCatching {
            session.sasWith(SignalCore.deviceName(context), payload.name, payload.identity)
        }.getOrNull()
        sendJoinerHandshake(handle, p)
    }

    /** joiner 在配对链路上收到的 MSG：配对期只可能是 DCS1（S_i 下发），其余丢弃。
     *  K2-2（P1）：配对完成后本链路就是双方聊天主链路（host 侧 onHostHandshake
     *  已把它注册进 links 并继续用它发聊天 MSG）——此后 MSG 须转主链路
     *  decryptAndStore 正常解密落库，否则 host→joiner 单向聊天全部静默丢失。
     *  （decryptAndStore 自带 DCS1 下发格式拒收，迟到/重放的 DCS1 不会走这里。） */
    private fun onJoinerBusiness(handle: LinkHandle, frame: ByteArray, p: PairingInternal) {
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        if (body.isEmpty()) return
        val context = ctx() ?: return
        val name = p.peerName ?: return
        if (p.finished) {
            decryptAndStore(name, body)
            return
        }
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val plain = runCatching { session.decrypt(name, WireMessage(body[0].toUByte(), body.copyOfRange(1, body.size))) }.getOrNull() ?: return
        if (plain.size == 4 + 32 && String(plain.copyOfRange(0, 4), Charsets.US_ASCII) == "DCS1") {
            finishJoinerWithSecret(p, plain.copyOfRange(4, plain.size))
        }
    }

    private fun finishJoinerWithSecret(p: PairingInternal, secret: ByteArray) {
        val context = ctx() ?: return // K2-9：shutdown 后迟到 DCS1 静默退出
        val name = p.peerName ?: return
        val theirId = p.peerIdentity ?: return
        val peerNodeId = runCatching { chat.dc.core.nodeIdFromNaddr(p.naddr) }.getOrDefault("")
        runCatching { SignalCore.contactStore(context).upsertContact(name, theirId, p.bucket ?: ByteArray(32), true, "", secret, peerNodeId, p.naddr) }
            .onFailure { android.util.Log.w(TAG, "联系人（含 S_i）落库失败", it) }
        invalidateCaches()
        p.finished = true
        p.link?.send(wireFrame(Wire.SAS_OK, ByteArray(0)))
        publishPairing()
    }

    /** 联系人落库后的缓存作废：扫描每槽缓存 + iroh nodeId 反查缓存（P2-8/P2-10）。 */
    private fun invalidateCaches() {
        invalidateScanCache()
        runCatching { chat.dc.app.core.IrohNodeManager.invalidateNodeIdIndex() }
    }

    /** 出示页进入。[payload] = 本场动态码载荷（QR 快连用它应答 QR_DIAL/QR_REQ），
     *  [challenge] = 蓝牙连接帧（f=2）的当场随机挑战。 */
    fun startPairingAsHost(payload: AddFriendPayload, challenge: ByteArray) {
        pairingObj = PairingInternal(asHost = true).apply {
            token = payload.token; bucket = payload.bucket; bleId = payload.ble
            qrPayload = payload
            this.challenge = challenge
            startedAtMs = System.currentTimeMillis()
        }
        publishPairing()
        republishAdv()
    }

    /** 出示页离开（本端已确认则保留结果，仅未完成时撤销配对）。 */
    fun stopPairingAsHost() {
        val p = pairingObj?.takeIf { it.asHost && !it.finished } ?: return
        if (p.localConfirmed) return
        p.link?.closeLink()
        pairingObj = null
        publishPairing()
        republishAdv()
    }

    /** 扫码页采集完成（UI 已 processBundle）。expiresAtMs = token 时效界
     *  （红队 R2-7，QR 载荷携带；旧版载荷缺省 0 → 握手 fail-closed）。 */
    fun startPairingAsJoiner(peerName: String, peerIdentity: ByteArray, token: ByteArray, bucket: ByteArray, bleId: ByteArray, naddr: String, expiresAtMs: Long = 0) {
        pairingObj = PairingInternal(asHost = false).apply {
            this.peerName = peerName; this.peerIdentity = peerIdentity
            this.token = token; this.bucket = bucket; this.bleId = bleId
            this.naddr = naddr
            this.expiresAtMs = expiresAtMs
        }
        publishPairing()
    }

    /**
     * 扫码页读到蓝牙连接帧（f=2）立即调：只登记搭线信息（名字/配对 id/挑战），
     * 常驻 BLE 扫描命中对方配对广播即回连（QR_DIAL→QR_OFFER→QR_REQ→QR_ID→HS），
     * 完整身份（含 token）经蓝牙上的 Signal 加密通道交换，不走二维码。
     * [identityReadyAtMs] = 本端 3 秒时长门槛到期时刻（FrameCollector 锚定）——
     * 到点才发 QR_REQ 索要完整身份，与出示端门槛共同维持防偷拍时长语义。
     */
    fun startQrDialAsJoiner(peerName: String, bleId: ByteArray, challenge: ByteArray, identityReadyAtMs: Long) {
        // 双路径互踩守卫（P2）：降级序列下数据帧可能先集齐（startPairingAsJoiner
        // 已建配对、SAS 进行中），之后才读到 f=2 蓝牙帧——旧码无条件覆盖
        // pairingObj，正在 SAS 的旧配对被孤儿化（其链路回调仍写旧对象，UI 快照
        // 却换成空壳新对象，状态机与界面脱钩）。已有活跃配对在 SAS 阶段即拒绝
        // 新搭线，先到先得
        val existing = pairingObj
        if (existing != null && !existing.finished && existing.sas != null) return
        pairingObj = PairingInternal(asHost = false).apply {
            this.peerName = peerName
            this.bleId = bleId
            this.challenge = challenge
            this.identityReadyAtMs = identityReadyAtMs
        }
        publishPairing()
    }

    fun stopPairingAsJoiner() {
        val p = pairingObj?.takeIf { !it.asHost && !it.finished } ?: return
        p.link?.closeLink()
        pairingObj = null
        publishPairing()
    }

    /** 快连失败后重试（P3，UI「重试」按钮）：清错误标记与中途状态，常驻扫描
     *  命中对方配对广播即重新回连（lastDialAtMs 归零解除限频等待）。 */
    fun retryQrDial() {
        val p = pairingObj?.takeIf { !it.asHost && !it.finished } ?: return
        p.dialError = 0
        p.link?.closeLink()
        p.link = null
        p.offerBundle = null // 作废中途会话材料，重走完整 QR_OFFER → QR_ID
        p.lastDialAtMs = 0L
        publishPairing()
    }

    /** 本地点「一致」：立即本地 pin + 存联系人；host 生成并下发 S_i。 */
    fun confirmSas() {
        val p = pairingObj?.takeIf { !it.finished && !it.localConfirmed } ?: return
        val context = ctx() ?: return // K2-9：shutdown 后静默退出
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val name = p.peerName ?: return
        val theirId = p.peerIdentity ?: return
        // 节点地址落库：host 取自配对握手携带的快照，joiner 取自 QR 载荷
        val peerNodeId = runCatching { chat.dc.core.nodeIdFromNaddr(p.naddr) }.getOrDefault("")
        runCatching { session.pinIdentity(name, theirId) }
        if (p.asHost) {
            val secret = ByteArray(32).also(security::nextBytes)
            runCatching { SignalCore.contactStore(context).upsertContact(name, theirId, p.bucket ?: ByteArray(32), true, "", secret, peerNodeId, p.naddr) }
                .onFailure { android.util.Log.w(TAG, "联系人（含 S_i）落库失败", it) }
            invalidateCaches()
            val wm = runCatching { session.encrypt(name, "DCS1".toByteArray(Charsets.US_ASCII) + secret) }
                .onFailure { android.util.Log.w(TAG, "DCS1 加密失败，S_i 未下发", it) }
                .getOrNull()
            wm?.let { p.link?.send(wireFrame(Wire.MSG, byteArrayOf(it.msgType.toByte()) + it.ciphertext)) }
            p.finished = true
        } else {
            // 全零 linkSecret 不落库（P2）：旧码先以全零占位，DCS1 一旦丢失
            // 就永久持零密钥——零密钥派生的槽位 ID 对所有零密钥联系人恒相同
            //（污染布隆过滤器 + 可关联），聊天链路 HMAC 也全错。DCS1 到达
            // （finishJoinerWithSecret 携真实 S_i）才落库；丢失则停留在
            // 「已确认待下发」态，重新扫码即可恢复，不会写坏任何数据。
        }
        p.localConfirmed = true
        p.link?.send(wireFrame(Wire.SAS_OK, ByteArray(0)))
        publishPairing()
    }

    // ---------------- 业务帧 ----------------

    /** 统一解密落库入口：BLE 帧 / iroh 远程载荷（均为 msgType+密文体）共用。
     *  返回 true = 解密成功且已落库（iroh 路径据此回执 ACK，红队 R2-2）。 */
    private fun decryptAndStore(peerName: String, body: ByteArray): Boolean {
        if (body.isEmpty()) return false
        val context = appContext ?: return false
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return false
        val plain = runCatching {
            session.decrypt(peerName, WireMessage(body[0].toUByte(), body.copyOfRange(1, body.size)))
        }.getOrNull() ?: return false // 解密失败：NAK，发送方重试
        if (plain.size == 4 + 32 && String(plain.copyOfRange(0, 4), Charsets.US_ASCII) == "DCS1") return false // 聊天链路拒收下发格式
        val text = String(plain, Charsets.UTF_8)
        val stored = runCatching { SignalCore.contactStore(context).appendMessage(peerName, false, text) }.isSuccess
        if (!stored) return false // 落库失败：NAK，发送方重试（不假送达）
        _incoming.tryEmit(Incoming(peerName, text))
        return true
    }

    private fun dispatchIncoming(handle: LinkHandle, frame: ByteArray, peerNameHint: String?) {
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        // 红队盲审 P1-B 修复：握手路径不走 AuthState，peerNameHint 为 null 时
        // 从 PairingObj 兜底取 peerName（onHostHandshake 已写入）
        val name = peerNameHint
            ?: pairingObj?.peerName?.takeIf { it.isNotBlank() }
            ?: return
        decryptAndStore(name, body)
    }

    /** iroh 远程链路投递（IrohNodeManager 回调）：与 BLE 收发同一条落库+入站流
     *  路径。返回解密+落库是否成功——调用方据此向 iroh 传输层回执
     *  ACK/NAK（红队 R2-2：假投递回执修复）。 */
    fun deliverRemote(peerName: String, body: ByteArray): Boolean = decryptAndStore(peerName, body)

    /**
     * 发送文本：BLE 在线链路优先（近场免费直发）；无链路且有对方节点快照
     * 则走 iroh 跨网络（阻塞等对端应用层确认，调用方须在 IO 线程）。
     * 两条路都不通返回 false（UI 显示「对方不在线」），不落库（队列补投为后续阶段）。
     */
    fun sendText(peerName: String, text: String): Boolean {
        val context = ctx() ?: return false // K2-9：shutdown 后无链路可发
        val contact = runCatching {
            SignalCore.contactStore(context).listContacts().firstOrNull { it.name == peerName }
        }.getOrNull() ?: return false
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return false
        val wm = runCatching { session.encrypt(peerName, text.toByteArray()) }.getOrNull() ?: return false
        val payload = byteArrayOf(wm.msgType.toByte()) + wm.ciphertext
        val sent = synchronized(links) { links[hex(contact.identity)] }?.let {
            it.send(wireFrame(Wire.MSG, payload))
            true
        } ?: (contact.nodeNaddr.isNotEmpty() && chat.dc.app.core.IrohNodeManager.isRunning() &&
            chat.dc.app.core.IrohNodeManager.send(contact.nodeNaddr, payload))
        if (sent) runCatching { SignalCore.contactStore(context).appendMessage(peerName, true, text) }
        return sent
    }

    fun isOnline(peerName: String): Boolean {
        val context = ctx() ?: return false // K2-9：shutdown 后全离线
        val contact = runCatching {
            SignalCore.contactStore(context).listContacts().firstOrNull { it.name == peerName }
        }.getOrNull() ?: return false
        return synchronized(links) { links.containsKey(hex(contact.identity)) }
    }
}
