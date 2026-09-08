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
import chat.dc.app.core.SignalCore
import chat.dc.app.friendlink.FriendLink
import chat.dc.core.Contact
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
import kotlinx.coroutines.launch
import java.security.SecureRandom
import java.util.UUID

private val SERVICE_PU = ParcelUuid(LinkUuids.SERVICE_UUID)
private val PAIR_UUID = ParcelUuid(UUID.fromString("8f9d5a11-4c2b-4e0a-9d1e-5a1b2c3d4e70"))

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
    @Volatile var sas: SasCode? = null
    @Volatile var localConfirmed = false
    @Volatile var peerConfirmed = false
    @Volatile var link: LinkHandle? = null
    @Volatile var finished = false

    fun snap() = PairingSnap(
        asHost = asHost,
        peerName = peerName,
        sas = sas,
        localConfirmed = localConfirmed,
        peerConfirmed = peerConfirmed,
        waitingLink = link == null,
    )
}

/**
 * 常驻 BLE mesh 编排：广播（布隆过滤器，10 分钟槽轮换 + 配对期临时 id）、
 * 占空比扫描、命中才回连 + 双向 HMAC 挑战应答、配对状态机（HS/SAS/S_i）、
 * 聊天收发。蓝牙射频行为留真机验证（阶段 4）；本文件保证编译与逻辑正确。
 */
object BleMesh {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val security = SecureRandom()

    @Volatile private var appContext: Context? = null
    @Volatile private var advertiser: BluetoothLeAdvertiser? = null
    @Volatile private var scanner: BluetoothLeScanner? = null
    private var server: BleServer? = null

    private val _peers = MutableStateFlow<Map<String, PeerState>>(emptyMap())
    val peers = _peers.asStateFlow()

    private val _pairing = MutableStateFlow<PairingSnap?>(null)
    val pairing = _pairing.asStateFlow()

    private val _incoming = MutableSharedFlow<Incoming>(extraBufferCapacity = 64)
    val incoming = _incoming.asSharedFlow()

    private var pairingObj: PairingInternal? = null
    private val links = mutableMapOf<String, LinkHandle>()
    private val connectingAddr = mutableSetOf<String>()
    private var advJob: Job? = null
    private var scanJob: Job? = null
    @Volatile private var advCallback: AdvertisingSetCallback? = null

    @SuppressLint("MissingPermission")
    fun init(context: Context) {
        if (appContext != null) return
        appContext = context.applicationContext
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bt = manager.adapter ?: return
        advertiser = bt.bluetoothLeAdvertiser
        scanner = bt.bluetoothLeScanner
        val srv = BleServer(context)
        srv.onNewClient = object : BleServer.NewClient {
            override fun onClient(link: BleServer.ServerLink) = handleIncomingLink(link)
        }
        srv.start()
        server = srv
        startAdvertiseLoop()
        startScanLoop()
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
        runCatching { server?.stop() }
        server = null
        synchronized(links) { links.values.forEach { runCatching { it.closeLink() } }; links.clear() }
        synchronized(connectingAddr) { connectingAddr.clear() }
        _peers.value = emptyMap()
        appContext = null
    }

    private fun ctx(): Context = appContext ?: error("BleMesh.init 未调用")
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun publishPairing() { _pairing.value = pairingObj?.snap() }

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
        val adv = advertiser ?: return
        val bloom = runCatching { currentBloom() }.getOrNull() ?: return
        val p = pairingObj?.takeIf { it.asHost && !it.finished && it.link == null }
        val data = AdvertiseData.Builder()
            .addServiceUuid(SERVICE_PU)
            .addServiceData(SERVICE_PU, FriendLink.advertisePayload(bloom))
            .setIncludeDeviceName(false)
            .apply { p?.bleId?.let { addServiceUuid(PAIR_UUID); addServiceData(PAIR_UUID, it) } }
            .build()
        val params = AdvertisingSetParameters.Builder()
            .setLegacyMode(false)
            .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
            .setTxPowerLevel(AdvertisingSetParameters.TRANSMIT_POWER_LOW)
            .build()
        advCallback?.let { runCatching { adv.stopAdvertisingSet(it) } }
        delay(250) // stop→start 栈内序列化留量
        val cb = object : AdvertisingSetCallback() {
            override fun onAdvertisingSetStarted(set: android.bluetooth.le.AdvertisingSet?, txPower: Int, status: Int) = Unit
        }
        advCallback = cb
        runCatching { adv.startAdvertisingSet(params, data, null, null, null, cb) }
    }

    private fun currentBloom(): ByteArray {
        val secrets = SignalCore.contactStore(ctx()).listContacts()
            .filter { it.verified }
            .map { it.linkSecret }
            .take(FriendLink.CAP_FRIENDS)
        return FriendLink.buildBloom(secrets, FriendLink.currentSlot(), ByteArray(2048).also(security::nextBytes))
    }

    // ---------------- 扫描回路 ----------------

    private fun startScanLoop() {
        scanJob?.cancel()
        scanJob = scope.launch {
            val sc = scanner ?: return@launch
            val cb = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    runCatching { handleScanResult(result) }
                }
            }
            val filters = listOf(ScanFilter.Builder().setServiceUuid(SERVICE_PU).build())
            val settings = ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build()
            while (true) {
                runCatching { sc.startScan(filters, settings, cb) }
                delay(1000)
                runCatching { sc.stopScan(cb) }
                delay(1000)
            }
        }
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
                connectJoiner(device, p)
                return
            }
        }

        val bloom = FriendLink.parseAdvertisePayload(record.serviceData[SERVICE_PU]) ?: return
        val contacts = runCatching { SignalCore.contactStore(ctx()).listContacts().filter { it.verified } }
            .getOrDefault(emptyList())
        if (contacts.isEmpty()) return
        val slot = FriendLink.currentSlot()
        val cands = FriendLink.candidates(bloom, contacts.map { it.linkSecret }, slot)
        if (cands.isEmpty()) return
        synchronized(links) {
            if (contacts.any { links.containsKey(hex(it.identity)) }) return
        }
        synchronized(connectingAddr) { if (!connectingAddr.add(device.address)) return }
        connectInitiator(device, cands.map { it.second }, contacts)
    }

    // ---------------- 回连发起方（client） ----------------

    @SuppressLint("MissingPermission")
    private fun connectInitiator(device: BluetoothDevice, candidateIds: List<ByteArray>, contacts: List<Contact>) {
        val context = ctx()
        val adapter = LinkAdapter()
        val link = BleClientLink(context, device, adapter)
        val handle = ClientLinkHandle(link)
        val st = AuthState()
        adapter.onFrame = { frame -> onInitiatorFrame(handle, frame, st, contacts, device) }
        adapter.onClosed = {
            st.peerHex?.let { h ->
                val removed = synchronized(links) { if (links[h] === handle) links.remove(h) != null else false }
                if (removed) _peers.value = _peers.value + (h to PeerState.OFFLINE)
            }
            synchronized(connectingAddr) { connectingAddr.remove(device.address) }
        }
        link.connect()
        link.whenReady { ok ->
            if (!ok) { link.close(); return@whenReady }
            val me = runCatching { SignalCore.session(context).identityKey() }.getOrNull() ?: run { link.close(); return@whenReady }
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
                if (body.size != 16 + 32) return
                val nonce = body.copyOfRange(0, 16)
                val theirId = body.copyOfRange(16, 48)
                // 候选集已在扫描层（布隆命中）过滤，identity 命中本地联系人即定身份
                val contact = contacts.firstOrNull { it.identity.contentEquals(theirId) } ?: return
                st.secret = contact.linkSecret
                st.nonce = nonce
                st.peerHex = hex(theirId)
                st.peerName = contact.name
                val context = ctx()
                synchronized(links) { links[st.peerHex!!] }?.closeLink()
                synchronized(links) { links[st.peerHex!!] = handle }
                _peers.value = _peers.value + (st.peerHex!! to PeerState.ONLINE)
                synchronized(connectingAddr) { connectingAddr.remove(device.address) }
                handle.send(wireFrame(Wire.AUTH_RSP, FriendLink.hmac(contact.linkSecret, nonce)))
                runCatching { SignalCore.contactStore(context).setVerified(contact.name, true) }
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
                if (removed) _peers.value = _peers.value + (h to PeerState.OFFLINE)
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
                if (frame.size < Wire.HEADER_LEN + 33) return
                val theirId = body.copyOfRange(0, 32)
                val n = body[32].toInt() and 0xFF
                val ids = (0 until n).map { body.copyOfRange(33 + it * FriendLink.ID_LEN, minOf(33 + (it + 1) * FriendLink.ID_LEN, body.size)) }
                val contacts = runCatching { SignalCore.contactStore(ctx()).listContacts().filter { it.verified } }.getOrDefault(emptyList())
                val slot = FriendLink.currentSlot()
                val hit = contacts.firstOrNull { c ->
                    ids.any { id -> FriendLink.slotId(c.linkSecret, slot).contentEquals(id) || FriendLink.slotId(c.linkSecret, slot - 1).contentEquals(id) }
                } ?: return // 假阳性入连：不回话，对端超时自断
                st.secret = hit.linkSecret
                st.peerHex = hex(hit.identity)
                st.peerName = hit.name
                st.initiatorIdentity = theirId
                val nonce = ByteArray(16).also(security::nextBytes)
                st.nonce = nonce
                val myId = runCatching { SignalCore.session(ctx()).identityKey() }.getOrNull() ?: return
                link.send(wireFrame(Wire.AUTH_CHA, nonce + myId))
            }
            Wire.AUTH_RSP -> {
                val secret = st.secret ?: return
                val nonce = st.nonce ?: return
                if (body.size != FriendLink.HMAC_TRUNC || !body.contentEquals(FriendLink.hmac(secret, nonce))) {
                    link.drop(); return
                }
                synchronized(links) { links[st.peerHex!!] }?.closeLink()
                synchronized(links) { links[st.peerHex!!] = handle }
                _peers.value = _peers.value + (st.peerHex!! to PeerState.ONLINE)
                val nonceB = ByteArray(16).also(security::nextBytes)
                st.nonceB = nonceB
                link.send(wireFrame(Wire.AUTH_B_CHA, nonceB))
            }
            Wire.AUTH_B_RSP -> {
                val ok = st.secret != null && st.nonceB != null &&
                    body.size == FriendLink.HMAC_TRUNC && body.contentEquals(FriendLink.hmac(st.secret!!, st.nonceB!!))
                if (!ok) link.drop()
            }
            Wire.HS -> onHostHandshake(handle, body)
            Wire.SAS_OK -> pairingObj?.takeIf { it.asHost && !it.finished }?.let {
                it.peerConfirmed = true
                publishPairing()
            }
            Wire.MSG -> dispatchIncoming(handle, frame, st.peerName)
            else -> Unit
        }
    }

    // ---------------- 配对 ----------------

    private fun onHostHandshake(handle: ServerLinkHandle, body: ByteArray) {
        val p = pairingObj?.takeIf { it.asHost && !it.finished } ?: return
        if (body.size < 1 + 1 + 32 + 1) return
        val nameLen = body[0].toInt() and 0xFF
        if (body.size < 1 + nameLen + 32 + 1) return
        val name = String(body.copyOfRange(1, 1 + nameLen), Charsets.UTF_8)
        val rest = body.copyOfRange(1 + nameLen, body.size)
        val mac = rest.copyOfRange(0, 32)
        val sigType = rest[32]
        val ct = rest.copyOfRange(33, rest.size)
        val token = p.token ?: return
        val bucket = p.bucket ?: return
        val verified = runCatching { verifyFirstMessageMac(token, bucket, ct, mac) }.getOrDefault(false)
        if (!verified) { handle.closeLink(); return }
        val context = ctx()
        val session = SignalCore.session(context)
        val plain = runCatching { session.decrypt(name, WireMessage(sigType.toUByte(), ct)) }.getOrNull() ?: return
        if (!plain.contentEquals("dc-hs".toByteArray())) return
        val theirId = runCatching { prekeySenderIdentity(ct) }.getOrNull() ?: return
        p.peerName = name
        p.peerIdentity = theirId
        p.link = handle
        p.sas = runCatching { session.sasWith(SignalCore.deviceName(context), name, theirId) }.getOrNull()
        val hexKey = hex(theirId)
        synchronized(links) { links[hexKey] = handle }
        _peers.value = _peers.value + (hexKey to PeerState.ONLINE)
        publishPairing()
    }

    @SuppressLint("MissingPermission")
    private fun connectJoiner(device: BluetoothDevice, p: PairingInternal) {
        val context = ctx()
        val adapter = LinkAdapter()
        val link = BleClientLink(context, device, adapter)
        val handle = ClientLinkHandle(link)
        val name = p.peerName ?: return
        adapter.onFrame = { frame ->
            if (frame.size >= Wire.HEADER_LEN) {
                when (frame[0].toInt()) {
                    Wire.SAS_OK -> { p.peerConfirmed = true; publishPairing() }
                    Wire.MSG -> onJoinerBusiness(handle, frame, p)
                    else -> Unit
                }
            }
        }
        adapter.onClosed = { p.link = null; publishPairing() }
        link.connect()
        link.whenReady { ok ->
            if (!ok || p.finished) { link.close(); return@whenReady }
            val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return@whenReady
            val token = p.token ?: return@whenReady
            val bucket = p.bucket ?: return@whenReady
            val wm = runCatching { session.encrypt(name, "dc-hs".toByteArray()) }.getOrNull() ?: return@whenReady
            val mac = runCatching { firstMessageMac(token, bucket, wm.ciphertext) }.getOrNull() ?: return@whenReady
            val nameBytes = name.toByteArray()
            val body = byteArrayOf(nameBytes.size.toByte()) + nameBytes + mac + byteArrayOf(wm.msgType.toByte()) + wm.ciphertext
            link.send(wireFrame(Wire.HS, body))
            p.link = handle
            val idHex = p.peerIdentity?.let { hex(it) }
            if (idHex != null) synchronized(links) { links[idHex] = handle }
            publishPairing()
        }
    }

    /** joiner 在配对链路上收到的 MSG：只可能是 DCS1（S_i 下发），其余丢弃等主链路。 */
    private fun onJoinerBusiness(handle: LinkHandle, frame: ByteArray, p: PairingInternal) {
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        if (body.isEmpty()) return
        val context = ctx()
        val name = p.peerName ?: return
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val plain = runCatching { session.decrypt(name, WireMessage(body[0].toUByte(), body.copyOfRange(1, body.size))) }.getOrNull() ?: return
        if (plain.size == 4 + 32 && String(plain.copyOfRange(0, 4), Charsets.US_ASCII) == "DCS1") {
            finishJoinerWithSecret(p, plain.copyOfRange(4, plain.size))
        }
    }

    private fun finishJoinerWithSecret(p: PairingInternal, secret: ByteArray) {
        val context = ctx()
        val name = p.peerName ?: return
        val theirId = p.peerIdentity ?: return
        runCatching { SignalCore.contactStore(context).upsertContact(name, theirId, p.bucket ?: ByteArray(32), true, "", secret) }
        p.finished = true
        p.link?.send(wireFrame(Wire.SAS_OK, ByteArray(0)))
        publishPairing()
    }

    /** 出示页进入。 */
    fun startPairingAsHost(token: ByteArray, bucket: ByteArray, bleId: ByteArray) {
        pairingObj = PairingInternal(asHost = true).apply {
            this.token = token; this.bucket = bucket; this.bleId = bleId
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

    /** 扫码页采集完成（UI 已 processBundle）。 */
    fun startPairingAsJoiner(peerName: String, peerIdentity: ByteArray, token: ByteArray, bucket: ByteArray, bleId: ByteArray) {
        pairingObj = PairingInternal(asHost = false).apply {
            this.peerName = peerName; this.peerIdentity = peerIdentity
            this.token = token; this.bucket = bucket; this.bleId = bleId
        }
        publishPairing()
    }

    fun stopPairingAsJoiner() {
        val p = pairingObj?.takeIf { !it.asHost && !it.finished } ?: return
        p.link?.closeLink()
        pairingObj = null
        publishPairing()
    }

    /** 本地点「一致」：立即本地 pin + 存联系人；host 生成并下发 S_i。 */
    fun confirmSas() {
        val p = pairingObj?.takeIf { !it.finished && !it.localConfirmed } ?: return
        val context = ctx()
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val name = p.peerName ?: return
        val theirId = p.peerIdentity ?: return
        runCatching { session.pinIdentity(name, theirId) }
        if (p.asHost) {
            val secret = ByteArray(32).also(security::nextBytes)
            runCatching { SignalCore.contactStore(context).upsertContact(name, theirId, p.bucket ?: ByteArray(32), true, "", secret) }
            val wm = runCatching { session.encrypt(name, "DCS1".toByteArray(Charsets.US_ASCII) + secret) }.getOrNull()
            wm?.let { p.link?.send(wireFrame(Wire.MSG, byteArrayOf(it.msgType.toByte()) + it.ciphertext)) }
            p.finished = true
        } else {
            runCatching { SignalCore.contactStore(context).upsertContact(name, theirId, p.bucket ?: ByteArray(32), true, "", ByteArray(32)) }
        }
        p.localConfirmed = true
        p.link?.send(wireFrame(Wire.SAS_OK, ByteArray(0)))
        publishPairing()
    }

    // ---------------- 业务帧 ----------------

    private fun dispatchIncoming(handle: LinkHandle, frame: ByteArray, peerNameHint: String?) {
        val body = frame.copyOfRange(Wire.HEADER_LEN, frame.size)
        if (body.isEmpty()) return
        val context = ctx()
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return
        val name = peerNameHint ?: return
        val plain = runCatching {
            session.decrypt(name, WireMessage(body[0].toUByte(), body.copyOfRange(1, body.size)))
        }.getOrNull() ?: return
        if (plain.size == 4 + 32 && String(plain.copyOfRange(0, 4), Charsets.US_ASCII) == "DCS1") return // 聊天链路拒收下发格式
        val text = String(plain, Charsets.UTF_8)
        runCatching { SignalCore.contactStore(context).appendMessage(name, false, text) }
        _incoming.tryEmit(Incoming(name, text))
    }

    /** 无在线链路返回 false（UI 显示「对方已离线」）。 */
    fun sendText(peerName: String, text: String): Boolean {
        val context = runCatching { ctx() }.getOrNull() ?: return false
        val contact = runCatching {
            SignalCore.contactStore(context).listContacts().firstOrNull { it.name == peerName }
        }.getOrNull() ?: return false
        val handle = synchronized(links) { links[hex(contact.identity)] } ?: return false
        val session = runCatching { SignalCore.session(context) }.getOrNull() ?: return false
        val wm = runCatching { session.encrypt(peerName, text.toByteArray()) }.getOrNull() ?: return false
        runCatching { SignalCore.contactStore(context).appendMessage(peerName, true, text) }
        handle.send(wireFrame(Wire.MSG, byteArrayOf(wm.msgType.toByte()) + wm.ciphertext))
        return true
    }

    fun isOnline(peerName: String): Boolean {
        val context = runCatching { ctx() }.getOrNull() ?: return false
        val contact = runCatching {
            SignalCore.contactStore(context).listContacts().firstOrNull { it.name == peerName }
        }.getOrNull() ?: return false
        return synchronized(links) { links.containsKey(hex(contact.identity)) }
    }
}
