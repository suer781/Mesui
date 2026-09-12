package chat.dc.app.addfriend

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import chat.dc.app.R
import chat.dc.app.ble.BleMesh
import chat.dc.app.core.SignalCore
import chat.dc.app.nearby.NearbyDiscovery
import chat.dc.app.ui.components.SubPageTopBar
import chat.dc.core.DcException
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import kotlinx.coroutines.delay
import java.security.SecureRandom

/**
 * 进入即请求「发现附近的设备」权限（未授权才弹）。
 * 出示侧后续用它做 BLE 广播、扫码侧用它做 BLE 扫描/连接（蓝牙传输阶段接入）。
 */
@Composable
private fun RequestNearbyPermissionOnEntry() {
    val context = LocalContext.current
    val discovery = remember { NearbyDiscovery(context) }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { }
    LaunchedEffect(Unit) {
        if (!discovery.hasPermissions()) {
            launcher.launch(discovery.requiredPermissions())
        }
    }
}

/** 本地加密库解密失败被自动重置后的一次性提示（session 访问时触发检测）。 */
@Composable
private fun IdentityResetNotice() {
    val shown = remember { SignalCore.consumeIdentityResetNotice() }
    if (shown) {
        Text(
            stringResource(R.string.identity_reset_notice),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 8.dp)
                .testTag("identity_reset_notice"),
        )
    }
}

/**
 * 加好友入口：先选角色。安全约束——「出示我的码」与「扫码添加」绝不同屏，
 * 要么别人扫你、要么你扫别人，二选一进入各自的独立页。
 */
@Composable
fun AddFriendRoleScreen(onBack: () -> Unit, onShow: () -> Unit, onScan: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        SubPageTopBar(title = stringResource(R.string.add_friend_title), onBack = onBack)
        Text(
            stringResource(R.string.add_friend_role_hint),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 12.dp),
        )
        RoleCard(
            tag = "role_show",
            icon = Icons.Filled.QrCode2,
            container = MaterialTheme.colorScheme.primary,
            title = stringResource(R.string.add_friend_role_show),
            desc = stringResource(R.string.add_friend_role_show_desc),
            onClick = onShow,
        )
        RoleCard(
            tag = "role_scan",
            icon = Icons.Filled.QrCodeScanner,
            container = MaterialTheme.colorScheme.tertiary,
            title = stringResource(R.string.add_friend_role_scan),
            desc = stringResource(R.string.add_friend_role_scan_desc),
            onClick = onScan,
        )
    }
}

@Composable
private fun RoleCard(
    tag: String,
    icon: ImageVector,
    container: Color,
    title: String,
    desc: String,
    onClick: () -> Unit,
) {
    Card(
        shape = MaterialTheme.shapes.large,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .clickable(onClick = onClick)
            .testTag(tag),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(container, RoundedCornerShape(12.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(icon, contentDescription = null, tint = Color.White)
            }
            Column(modifier = Modifier.padding(horizontal = 12.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(
                    desc,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

// 两阶段展示阶段号（见 [ShowMyCodeScreen]）：蓝牙搭线 → 身份交换；0 = 降级混合
private const val SHOW_PHASE_HANDSHAKE = 1
private const val SHOW_PHASE_EXCHANGE = 2
private const val SHOW_PHASE_FALLBACK = 0

/** 阶段 1（蓝牙搭线）最长停留：超过仍未建立蓝牙链路（对端不支持快连/一直没扫）
 *  即降级为旧式 f=1/f=2 交替序列（对方可走数据帧采集路径，安全码比对兜底）。
 *  须覆盖对端 3 秒防偷拍时长门槛 + BLE 连接/握手耗时，再留余量。 */
private const val HANDSHAKE_PHASE_MS = 8_000L

/**
 * 「别人扫我」：两阶段出示（蓝牙/身份信息防混暴露）——
 *  阶段 1（蓝牙搭线）：只滚蓝牙连接帧（f=2，少量重复），对方读到即经常驻
 *    BLE 扫描回连，本阶段不出示任何数据帧；
 *  阶段 2（身份交换）：蓝牙链路建立（本端 SAS 在手）后只滚数据帧 f=1 +
 *    奇偶帧 f=3 + 噪声帧 f=0——完整身份经加密蓝牙通道交换，f=2 与 f=1 绝不
 *    出现在同一滚动序列，长曝光单照至多捕到一种信息；
 *  降级：蓝牙迟迟未建立（对方不支持快连/超时）→ 旧式 f=1/f=2 交替序列
 *    （对方可走数据帧采集路径），安全码比对兜底。
 *  每轮展示开始重新生成帧内随机盐（nonce）：CRC 随之重算，同一张物理二维码
 *  每轮在字节层不同（防长曝光拼接）；sid 与数据内容不变。奇偶帧让扫描端丢
 *  1 帧可即时恢复。自适应帧率：间隔 = max(实测编码耗时, 150ms 最小视觉间隔)。
 *  载荷为真实密钥材料；进入即登记 host 配对（mesh 广播临时配对 id 等对方
 *  回连，收到 HS 后展示 SAS 供双方肉眼比对确认）。
 */
@Composable
fun ShowMyCodeScreen(onBack: () -> Unit) {
    RequestNearbyPermissionOnEntry()
    val context = LocalContext.current
    val security = remember { SecureRandom() }
    // Keystore/native 失败（厂商机型异常、测试环境）不能崩页面：降级为明确错误态
    val session = remember { runCatching { SignalCore.session(context) }.getOrNull() }
    val irohSnap by chat.dc.app.core.IrohNodeManager.state.collectAsState()
    // 红队盲审 P0-2 修复：payload 首次生成后冻结——不随 irohSnap.naddr 重生成。
    // naddr 迟到/变化不影响 QR 载荷（BLE 是传输管道，iroh 地址走加密通道交换）。
    // 随 naddr 重生成会导致 challenge/bleId 全换 → 已扫旧码的扫码端永久卡死。
    val myPayload = remember(session) {
        session?.let {
            fun random(n: Int) = ByteArray(n).also(security::nextBytes)
            AddFriendPayload(
                name = SignalCore.deviceName(context),
                identity = it.identityKey(),
                bundle = it.prekeyBundleWire(),
                bucket = random(32),
                token = random(48),
                ble = random(8),
                naddr = "",
            )
        }
    }
    // 蓝牙连接帧的当场挑战：与配对登记共用同一份（回连方须原样回传才获应答），
    // 载荷重生成（节点地址就绪等）时随之重生成
    val challenge = remember(myPayload) { ByteArray(16).also(security::nextBytes) }
    LaunchedEffect(myPayload, challenge) {
        myPayload?.let { BleMesh.startPairingAsHost(it, challenge) }
    }
    DisposableEffect(myPayload) {
        // 必须在 effect 体内捕获本次登记的载荷：onDispose 若活读 myPayload，
        // 载荷重生成（iroh 节点地址就绪等）时会读到新值非空 → 把「刚重新登记
        // 的 host 配对」当成页面退出撤销掉，出示端配对随之死锁
        val registered = myPayload
        onDispose { if (registered != null) BleMesh.stopPairingAsHost() }
    }
    val pairSnap by BleMesh.pairing.collectAsState()
    // 两阶段展示当前阶段（UI 提示用）：1 蓝牙搭线 → 2 身份交换；0 = 降级混合
    var showPhase by remember(myPayload) { mutableStateOf(SHOW_PHASE_HANDSHAKE) }
    var frameBmp by remember(myPayload) { mutableStateOf<Bitmap?>(null) }
    LaunchedEffect(myPayload, challenge) {
        val payload = myPayload ?: return@LaunchedEffect
        // 静态内容一次算好：数据段 / sid / 蓝牙搭线信息整场不变——每轮变化的
        // 只有帧包装（随机盐 + 随之重算的 CRC）
        val sid = FrameCodec.sidOf(payload)
        val segments = FrameCodec.segments(payload)
        val bleInfo = BleConnectInfo(
            sid = sid,
            name = payload.name,
            bleId = payload.ble,
            serviceUuid = chat.dc.app.ble.LinkUuids.SERVICE_UUID.toString(),
            challenge = challenge,
        )
        val pacer = AdaptiveFramePacer()
        val shownAt = System.currentTimeMillis()
        while (true) {
            // 两阶段防混暴露 + 降级：
            //  阶段 1（蓝牙搭线）：只滚 f=2（对方读到即回连，不出示任何数据帧）；
            //  阶段 2（身份交换）：本端握手完成（SAS 在手 = 蓝牙链路建立）后只滚
            //    f=1+f=3+f=0——完整身份经加密蓝牙通道交换，f=2 与 f=1 绝不同序列；
            //  降级：开场 HANDSHAKE_PHASE_MS 仍无链路（对方不支持快连/没扫）→
            //    旧式 f=1/f=2 交替（对方走数据帧采集路径，安全码比对兜底）。
            val snap = pairSnap
            showPhase = when {
                snap != null && snap.asHost && snap.sas != null -> SHOW_PHASE_EXCHANGE
                System.currentTimeMillis() - shownAt > HANDSHAKE_PHASE_MS -> SHOW_PHASE_FALLBACK
                else -> SHOW_PHASE_HANDSHAKE
            }
            // 每轮开始重新生成随机盐：帧内 nonce 变化 → CRC 随之重算 → 同一张
            // 物理二维码每轮在字节层不同（防长曝光拼接）；sid 与数据内容不变
            // （sid 绑定的是载荷文本，不是 nonce）。
            val nonce = FrameCodec.nonce(security)
            val pass = when (showPhase) {
                SHOW_PHASE_EXCHANGE -> FrameCodec.dataPass(sid, segments, bleInfo = null, nonce, security)
                SHOW_PHASE_FALLBACK -> FrameCodec.dataPass(sid, segments, bleInfo = bleInfo, nonce, security)
                else -> FrameCodec.handshakePass(bleInfo, nonce)
            }
            for (frame in pass) {
                // 实测单帧编码耗时（zxing 矩阵 + 位图写入，CPU 密集）喂给节拍器
                val encodeStart = System.nanoTime()
                frameBmp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                    QrCodec.encode(frame, 480)
                }
                // 自适应帧率：间隔 = max(实测编码耗时 EWMA, 最小视觉间隔 150ms)。
                // 全程循环多播，接收端缺帧靠奇偶帧恢复或下一轮补齐
                delay(pacer.afterEncode((System.nanoTime() - encodeStart) / 1_000_000))
            }
        }
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        SubPageTopBar(title = stringResource(R.string.add_friend_role_show), onBack = onBack)
        IdentityResetNotice()
        if (myPayload == null) {
            // 身份不可用（Keystore/native 异常）：明确降级提示，不出码也不登记配对
            Text(
                stringResource(R.string.identity_unavailable),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 24.dp).testTag("identity_unavailable"),
            )
            return@Column
        }
        Text(stringResource(R.string.add_friend_show_hint), style = MaterialTheme.typography.bodyMedium)
        frameBmp?.let { bmp ->
            Image(
                bitmap = bmp.asImageBitmap(),
                contentDescription = stringResource(R.string.add_friend_qr_desc),
                modifier = Modifier
                    .size(240.dp)
                    .padding(vertical = 8.dp)
                    .testTag("qr_image"),
            )
        }
        // 两阶段状态提示：蓝牙搭线 → 身份经加密通道交换 / 降级兼容模式
        Text(
            stringResource(
                when (showPhase) {
                    SHOW_PHASE_EXCHANGE -> R.string.add_friend_show_phase_exchange
                    SHOW_PHASE_FALLBACK -> R.string.add_friend_show_phase_fallback
                    else -> R.string.add_friend_show_phase_handshake
                },
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 8.dp).testTag("show_phase_hint"),
        )
        // 对方已连接并发来握手：进入 SAS 比对确认
        val snap = pairSnap
        if (snap != null && snap.asHost && snap.sas != null) {
            Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag("host_pairing_card")) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.add_friend_verify), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.add_friend_safety_code, snap.sas!!.six),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                    Text(
                        stringResource(R.string.add_friend_safety_code_full, snap.sas!!.full),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    if (!snap.localConfirmed) {
                        Button(
                            onClick = { BleMesh.confirmSas() },
                            modifier = Modifier.fillMaxWidth().testTag("host_sas_confirm"),
                        ) {
                            Text(stringResource(R.string.add_friend_sas_confirm))
                        }
                    } else {
                        Text(
                            if (snap.peerConfirmed) stringResource(R.string.add_friend_peer_confirmed)
                            else stringResource(R.string.add_friend_local_confirmed_wait),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (snap.finished) {
                        Text(
                            stringResource(R.string.add_friend_done),
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }
        }
    }
}

/**
 * 「我扫别人」：扫码即搭线——读到蓝牙连接帧（f=2）立即经常驻 BLE 扫描回连对方
 * （不等数据帧集齐），3 秒防偷拍时长门槛到期后经蓝牙上的 Signal 加密通道交换
 * 完整身份（token 只走密文），随后 SAS 比对（SP-3 原则不变）。
 * UI 只有取景器 + 提示文案；配对卡片在蓝牙帧到手/身份交换后出现。
 * 旧版对端（无 f=2 帧）仍走数据帧全集采集回退（原流程不变），缺失数据帧可由
 * f=3 奇偶帧 XOR 即时恢复（FEC，不必等循环重播）。
 */
@Composable
fun ScanToAddScreen(onBack: () -> Unit) {
    RequestNearbyPermissionOnEntry()
    val context = LocalContext.current
    var cameraGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val cameraPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { cameraGranted = it }

    // 会话延迟到「采集完成建会话」时才取：无相机权限的引导分支不触碰 Keystore/native
    val collector = remember { FrameCollector() }
    var collectorState by remember { mutableStateOf<FrameCollector.State?>(null) }
    // 蓝牙连接帧（f=2）搭线信息：先到先冻——读到即触发 BLE 回连（QR 快连）
    var bleInfo by remember { mutableStateOf<BleConnectInfo?>(null) }
    val pairSnap by BleMesh.pairing.collectAsState()

    // 旧版回退路径：数据帧集齐 + 3 秒仍可完成（无论是否扫到蓝牙帧）。
    // 红队盲审 P1-A 修复：移除 `ble == null` 门——快连失败时数据帧兜底仍可用，
    // 不再把扫码端锁死在「正在交换身份」死路径。
    val legacyPayload = collectorState?.takeIf { it.complete }?.payload
    var peerPayload by remember { mutableStateOf<AddFriendPayload?>(null) }
    LaunchedEffect(legacyPayload) {
        if (peerPayload == null && legacyPayload != null) peerPayload = legacyPayload
    }

    // 快连路径：登记搭线（BleMesh 常驻扫描命中对方配对广播即回连）。
    // established: 0 失败 / 1 成功 / 2 对方身份已变更（仅旧版回退路径使用）
    var established by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(peerPayload) {
        peerPayload?.let { p ->
            // PQXDH 建会话是重活：首取会话要 dlopen native + 开 SQLCipher，
            // processBundle 还要跑 Kyber-1024 + X25519——全部在主线程会把
            // 扫码 UI 整个冻住（用户报的「扫描端卡一下」）。挪 IO 线程，
            // 与快连路径（onJoinerQrOffer 在 BleMesh 协程里建会话）同一线程纪律
            established = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                val session = runCatching { SignalCore.session(context) }.getOrNull()
                when {
                    session == null -> 0
                    else -> try {
                        session.processBundle(p.name, p.bundle)
                        BleMesh.startPairingAsJoiner(p.name, p.identity, p.token, p.bucket, p.ble, p.naddr)
                        1
                    } catch (_: DcException.RemoteIdentityChanged) {
                        2
                    } catch (_: Exception) {
                        0
                    }
                }
            }
        }
    }
    DisposableEffect(peerPayload) {
        // 捕获 effect 本次登记的载荷（同上：onDispose 活读会把 key 变化时的
        // 新值误当成「页面退出时的存量」处理）
        val registered = peerPayload
        onDispose { if (registered != null) BleMesh.stopPairingAsJoiner() }
    }
    // 快连路径清理：页面退出即撤销（已完成的配对不动，链路保留为聊天链路）。
    // **必须捕获 effect 登记时的 bleInfo**：onDispose 里活读 state 读到的是
    // 当前值——读到 f=2 蓝牙帧当帧 bleInfo 由 null 变为非空，key 随之变化触发
    // 旧 effect 清理，活读会把「刚注册的 QR 快连搭线」当成存量撤销
    // （startQrDialAsJoiner 登记的 pairingObj 被立刻 stopPairingAsJoiner 清空，
    // 常驻扫描从此匹配不到任何配对广播，扫码端永远加不上人）；
    // 回调里 `if (bleInfo == null)` 的先到先冻守卫又阻止重新登记 → 死锁。
    DisposableEffect(bleInfo) {
        val dial = bleInfo
        onDispose { if (dial != null) BleMesh.stopPairingAsJoiner() }
    }
    // 真 SAS：绑定双方长期身份公钥 + 双方地址名，两端各算一端、结果一致
    // （快连路径的 SAS 由 BleMesh 在 QR_ID 到达时算好，随 pairSnap 下发）
    val sas = remember(peerPayload, established) {
        peerPayload?.takeIf { established == 1 }?.let { p ->
            runCatching {
                SignalCore.session(context).sasWith(SignalCore.deviceName(context), p.name, p.identity)
            }.getOrNull()
        }
    }
    // 快连卡片：蓝牙帧在手 + 扫码端配对对象在场（SAS/错误/交换中三态）
    val fastSnap = pairSnap?.takeIf { bleInfo != null && !it.asHost }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        IdentityResetNotice()
        SubPageTopBar(title = stringResource(R.string.add_friend_role_scan), onBack = onBack)
        Text(
            stringResource(R.string.add_friend_scan),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(bottom = 4.dp),
        )
        // 红队盲审 P0-1 修复：仅在有明确结果（SAS 或错误）时才用结果卡替换取景器；
        // 扫描进行中取景器保持可见（相机继续采集 + 帧率不停），状态文字在下方
        val fastDone = fastSnap?.let { it.sas != null || (it.dialError ?: 0) > 0 } == true
        when {
            fastDone -> Card(modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("pairing_card")) {
                Column(modifier = Modifier.padding(12.dp)) {
                    when (fastSnap.dialError) {
                        2 -> {
                            Text(
                                stringResource(R.string.add_friend_identity_changed),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            return@Card
                        }
                        1 -> {
                            Text(stringResource(R.string.add_friend_establish_failed), style = MaterialTheme.typography.bodySmall)
                            // 快连失败就地重试：清错误态并解除限频，常驻扫描
                            // 命中对方配对广播即重新回连，不必退出重扫
                            Button(
                                onClick = { BleMesh.retryQrDial() },
                                modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("qr_retry"),
                            ) {
                                Text(stringResource(R.string.add_friend_retry))
                            }
                            return@Card
                        }
                    }
                    Text(stringResource(R.string.add_friend_verify), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.add_friend_safety_code, fastSnap.sas!!.six),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                    Text(
                        stringResource(R.string.add_friend_safety_code_full, fastSnap.sas!!.full),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    if (!fastSnap.localConfirmed) {
                        Button(
                            onClick = { BleMesh.confirmSas() },
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("sas_confirm"),
                        ) {
                            Text(stringResource(R.string.add_friend_sas_confirm))
                        }
                    } else {
                        Text(
                            if (fastSnap.peerConfirmed) stringResource(R.string.add_friend_peer_confirmed)
                            else stringResource(R.string.add_friend_local_confirmed_wait),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (fastSnap.finished) {
                        Text(
                            stringResource(R.string.add_friend_done),
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }
            peerPayload != null -> Card(modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("pairing_card")) {
                Column(modifier = Modifier.padding(12.dp)) {
                    when (established) {
                        2 -> {
                            Text(
                                stringResource(R.string.add_friend_identity_changed),
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            return@Card
                        }
                        0 -> {
                            Text(stringResource(R.string.add_friend_establish_failed), style = MaterialTheme.typography.bodySmall)
                            return@Card
                        }
                    }
                    Text(stringResource(R.string.add_friend_verify), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.add_friend_safety_code, sas?.six ?: "……"),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                    Text(
                        stringResource(R.string.add_friend_safety_code_full, sas?.full ?: ""),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(bottom = 8.dp),
                    )
                    if (established == 1 && pairSnap?.waitingLink != false) {
                        Text(stringResource(R.string.add_friend_waiting_link), style = MaterialTheme.typography.bodySmall)
                    }
                    if (pairSnap?.localConfirmed != true) {
                        Button(
                            onClick = { BleMesh.confirmSas() },
                            enabled = established == 1 && sas != null,
                            modifier = Modifier.fillMaxWidth().padding(top = 4.dp).testTag("sas_confirm"),
                        ) {
                            Text(stringResource(R.string.add_friend_sas_confirm))
                        }
                    } else {
                        Text(
                            if (pairSnap?.peerConfirmed == true) stringResource(R.string.add_friend_peer_confirmed)
                            else stringResource(R.string.add_friend_local_confirmed_wait),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    if (pairSnap?.finished == true) {
                        Text(
                            stringResource(R.string.add_friend_done),
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }
            !cameraGranted -> Button(
                onClick = { cameraPermLauncher.launch(Manifest.permission.CAMERA) },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("grant_camera"),
            ) {
                Text(stringResource(R.string.add_friend_grant_camera))
            }
            else -> {
                val barcodeView = remember { DecoratedBarcodeView(context) }
                DisposableEffect(Unit) {
                    barcodeView.decodeContinuous(object : BarcodeCallback {
                        override fun barcodeResult(result: BarcodeResult) {
                            val now = System.currentTimeMillis()
                            // 蓝牙连接帧（f=2）：读到立即回调搭线（不等数据帧集齐）——
                            // 第二参 = 3 秒时长门槛到期时刻（防偷拍门槛不变，到点才
                            // 交换完整身份）。重复帧不重复回调。
                            collector.tryBluetoothConnect(result.text, now) { info, readyAtMs ->
                                if (bleInfo == null) {
                                    bleInfo = info
                                    BleMesh.startQrDialAsJoiner(info.name, info.bleId, info.challenge, readyAtMs)
                                }
                            }
                            collectorState = collector.onFrame(result.text, now)
                        }

                        override fun possibleResultPoints(points: MutableList<ResultPoint>?) = Unit
                    })
                    barcodeView.resume()
                    onDispose { barcodeView.pause() }
                }
                // 相机句柄跟随 Activity 生命周期：退后台即释放（DecoratedBarcodeView
                // 内部的相机线程/解码泵只有收到 pause 才停，Compose 不会替它做），
                // 回前台恢复解码（decodeContinuous 回调已注册，resume 即续上）
                val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
                DisposableEffect(lifecycleOwner) {
                    val observer = androidx.lifecycle.LifecycleEventObserver { _, event ->
                        when (event) {
                            androidx.lifecycle.Lifecycle.Event.ON_RESUME -> barcodeView.resume()
                            androidx.lifecycle.Lifecycle.Event.ON_PAUSE -> barcodeView.pause()
                            else -> Unit
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
                }
                LaunchedEffect(Unit) {
                    while (true) {
                        delay(200)
                        collectorState = collector.snapshot(System.currentTimeMillis())
                    }
                }
                AndroidView(
                    factory = { barcodeView },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(260.dp)
                        .testTag("scan_view"),
                )
                // 只提示，不做帧数进度：3 秒门槛到期（蓝牙帧已扫到）或数据帧
                // 集齐即自动完成，无须用户盯数字
                Text(
                    stringResource(R.string.add_friend_collect_hint),
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            }
        }
    }
}
