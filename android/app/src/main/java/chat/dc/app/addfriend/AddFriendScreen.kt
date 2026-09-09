package chat.dc.app.addfriend

import android.Manifest
import android.content.pm.PackageManager
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
import androidx.compose.material3.LinearProgressIndicator
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
fun AddFriendRoleScreen(onShow: () -> Unit, onScan: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text(
            stringResource(R.string.add_friend_title),
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 4.dp),
        )
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

/**
 * 「别人扫我」：只显示我的动态码。数据帧与当场新随机的噪声帧交错播放（280ms/帧），
 * 每两帧画面都不同，单帧/单张截图不含完整信息。
 * 载荷为真实密钥材料；进入即登记 host 配对（mesh 广播临时配对 id 等对方回连，
 * 收到 HS 后展示 SAS 供双方肉眼比对确认）。
 */
@Composable
fun ShowMyCodeScreen() {
    RequestNearbyPermissionOnEntry()
    val context = LocalContext.current
    val security = remember { SecureRandom() }
    // Keystore/native 失败（厂商机型异常、测试环境）不能崩页面：降级为明确错误态
    val session = remember { runCatching { SignalCore.session(context) }.getOrNull() }
    val irohSnap by chat.dc.app.core.IrohNodeManager.state.collectAsState()
    val myPayload = remember(session, irohSnap.naddr) {
        session?.let {
            fun random(n: Int) = ByteArray(n).also(security::nextBytes)
            AddFriendPayload(
                name = SignalCore.deviceName(context),
                identity = it.identityKey(),
                bundle = it.prekeyBundleWire(),
                bucket = random(32),
                token = random(48),
                ble = random(8),
                naddr = irohSnap.naddr,
            )
        }
    }
    LaunchedEffect(myPayload) {
        myPayload?.let { BleMesh.startPairingAsHost(it.token, it.bucket, it.ble) }
    }
    DisposableEffect(myPayload) {
        onDispose { if (myPayload != null) BleMesh.stopPairingAsHost() }
    }
    val sid = remember {
        ByteArray(4).also(security::nextBytes).joinToString("") { "%02x".format(it) }
    }
    val dataFrames = remember(myPayload, sid) { myPayload?.let { FrameCodec.split(it, sid) } }
    var frameBmp by remember(myPayload) {
        mutableStateOf(dataFrames?.firstOrNull()?.let { QrCodec.encode(it, 480) })
    }
    LaunchedEffect(dataFrames) {
        val frames = dataFrames ?: return@LaunchedEffect
        var dataSeq = 0
        while (true) {
            // 每 4 个数据帧才插 1 个噪声帧：噪声只为防单帧截屏，1:1 会把
            // 有效帧率砍半——高密度帧解码本来就慢，跳一帧就「总差最后一帧」
            val showNoise = dataSeq > 0 && dataSeq % 4 == 0
            val f = if (showNoise) {
                FrameCodec.noiseFrame(sid, security)
            } else {
                frames[dataSeq % frames.size].also { dataSeq += 1 }
            }
            frameBmp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                QrCodec.encode(f, 480)
            }
            // 150ms/帧：全部数据帧 ~2.2s 一轮，配合扫描端 3 秒时长门槛，
            // 正常情况 3-4 秒内必能集齐
            delay(150)
        }
    }
    val pairSnap by BleMesh.pairing.collectAsState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        IdentityResetNotice()
        Text(
            stringResource(R.string.add_friend_role_show),
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 8.dp),
        )
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
 * 「我扫别人」：只开相机采集对方动态码，集齐全部数据帧且 ≥3 秒才完成。
 * 完成后：解析出的真实 bundle 立即跑 PQXDH 建会话（内存 store），
 * 并计算真 SAS（绑定双方长期身份公钥）供用户带外比对；
 * token-MAC 首条消息与 BLE 传输在阶段 3 接入。
 */
@Composable
fun ScanToAddScreen() {
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
    val peerPayload = collectorState?.takeIf { it.complete }?.payload

    // 采集完成 → PQXDH 建会话 + 登记 joiner 配对（mesh 负责扫到配对 id 后
    // 回连、发 HS、S_i 接收）。established: 0 失败 / 1 成功 / 2 对方身份已变更
    var established by remember { mutableStateOf<Int?>(null) }
    LaunchedEffect(peerPayload) {
        peerPayload?.let { p ->
            val session = runCatching { SignalCore.session(context) }.getOrNull()
            established = when {
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
    DisposableEffect(peerPayload) {
        onDispose { if (peerPayload != null) BleMesh.stopPairingAsJoiner() }
    }
    // 真 SAS：绑定双方长期身份公钥 + 双方地址名，两端各算一端、结果一致
    val sas = remember(peerPayload, established) {
        peerPayload?.takeIf { established == 1 }?.let { p ->
            runCatching {
                SignalCore.session(context).sasWith(SignalCore.deviceName(context), p.name, p.identity)
            }.getOrNull()
        }
    }
    val pairSnap by BleMesh.pairing.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        IdentityResetNotice()
        Text(
            stringResource(R.string.add_friend_role_scan),
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 8.dp),
        )
        Text(
            stringResource(R.string.add_friend_scan),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(bottom = 4.dp),
        )
        when {
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
                            collectorState = collector.onFrame(result.text, System.currentTimeMillis())
                        }

                        override fun possibleResultPoints(points: MutableList<ResultPoint>?) = Unit
                    })
                    barcodeView.resume()
                    onDispose { barcodeView.pause() }
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
                val st = collectorState
                if (st != null && st.total > 0) {
                    LinearProgressIndicator(
                        progress = {
                            val framesPart = if (st.total == 0) 0f else st.collected.toFloat() / st.total
                            val timePart = (st.elapsedMs.toFloat() / FrameCodec.MIN_COLLECT_MS).coerceAtMost(1f)
                            (framesPart * 0.6f + timePart * 0.4f).coerceIn(0f, 1f)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 8.dp)
                            .testTag("collect_progress"),
                    )
                    Text(
                        if (st.collected >= st.total) {
                            // 全部帧已到手、只剩 3 秒防截屏时长门槛：明确告知
                            // 用户不是「总差一帧」，避免误解为识别失败
                            stringResource(R.string.add_friend_collected_waiting)
                        } else {
                            stringResource(
                                R.string.add_friend_progress,
                                st.collected,
                                st.total,
                                // 时间门槛满足后秒数封顶在阈值，不再无限上涨
                                st.elapsedMs.coerceAtMost(FrameCodec.MIN_COLLECT_MS) / 1000.0,
                            )
                        },
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else {
                    Text(
                        stringResource(R.string.add_friend_collect_hint),
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                }
            }
        }
    }
}
