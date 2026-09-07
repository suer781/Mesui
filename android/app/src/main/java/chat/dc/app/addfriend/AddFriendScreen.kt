package chat.dc.app.addfriend

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import chat.dc.app.R
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import kotlinx.coroutines.delay
import java.security.SecureRandom

/**
 * 添加好友子页（动态分帧二维码）：
 * - 我的码：数据帧与「当场新随机」的噪声帧交错播放（280ms/帧），每两帧画面都不同，
 *   单帧/单张截图不含完整信息
 * - 扫对方的码：相机连续采集，集齐全部数据帧且 ≥3 秒才完成 → 安全码核对 → 蓝牙协商
 */
@Composable
fun AddFriendScreen() {
    val security = remember { SecureRandom() }
    val myPayload = remember { AddFriendPayload.generate() }
    val sid = remember {
        ByteArray(4).also(security::nextBytes).joinToString("") { "%02x".format(it) }
    }
    val dataFrames = remember(myPayload, sid) { FrameCodec.split(myPayload, sid) }
    var frameIdx by remember { mutableIntStateOf(0) }

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

    val collector = remember { FrameCollector() }
    var collectorState by remember { mutableStateOf<FrameCollector.State?>(null) }
    val peerPayload = collectorState?.takeIf { it.complete }?.payload

    // 280ms/帧，QR 编码较重：离主线程编码，位图仅在换帧时重建
    var frameBmp by remember { mutableStateOf(QrCodec.encode(dataFrames[0], 480)) }
    LaunchedEffect(dataFrames) {
        while (true) {
            frameIdx += 1
            // 奇数帧放数据帧（顺序循环），偶数帧放一张当场新随机的噪声帧：
            // 每两帧画面都不同，肉眼是持续变动的图案；采集端靠 f=0 忽略噪声帧
            val f = if (frameIdx % 2 == 1) {
                dataFrames[(frameIdx / 2) % dataFrames.size]
            } else {
                FrameCodec.noiseFrame(sid, security)
            }
            frameBmp = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
                QrCodec.encode(f, 480)
            }
            delay(280)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.add_friend_title),
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 12.dp),
        )
        Text(stringResource(R.string.add_friend_show_hint), style = MaterialTheme.typography.bodyMedium)
        Image(
            bitmap = frameBmp.asImageBitmap(),
            contentDescription = stringResource(R.string.add_friend_qr_desc),
            modifier = Modifier
                .size(240.dp)
                .padding(vertical = 8.dp)
                .testTag("qr_image"),
        )

        Text(
            stringResource(R.string.add_friend_scan),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(top = 8.dp, bottom = 4.dp),
        )
        when {
            peerPayload != null -> Card(modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(stringResource(R.string.add_friend_verify), style = MaterialTheme.typography.titleSmall)
                    Text(
                        stringResource(R.string.add_friend_safety_code, peerPayload.fingerprintGroups()),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 8.dp),
                    )
                    Text(stringResource(R.string.add_friend_ble_pending), style = MaterialTheme.typography.bodySmall)
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
                        stringResource(
                            R.string.add_friend_progress,
                            st.collected,
                            st.total,
                            // 时间门槛满足后秒数封顶在阈值，不再无限上涨
                            st.elapsedMs.coerceAtMost(FrameCodec.MIN_COLLECT_MS) / 1000.0,
                        ),
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

        Text(
            stringResource(R.string.add_friend_pending_core),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 12.dp),
        )
    }
}
