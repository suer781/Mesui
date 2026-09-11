# 应用全貌与功能基线（审查锚点，2026-09-11 按代码现状修订）

> 本文档是所有代码审查的**基准线**：先读本文再报缺陷。凡本文标注为「设计决策/已知取舍」的行为，
> **不是 bug**；凡与本文描述矛盾的行为才是缺陷。文档由主理人基于全仓逐行阅读与 CI 实测汇编。

## 一、这个应用是什么

**无服务器 P2P 加密聊天**：每个用户即节点，无账号、无推送、无中心目录。
- 前端：Kotlin + Jetpack Compose（minSdk 26 / Android 8.0+）
- 核心：Rust（crates/core），经 UniFFI 暴露给 Kotlin（JNA 桥；CI 生成 dc_core.kt）
- 传输：双通道——BLE 近场（GATT 链路）+ iroh（QUIC 直连/自建中继，需网络）；**两者都是传输管道，消息内容永远是 Signal 会话密文**
- 当前阶段：端到端闭环（动态分帧二维码/蓝牙快连加好友→SAS→落库→近场/跨网收发）；mesh 多跳中转**尚未实现**（设计见 docs/BLE-RELAY-DESIGN.md 与 SP-9，勿把「没有中转」报成 bug）；离线信箱补投/联系人间中继也未实现

## 二、模块地图（谁负责什么）

### Rust（crates/core/src）
| 模块 | 职责 | 关键事实 |
|---|---|---|
| identity.rs | Ed25519 长期身份 + 1024 位指纹 | 身份公钥**序列化后 33 字节**（1 字节类型前缀+32），全仓契约 = 33 |
| entropy.rs | BLAKE3 熵池 + OS CSPRNG | OS 为主源，传感器为增强 |
| envelope.rs | CBOR 信封 | msg_id 去重 + ttl_hops（为中转预留）；sender 按路径分流（联系人=长期钥/陌生人=化名节点钥）；单播/群播互斥校验；**无签名字段 = 已知缺口 A0** |
| nodekey.rs | 节点密钥轮换公告 SP-2 | 长期钥签名 + 单调 serial + 7 天过渡窗 + 30 天有效期上限 + 密钥环持久化接口；**未接入传输** |
| mailbox.rs | 信箱桶门禁 SP-1 | 256 位随机桶地址；写桶须 keyed-BLAKE3 MAC（绑定信封全部字段）；±5min 重放窗 + msg_id 过期台账（满 fail-closed） |
| relay.rs | 陌生人中继票 SP-7 | 挑战哈希+nonce 缓存（逐过期/旧挑战逐出、活条目永不驱逐）+TTL≤2h；默认关闭 |
| governor.rs | 转发份额治理 | **15% 顶、电量 40→5 smoothstep 到 3% 地板、每发送者 6 条/分保底、双曲线取 min、NaN fail-closed——全部已实现，勿报缺失** |
| clock.rs | 软件内部独立时钟 SP-8 | 网络双源交叉验证(≤5s) + 蓝牙 3 人法定人数 + 采纳限幅±2min/冷却10min + 高水位防回拨 + 仅信任已验证联系人 |
| adaptive.rs | 负载三档引擎 | 升档即时可跳级、降档逐级防抖、锁档、NaN fail-closed；只产出档位，传输策略未接 |
| handshake.rs | Signal 会话（PQXDH+Double Ratchet+SAS+TOFU） | vendored libsignal eb7864c；`Device::generate`=内存库，`open`=SQLCipher 持久；TOFU 拒绝单独成类（IdentityChanged） |
| signal_store.rs | SQLCipher store | strict 模式必须给 key；`save_identity` 拒绝异钥覆盖（P1-1 已修） |
| contacts.rs | 联系人/消息落库 | identity 接受 33 字节（32 保留兼容），bucket/link_secret 固定 32；node_id/node_naddr 为跨网快照列（旧库自动迁移） |
| node.rs | iroh endpoint + NodeSink 回调 | presets::Minimal（零 n0 依赖）；一消息一流 + 1 字节 ACK；dc://node 快照编解码；无并发流上限 = 已知 P1-3 |
| queue.rs | 加密队列+重试调度 | 已实现但**未接入 Android 发送路径**（已知待办，勿重复报） |
| retry.rs | 指数退避+全抖动（纯计算） | 驱动方为通道状态机（未接） |
| settings.rs | serde JSON 设置模型 | 含 strict_crypto（默认开）、NodeServiceCfg.scope 三档等；UI 仅部分接入 |
| ffi.rs | UniFFI 导出 | SignalSession/ContactStore/IrohNode/NodeCallback/DcError(RemoteIdentityChanged 单独成类)/first_message_mac 等；`smoke_test_all_modules` 是防链接器裁剪的探针，**不是功能** |

### Kotlin（android/app/src/main/java/chat/dc/app）
| 模块 | 职责 | 关键事实 |
|---|---|---|
| ble/BleMesh.kt | BLE mesh 编排常驻单例 | 广播=布隆过滤器；占空比扫描；命中回连；HMAC 挑战；配对状态机（含 QR 快连 QR_DIAL/QR_OFFER/QR_REQ/QR_ID）；聊天收发（BLE 优先→iroh 兜底）；`deliverRemote` 为 iroh 入站统一入口 |
| ble/BleChannel.kt | Wire 帧协议 + GATT 链路 | 帧 = [type:1][bodyLen:2 BE]，body ≤4KB（超限 require 快速失败）；BleClientLink/BleServer、MTU 517、分片泵 |
| friendlink/FriendLink.kt | 匿名发现 | HKDF(好友共享秘密 S_i)→每日钥→10 分钟槽位 4 字节 ID→布隆+随机填充至固定 set-bit 目标 |
| core/SignalCore.kt | 密钥管理单例 | Keystore AES-GCM 包裹 SQLCipher 库密钥（解不开=重置+一次性 UI 提示，非静默）；deviceName=ANDROID_ID（已知 P2-3，待改随机名） |
| core/IrohNodeManager.kt | iroh 生命周期 | 节点种子 Keystore 包裹落盘 dc.nodekey；启动失败 5s/15s/45s 退避自愈 + 世代守卫；nodeId→联系人名缓存；中继 URL 存 SharedPreferences 可改（保存即重启） |
| service/NodeService.kt | 前台服务 | START_STICKY；通知只显示应用名（**设计如此，隐私**）；先合规占位再后台初始化（Android 12+ 5 秒死线）；onDestroy 步骤边界取消 |
| addfriend/* | 扫码加好友 | QR 动态分帧（自适应帧率，下限 150ms/帧；每 4 数据帧 1 噪声帧，每 2 数据帧 1 蓝牙帧；纠错 L）+ f=2 蓝牙快连；扫满/快连 +3s 门槛→PQXDH→SAS |
| ui/* | 四页 + 子页 | 全部接真实 SQLCipher 数据；无演示数据（**设计如此**） |

## 三、关键流程（实际调用链）

1. **加好友 · 蓝牙快连路径（默认）**：扫码端读到 f=2 蓝牙搭线帧 → `BleMesh.startQrDialAsJoiner`
   登记搭线 → 常驻扫描命中对方配对广播回连 → `QR_DIAL`（原样回传挑战）→ 出示端
   `QR_OFFER`（PreKeyBundle 明文）→ 扫码端 PQXDH `processBundle` → 到 3 秒门槛后
   `QR_REQ`（Signal 密文标记 dc-idreq）→ 出示端 `QR_ID` 密文下发完整 dc://add 载荷
   （**token 只走密文**）→ 绑定校验（同名同 bundle）→ token-MAC 握手（HS 帧）→
   `sasWith` 显示安全码 → **双方各自点「一致」** → host 经配对链路下发 DCS1（含 S_i
   共享秘密）→ 双方 `upsert_contact` 落库（identity=33 字节，含 node_naddr 快照）
2. **加好友 · 数据帧回退路径（旧版对端）**：扫齐全部数据帧 + 3 秒 → 内容门
   （H(重组文本)==sid）→ `AddFriendPayload.parse` → 同上自 processBundle 起
3. **近距离重连**：FriendLink 槽位 ID 命中布隆 → 回连 GATT → AUTH_CAND/AUTH_CHA
   （nonce+identity 33B）→ HMAC 挑战应答 → 建立 links[identity]
4. **发消息**：`sendText` → `session.encrypt`（Double Ratchet）→ BLE 在线直发 `Wire.MSG`；
   否则 iroh `send(naddr)`（阻塞至对端应用层 1 字节 ACK）→ 两路都不通返回 false
   （UI 提示「对方不在线」），不落库（**应用层 ack/队列补投未接 BLE 路径**，已知 P1）
5. **收消息**：`decryptAndStore`（统一入口：BLE 帧与 iroh `deliverRemote` 同路）→ 落库 → UI 流刷新
6. **持久化**：SQLCipher（filesDir/dc-signal.db），库密钥由 Keystore AES-GCM 包裹存 dc.dbkey；
   iroh 节点种子同模式存 dc.nodekey

## 四、设计决策红线（这些不是 bug，勿报勿改）

1. **身份公钥 = 33 字节**（含 libsignal 类型前缀）——所有路径必须以 33 为准；32 字节才是 bug
2. 布隆广播**故意**填充到固定 set-bit 目标（隐藏好友数）；槽位轮换故意 10 分钟（匿名性权衡，文档已接受跟随者风险）
3. 广播**不含**设备名（`setIncludeDeviceName(false)`）；前台通知**不显示**消息内容
4. `smoke_test_all_modules`、`build_probe` 是链接器探针
5. TOFU：首次自动信任 + 应用层 `verified` 闸门（异钥覆盖已被 signal_store 拒绝，
   P1-1 已修；但「TOFU 自动信任」本身是设计）
6. UI 空态优先、不放演示数据
7. 陌生人中继/多跳中转**未实现**是已知状态（有设计文档），不算缺陷
8. 队列补投未接 = 已知待办；「无 ack」仅指 **BLE 路径**（iroh 路径已有 1 字节应用层
   ACK 并在 send 返回前确认）——报缺陷只在接受任务时引用编号，不重复展开

## 五、已知问题台账（2026-09-11 核对；勿重复报，引用编号即可）

**已修（回归测试/提交在树，勿再报）**：
P0-1 BLE AUTH 32/33 契约统一（修于 befb1d8，BleMesh IDENTITY_LEN=33）｜
P0-2 contacts.rs upsert 拒 33（修于 f06df7b，现 33 放行/32 兼容）｜
P1-1 TOFU pin 静默换钥（修于 7a195a3，save_identity 拒绝异钥覆盖）｜
盲区审计 A 聊天页滚动打断（c58d466）｜B iroh 回调线程阻塞 reactor（c58d466）｜
C 每消息全表反查联系人（c58d466，nodeIdIndex 缓存）｜D 配对早于 onReady 致 naddr
永久空（d07a458，sendJoinerHandshake 等快照最多 4s）｜E 本人二维码入口误绑（d07a458，
直达 add_friend_show）｜P2-7 4KB 静默失败（wireFrame 改 require 快速失败；QR_OFFER
超限主动放弃快连走数据帧回退）。

**仍开放**：
P1-3 node.rs 无并发流上限｜P1-4 配对链路收不了 MSG（聊天消息到达经 AUTH/配对建立
的链路时被丢弃）｜P1-5（部分）Keystore 失败清库现有一次性提示，但自动重置本身仍是
兜底行为｜P1-6 joiner 收 DCS1 即自动落库 verified=true（早于本端 SAS 确认）｜
P2-1 AUTH HMAC 比较非常量时间（FriendLink.hmac 后 contentEquals）｜
P2-2 AUTH_B 反向认证死代码（initiator 不处理 AUTH_B_CHA）｜P2-3 ANDROID_ID 设备名｜
P2-5/6 配对竞态｜P2-8 BLE 路径无 ack。
完整台账与行号：docs/INDUSTRY-COMPARISON-2026-09-09.md 第 3 节（其中行号基于
2026-09-09 代码，此后已有漂移，以编号检索为准）。

## 六、审查纪律

- 逐模块、逐文件排查；每条发现必须带 文件:行号 + 触发场景
- 报缺陷前先对照第二节「关键事实」与第四节「红线」：**设计决策 ≠ 缺陷**
- 与台账重复的引用编号，不新开条目
- 存疑就标「存疑」，不凑数
