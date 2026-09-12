# 应用全貌与功能基线（审查锚点，2026-09-09）

> 本文档是所有代码审查的**基准线**：先读本文再报缺陷。凡本文标注为「设计决策/已知取舍」的行为，
> **不是 bug**；凡与本文描述矛盾的行为才是缺陷。文档由主理人基于全仓逐行阅读与 CI 实测汇编。

## 一、这个应用是什么

**无服务器 P2P 加密聊天**：每个用户即节点，无账号、无推送、无中心目录。
- 前端：Kotlin + Jetpack Compose（Android 8.0+）
- 核心：Rust（crates/core），经 UniFFI 暴露给 Kotlin（JNA 桥）
- 传输：双通道——BLE 近场（GATT 链路）+ iroh（QUIC 打洞，需网络）；**两者都是传输管道，消息内容永远是 Signal 会话密文**
- 当前阶段：端到端最小闭环（加好友→落库→近场/跨网收发），mesh 多跳中转**尚未实现**（设计见 docs/BLE-RELAY-DESIGN.md，勿把「没有中转」报成 bug）

## 二、模块地图（谁负责什么）

### Rust（crates/core/src）
| 模块 | 职责 | 关键事实 |
|---|---|---|
| identity.rs | Ed25519 长期身份 + 1024 位指纹 | 身份公钥**序列化后 33 字节**（1 字节类型前缀+32），全仓契约 = 33 |
| entropy.rs | BLAKE3 熵池 + OS CSPRNG | OS 为主源，传感器为增强 |
| envelope.rs | CBOR 信封 | msg_id 去重 + ttl_hops（为中转预留）；sender 按路径分流（联系人=长期钥/陌生人=化名节点钥）；**无签名字段 = 已知缺口 A0** |
| mailbox.rs | 信箱桶门禁 SP-1 | 256 位随机桶地址；写桶须 keyed-BLAKE3 MAC；±5min 重放窗 |
| relay.rs | 陌生人中继票 SP-7 | 挑战哈希+nonce 缓存+TTL≤2h；默认关闭 |
| governor.rs | 转发份额治理 | **15% 顶、电量 40→5 smoothstep 到 3% 地板、每发送者 6 条/分保底、双曲线取 min、NaN fail-closed——全部已实现，勿报缺失** |
| handshake.rs | Signal 会话（PQXDH+Double Ratchet+SAS+TOFU） | vendored libsignal eb7864c；`Device::generate`=内存库，`open`=SQLCipher 持久 |
| signal_store.rs | SQLCipher store | strict 模式必须给 key |
| contacts.rs | 联系人/消息落库 | **identity 契约正在 32/33 间打架 = 已知 P0-2** |
| node.rs | iroh endpoint + NodeCallback | 无并发流上限 = 已知 P1-3 |
| queue.rs | 加密队列+重试调度 | 已实现但**未接入 Android 发送路径**（已知待办，勿重复报） |
| ffi.rs | UniFFI 导出 | SignalSession/ContactStore/CoreInfo/first_message_mac 等；`smoke_test_all_modules` 是防链接器裁剪的探针，**不是功能** |

### Kotlin（android/app/src/main/java/chat/dc/app）
| 模块 | 职责 | 关键事实 |
|---|---|---|
| ble/BleMesh.kt | BLE mesh 编排常驻单例 | 广播=布隆过滤器；占空比扫描；命中回连；HMAC 挑战；配对状态机；聊天收发（BLE 优先→iroh 兜底） |
| friendlink/FriendLink.kt | 匿名发现 | HKDF(好友共享秘密 S_i)→每日钥→10 分钟槽位 4 字节 ID→布隆+随机填充至固定 set-bit 目标 |
| core/SignalCore.kt | 密钥管理单例 | Keystore AES-GCM 包裹 SQLCipher 库密钥；deviceName=ANDROID_ID（已知 P2，待改随机名） |
| core/IrohNodeManager | iroh 生命周期 | 前台服务宿主 |
| service/NodeService.kt | 前台服务 | START_STICKY；通知只显示应用名（**设计如此，隐私**） |
| addfriend/* | 扫码加好友 | QR 动态分帧（150ms/帧，数据:噪声=3:1，纠错 L）；扫满+3s 门槛→PQXDH→SAS |
| ui/* | 四页 + 子页 | 空态优先，无演示数据（**设计如此**） |

## 三、关键流程（实际调用链）

1. **加好友（扫码方=joiner）**：扫动态码集齐帧 → `AddFriendPayload.parse` → `session.processBundle`（PQXDH）→ `sasWith` 显示安全码 → **双方各自点「一致」** → host 经 BLE 配对链路下发 DCS1（含 S_i 共享秘密）→ joiner `upsertContact` → 双方 `upsert_contact` 落库（identity=33 字节）
2. **近距离重连**：FriendLink 槽位 ID 命中布隆 → 回连 GATT → AUTH_CHA（nonce+identity 33B）→ HMAC 挑战应答 → 建立 links[identity]
3. **发消息**：`sendText` → `session.encrypt`（Double Ratchet）→ BLE 在线直发 `Wire.MSG`；否则 iroh `send(naddr)` → **应用层 ack/队列补投未接**（已知 P1）
4. **收消息**：`decryptAndStore`（统一入口：BLE 帧/iroh 载荷同路）→ 落库 → UI 流刷新
5. **持久化**：SQLCipher（filesDir/dc-signal.db），库密钥由 Keystore AES-GCM 包裹存 dc.dbkey

## 四、设计决策红线（这些不是 bug，勿报勿改）

1. **身份公钥 = 33 字节**（含 libsignal 类型前缀）——所有路径必须以 33 为准；32 字节才是 bug
2. 布隆广播**故意**填充到固定 set-bit 目标（隐藏好友数）；槽位轮换故意 10 分钟（匿名性权衡，文档已接受跟随者风险）
3. 广播**不含**设备名（`setIncludeDeviceName(false)`）；前台通知**不显示**消息内容
4. `smoke_test_all_modules`、`build_probe` 是链接器探针
5. TOFU：首次自动信任 + 应用层 `verified` 闸门（换钥告警丢失是已知 P1-1，会修；但「TOFU 自动信任」本身是设计）
6. UI 空态优先、不放演示数据
7. 陌生人中继/多跳中转**未实现**是已知状态（有设计文档），不算缺陷
8. 队列补投未接 = 已知待办，报「无 ack」只在接受任务时引用编号，不重复展开

## 五、已知问题台账（勿重复报，引用编号即可）

P0-1 BleMesh AUTH 33/32（BleMesh.kt:319-321）｜P0-2 contacts.rs upsert 拒 33（contacts.rs:117）｜
P1-1 TOFU pin 静默覆盖（signal_store.rs:173-197）｜P1-3 node.rs 无流上限（node.rs:77-105）｜
P1-4 配对链路收不了 MSG（BleMesh.kt:439,588）｜P1-5 Keystore 失败静默清库（SignalCore.kt:92-97）｜
P1-6 joiner DCS1 自动落库（BleMesh.kt:494-499）｜P2-1 非恒定时间比较（:384,396）｜P2-2 AUTH_B 死代码（:390）｜
P2-3 ANDROID_ID 设备名（SignalCore.kt:54）｜P2-5/6 配对竞态｜P2-7 4KB 静默失败（:606）｜P2-8 无 ack（:613）。
完整台账：docs/INDUSTRY-COMPARISON-2026-09-09.md 第 3 节。

## 六、审查纪律

- 逐模块、逐文件排查；每条发现必须带 文件:行号 + 触发场景
- 报缺陷前先对照第二节「关键事实」与第四节「红线」：**设计决策 ≠ 缺陷**
- 与台账重复的引用编号，不新开条目
- 存疑就标「存疑」，不凑数
