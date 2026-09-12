# Mesui 实现状态与待办 Wiki

本文件记录去中心化聊天项目 Mesui 的当前实现状态、已定稿的加密握手设计、剩余待办、已知缺陷、环境与验证约束、关键决策。仅陈述事实与工程判断，不含评价性措辞。

最后更新：2026-09-11（GLM-Zcode 分支，对应提交 `e9cd671` 一线；本文按全仓代码逐文件核对改写）

---

## 1. 项目概况

- 定位：主打安全、去中心化、**不依赖中心服务器/网络**的端到端加密聊天。人人即节点，近距离靠蓝牙（BLE GATT 1对1 直连）、远距离靠 P2P（iroh QUIC 直连/可选自建中继）；mesh 多跳中转与人群转发仅有协议原语，未接传输。
- 技术栈：Rust 核心（crate `dc-core`，edition 2024，AGPL-3.0-or-later）+ Android Kotlin/Compose 壳（minSdk 26）。
- 密码学原则：所有密码学原语来自第三方库（ed25519-dalek、blake3、getrandom、vendored libsignal-protocol、SQLCipher/rusqlite、iroh）；本仓只做编排，不自研原语。
- 仓库：`github.com/suer781/Mesui`，默认分支 `main`；当前开发分支 `GLM-Zcode`。

---

## 2. 代码结构

### 2.1 Rust 核心 `crates/core/src`

| 模块 | 职责 | 门控 feature |
|---|---|---|
| `identity.rs` | Ed25519 长期身份密钥；域分隔 BLAKE3-XOF 1024 位指纹 | 常开 |
| `entropy.rs` | 熵源：内核 CSPRNG 为主 + 传感器噪声 BLAKE3 搅拌增强 | 常开 |
| `envelope.rs` | CBOR 信封 + 4 字节大端长度分帧（4MiB 上限）+ FIFO 去重 + zstd 压缩；单播/群播互斥与群信封 ttl 校验；sender 语义分流（联系人=长期钥/陌生人=化名节点钥） | 常开（压缩需 `compress`） |
| `nodekey.rs` | 节点密钥轮换公告：长期钥签名、单调 serial、7 天过渡窗、30 天有效期上限、按 serial 取钥匙、单身份公告数上限、state()/restore() 持久化接口（未接传输） | 常开 |
| `mailbox.rs` | 信箱桶门禁：256 位随机桶地址、keyed-BLAKE3 MAC（绑定信封全部字段）、±5min 重放窗、msg_id 过期台账（满 fail-closed）、verify_inbound 强制「先验签后去重」顺序 | 常开 |
| `queue.rs` | SQLCipher 整库加密的待发队列 + 收件去重；重试调度；u64→i64 钳制 | `db` |
| `maildrop.rs` | 信箱节点服务（SP-1 v9.2）：MailboxManager 按 SP-1 顺序执行「MAC→窗口→nonce 去重→限速→入库」；per-pair 分区 NonceCache + per-pair 限速（≤30 写/分/对）；pair_key 派生 | `db` |
| `delivery.rs` | DeliveryManager：把 queue.rs 接到实际发送回调（SendFn）；tick 驱动重试/退避（catch_unwind 包裹回调）；cleanup（prune_seen 7 天 + prune_dead 30 天）；revive 复活死信 | `db` |
| `contacts.rs` | 联系人 + 聊天记录落库（identity 33 字节契约、link_secret、node_id/node_naddr 跨网快照列）；与 Signal store 同库双连接（busy_timeout 串行） | `db` |
| `relay.rs` | 陌生人人群转发票：握手挑战绑定 + 指纹缓存（活条目永不驱逐、满 fail-closed）+ TTL ≤2h 强制 | 常开 |
| `adaptive.rs` | 负载三档引擎（轻/中/重）：升档即时可跳级、降档逐级防抖；NaN 指标 fail-closed | 常开 |
| `governor.rs` | 陌生人中继资源治理：令牌桶；电量/负载 smoothstep 连续曲线降份额；保底 6 条/分/发送者 | 常开 |
| `clock.rs` | 内部单调时钟：网络双源交叉验证（≤5s）+ 蓝牙 3 人法定人数共识 + 高水位防回拨 + 采纳限幅（±2min/次、10min 冷却）+ 仅信任已验证联系人 | 常开 |
| `retry.rs` | 指数退避 + 全抖动（纯计算） | 常开 |
| `settings.rs` | serde JSON 设置持久化（strict_crypto、scope 三档等） | 常开 |
| `handshake.rs` | **Signal 会话层**：PQXDH 初始协商 + Double Ratchet + SAS + TOFU + bundle 上线格式；后端统一 SQLCipher（generate=内存库，open=文件库） | `signal` |
| `signal_store.rs` | libsignal 五 store trait 的 SQLCipher 实现；save_identity 拒绝异钥覆盖；预密钥单调 id | `signal` |
| `node.rs` | iroh 远程节点（QUIC 端点）：presets::Minimal（零 n0 依赖）、一消息一流 + 1 字节应用层 ACK、`dc://node?v=1` 地址快照编解码 | `iroh-net` |
| `ffi.rs` | UniFFI 导出层：`CoreInfo`、`SignalSession`、`ContactStore`、`IrohNode`+`NodeCallback`、`WireMessage`/`SasCode`/`Contact`/`ChatMessage`、`DcError`（RemoteIdentityChanged 单独成类）、`smoke_test_all_modules`（链接器探针，非功能） | `ffi` |
| `signal_backend` | 构建探针（证明 libsignal 可链接） | `signal` |

Feature：`default = ["db","compress","signal","iroh-net"]`；`ffi` 与 `vendored-openssl` 非默认。`signal` 追加依赖 `rand 0.9`（须与 libsignal 同版本，否则 `Rng/CryptoRng` 非同一 trait）+ `futures 0.3`（`block_on` 驱动 libsignal 的 `?Send` async trait）+ `async-trait`。`db` 门控 queue 与 contacts。另有薄壳 bin `src/bin/uniffi-bindgen.rs`（cli feature 转发到 uniffi-bindgen main）。

集成测试在 `crates/core/tests/`（redteam / security_bruteforce / iroh_pair，进程内确定性测试），示例在 `crates/core/examples/e2e_demo.rs`；CI 现已执行 tests/ 全量（见 §3）。

### 2.2 Android 壳 `android/app/src/main/java/chat/dc/app`

| 文件 | 职责 | 状态 |
|---|---|---|
| `MainActivity.kt` | Compose 底部三 tab（消息/联系人/我的）+ 导航图；启动前台 `NodeService`（通知权限回调里启动，拒绝也照跑） | 导航含 `add_friend`(选角色)/`add_friend_show`/`add_friend_scan`/`nearby`/`chat/{id}`；资料卡 QR 直达 `add_friend_show` |
| `service/NodeService.kt` | 前台常驻服务（START_STICKY，connectedDevice 类型） | 真实宿主：初始化 Signal 会话（先合规占位再后台初始化，规避 Android 12+ 5 秒死线）+ `BleMesh.init` + `IrohNodeManager.start`；onDestroy 步骤边界取消 |
| `ble/BleMesh.kt` | BLE 编排常驻单例：布隆广播（10 分钟槽 + 配对期临时 id）、占空比扫描、回连 + 双向 HMAC 挑战、配对状态机（含 QR 快连）、聊天收发（BLE 优先→iroh 兜底）、`deliverRemote` 统一入站 | 功能完整；真机射频待验证 |
| `ble/BleChannel.kt` | Wire 帧协议（[type:1][bodyLen:2]，body≤4KB require）+ FrameSink 重组 + GATT client/server 链路（MTU 517、分片泵） | 纯逻辑部分有 JVM 测试 |
| `friendlink/FriendLink.kt` | 匿名回连匹配：HKDF(S_i)→每日钥→10 分钟槽位 4B ID→1024bit 布隆 + 随机填充至固定 set-bit 目标；HMAC 挑战应答 | 纯 JVM，有单测 |
| `core/SignalCore.kt` | SignalSession/ContactStore 应用级单例 | Keystore AES-GCM 包裹 SQLCipher 库密钥（dc.dbkey→dc-signal.db）；解不开=重置+一次性 UI 提示；deviceName=ANDROID_ID（已知 P2-3） |
| `core/IrohNodeManager.kt` | iroh 节点生命周期 | 节点种子 Keystore 包裹落盘 dc.nodekey；启动失败 5s/15s/45s 退避自愈（最多 3 次）+ 世代守卫；nodeId→联系人名缓存；自建中继 URL 配置（保存即重启） |
| `nearby/NearbyDiscovery.kt` | BLE 扫描/广播 + 经典蓝牙 bonded 列表；权限模型 | 只 scan/advertise（连接由 BleMesh/BleChannel 承担）；MAC 只以单向 SHA-256 别名展示 |
| `nearby/NearbyScreen.kt` | 附近设备页 | 功能可用（扫描/广播） |
| `addfriend/AddFriendPayload.kt` | `dc://add?v=2` 真实载荷（name/identity 33B/bundle/bucket/token 48B/ble 8B/naddr 可选）+ 动态分帧 FrameCodec（v2 帧格式、sid=载荷哈希、CRC32、f=2 蓝牙搭线帧）+ FrameCollector + AdaptiveFramePacer + QrCodec（纠错 L、setPixels 批量写） | 有 JVM 单测 |
| `addfriend/AddFriendScreen.kt` | `AddFriendRoleScreen`(选角色) / `ShowMyCodeScreen`(出示动态码+蓝牙帧交错播放) / `ScanToAddScreen`(扫码+快连回连+双路径配对卡片) | 全流程可用（真机射频待验证） |
| `ui/messages`、`ui/contacts`、`ui/chat`、`ui/me`、`ui/components`、`ui/theme` | 各主 tab 与聊天页 UI | 全部接真实 SQLCipher 数据；MeScreen 有节点面板（中继配置）/存储/关于真实数据；无演示数据 |

---

## 3. 构建与 CI 事实

`.github/workflows/build.yml`，触发：`push:[main]` + `pull_request:[main]` + `workflow_dispatch`。

步骤：
1. Rust stable + Android 目标（arm64-v8a / armeabi-v7a / x86_64）。
2. `Swatinem/rust-cache`（键含 Cargo.lock；Cargo.toml 变更会导致缓存失效 → 全量重编 libsignal，约 20+ 分钟）。
3. 安装 `cargo-ndk`、`protoc`（libsignal 后量子棘轮的 protobuf 代码生成需要；先摘 runner 自带 google-chrome apt 源防 Hash Sum mismatch，update 失败重试一次）。
4. 定位预装 NDK（fail-fast：查 ANDROID_NDK_HOME/ANDROID_NDK_ROOT 与 SDK ndk/*，找不到立即报错，不静默带空路径）。
5. 补齐 vendored 依赖（`third_party/` 不入库）：libsignal 按 SHA `eb7864c4d15435ee33681ce828930d9a4296f155` 浅抓取；iroh/iroh-relay 从 crates.io 取 1.1.0 解包。
6. `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/app/src/main/jniLibs build --release --lib -p dc-core --features vendored-openssl,ffi`（OPENSSL_DIR 指到空目录满足存在性检查，真实头文件由 vendored-openssl 提供）。
7. `cargo test --lib -p dc-core --features vendored-openssl`。
8. `cargo test --tests -p dc-core --features vendored-openssl`（集成测试全量：redteam / security_bruteforce / iroh_pair，进程内确定性、不依赖外网）。
9. 构建 host（x86_64-linux）cdylib + `uniffi-bindgen generate --library` 生成 Kotlin 绑定到 `android/app/src/main/uniffi`（不入库，每次构建重新生成；build.gradle.kts sourceSets 纳入）。
10. JDK 17 → `gradlew assembleDebug` → `gradlew testDebugUnitTest`（Kotlin/Robolectric 单测）→ `gradlew assembleRelease`（R8 混淆路径验证，proguard keep `chat.dc.core` + `-dontwarn java.awt.**`）→ 上传 APK 制品。

**验证盲区（重要）**：
- Rust 单元测试 + 集成测试均已入 CI；**Android instrumented test（src/androidTest/，如存在）仍未被 CI 执行**（无模拟器）。
- 蓝牙射频连通性、iroh 跨真机网络连通性无法在 CI 验证。
- `actions/upload-artifact@v4` 触发 GitHub 平台的 “Node.js 20 is deprecated … forced to run on Node.js 24” 警告，属平台弃用提示，非本项目代码问题，不影响构建结果。

---

## 4. 加密握手协议（已定稿设计）

参与者：被扫方 Bob（出示动态码）、扫码方 Alice（扫码）。

### 4.1 数据与流程
1. **QR 载荷**（Bob 出示，动态分帧 `dc://add?v=2`）：Bob 地址名（ProtocolAddress/SAS 本地标识）+ 长期身份公钥（33 字节）+ `PreKeyBundle` 上线格式（签名预密钥 + 一次性预密钥 + Kyber-1024 预密钥，均由长期身份钥签名）+ 桶地址（32B 随机）+ 一次性 token（48B）+ **BLE 配对 id（8B，与出示端 PAIR_UUID 广播同值，已加）** + iroh `dc://node?v=1` 地址快照（可选）。
2. **采集**：Alice 相机连续采集，集齐全部数据帧且 ≥3 秒（或读到 f=2 蓝牙搭线帧走快连）→ 拼接 → `AddFriendPayload.parse`（内含内容门 H(重组文本)==sid）。
3. **初始协商（PQXDH）**：Alice `process_bundle` → X25519 + Kyber-1024 组合，内部 HKDF 从共享点派生根密钥（**不直接用共享点当密钥**）。
4. **首条消息（带外认证）**：Alice 发 `PreKeySignalMessage`，附 **QR token+桶地址派生的 keyed-BLAKE3 MAC**；Bob 先验 MAC 再解密。token 只经当面二维码（快连路径经蓝牙上的 Signal 密文 QR_ID）传递，未扫到码者无法为首条消息造出合法 MAC。
5. **逐条加密**：`message_encrypt`/`message_decrypt` 驱动 Double Ratchet，逐条换钥 → 前向保密 + 后向自愈（post-compromise security）。
6. **SAS 带外比对**：两端各用 libsignal `Fingerprint::new(version=2, iterations=5200, local_id, local_identity_key, remote_id, remote_identity_key)` → `display_string()`（60 位）+ 由完整串 blake3 派生的 **6 位短码**。SAS 绑定双方长期身份公钥且两端算出同一串；中间人与两边分别协商 → 码必不一致。
7. **TOFU 落盘**：SAS 用户比对通过后，才 `pin_identity`（`IdentityKeyStore.save_identity`）固定对方长期身份公钥。之后重连直接校验长期签名，免扫码；对方长期钥变更 → 异钥被拒（`UntrustedIdentity` → FFI `RemoteIdentityChanged`），需重新带外验证。
8. **防重放**：Double Ratchet 消息计数器 + `mailbox.rs` 的 msg_id 过期台账 + 时间戳 + ±5min 窗，双重。

### 4.2 已纠正的错误认知
- “扫码方拿到公钥后自己算出对方私钥”**在数学上不可能**（否则公钥密码学整体失效）。正确机制：双方各生成临时密钥对，各自用「己方私钥 + 对方公钥」做 ECDH，得到**同一个共享点**，再经 HKDF 派生会话密钥。

### 4.3 已实现部分（`handshake.rs` + `signal_store.rs`，CI 绿）
- `Device`：后端统一为 `SqlSignalStore`（SQLCipher）；`generate`=内存库、`open`=文件库；方法 `generate / open / identity_key / prekey_bundle / process_bundle / encrypt / decrypt / pin_identity / is_trusted`。
- `bundle_to_wire` / `bundle_from_wire`：用 `PreKeyBundle` 公开 getter 抽字段（id 走 `Into<u32>`、curve/kem 公钥与身份钥走各自 serialize）+ CBOR 打包；对端 `PreKeyBundle::new` 精确重建。
- `sas_code`、`first_message_mac`、`verify_first_message_mac`；TOFU 拒绝映射为 `CoreError::IdentityChanged`（FFI 层 `DcError.RemoteIdentityChanged`）。
- 10 个单元测试（lib 内，CI 会跑）：PQXDH+双棘轮往返、连续消息密钥互异、重放同一密文被拒、篡改密文被拒、SAS 两端一致且识别身份替换、TOFU pin 与身份变更、换钥拒绝且错误成类（IdentityChanged）、首条消息 token-MAC、bundle wire 往返、端到端连接流程（`full_connection_flow_over_wire`）、33 字节身份契约回归（`identity_key_wire_bytes_are_33…`）。

### 4.4 UniFFI 导出（`ffi.rs`，CI 生成 Kotlin 绑定，App 已在用）
- `SignalSession`（`uniffi::Object`）：内部 `Mutex<Device>` 满足 UniFFI 的 `&self` 契约；构造器 `generate`（内存库）/ `open`（SQLCipher 持久库）；方法 `identity_key / prekey_bundle_wire / process_bundle / encrypt / decrypt / sas_with / pin_identity / is_trusted`。
- `ContactStore`（`uniffi::Object`）：`upsert_contact / list_contacts / set_verified / delete_contact / append_message / last_messages / messages`（与 SignalSession 同库同 key、不同表）。
- `IrohNode`（`uniffi::Object`）+ `NodeCallback`（callback interface）：`start(relay_url, seed32, callback) / node_id_hex / export_naddr / send / stop`；自由函数 `node_id_from_naddr`。
- `WireMessage{msg_type:u8, ciphertext:Vec<u8>}`、`SasCode{full:String, six:String}`、`Contact`、`ChatMessage`（`uniffi::Record`）；`DcError`（`uniffi::Error`，`Core`/`RemoteIdentityChanged` 两类——TOFU 拒绝单独成类供 UI 区分）。
- 自由函数 `first_message_mac` / `verify_first_message_mac` / `prekey_sender_identity`。
- FFI 面只用 String/Vec<u8>/bool/Record，libsignal 类型一律转字节。

---

## 5. 进度总览

| 阶段 | 内容 | 状态 | 载体 |
|---|---|---|---|
| 阶段 1 | Rust 握手核心（PQXDH+双棘轮+SAS+TOFU） | ✅ 已合并 | PR#2 → `744b221` |
| 阶段 1+ | bundle 上线格式 + 端到端连接测试 | ✅ 已合并 | PR#3 → `da69717` |
| UI | 加好友角色分屏 + 进入即请求附近设备权限 | ✅ 已合并 | PR#4 → `04561ac` |
| （附带）| 扫码计时封顶 + 动态码交错噪声帧 + 全项目注释去叙事 | ✅ 已合并 | PR#1 → `3b588ec` |
| 阶段 2 · 第一刀 | Rust 侧 UniFFI 导出 `SignalSession` | ✅ 已合并 | PR#5 → `d6f469b` |
| 阶段 2 · 第二刀 | CI 生成 Kotlin 绑定 + gradle 接入（JNA） | ✅ 已完成 | CI 第 9 步 + `dc_core.kt` + `jna:5.13.0@aar` |
| 阶段 0 | QR 载荷换真实密钥/真 SAS | ✅ 已完成 | `AddFriendPayload`(v=2 真实字段) + `SignalCore`/`BleMesh` 配对流程 |
| 阶段 3 | BLE GATT 传输 + SQLCipher 持久化 store + 联系人落盘 + 串起整条链 | ✅ 已完成（GLM-Zcode 分支） | `ble/BleChannel.kt`/`ble/BleMesh.kt` + `signal_store.rs` + `contacts.rs` |
| 增量 | iroh 远程链路（dc://node 快照 + 应用层 ACK + 生命周期自愈）+ 动态码蓝牙快连（f=2 帧）+ 竞品安全修复（时钟/门禁/轮换/转发票/治理器） | ✅ 已在 GLM-Zcode 分支 | `node.rs`/`IrohNodeManager.kt`/`AddFriendPayload.kt`/`clock.rs`/`mailbox.rs`/`nodekey.rs`/`relay.rs`/`governor.rs` |
| 阶段 4 | 两台真机实测蓝牙射频 + 跨网连通 | ⬜ 待做（需硬件） | — |
| 阶段 7/8 | 群聊两类 + 自适应接线；代理/无障碍/arti/自毁计时器 | ⬜ 未开工 | — |

---

## 6. 待办路线图（含验收标准与依赖）

> 阶段 2 第二刀、阶段 0、阶段 3 已完成（见 §5），原任务清单保留在 git 历史，此处只列剩余项。

### 阶段 4：两台真机实测（需硬件，只能由所有者执行）
任务：两台 Android 设备，走「A 出示 / B 扫码（含 f=2 蓝牙快连路径）→ BLE 连接 → SAS 比对一致 → 加为联系人 → 加密互发」全流程；再开网络验证 iroh 跨网收发（同 WiFi 直连 / 自建中继跨网）。
交付物：本 wiki 附一份手动测试步骤清单（待实测后补）。
说明：蓝牙射频连接无法在 Windows/无设备环境验证；CI 只能保证编译与逻辑测试，不能保证射频连通。

### 已知待办（按台账编号，勿重复报）
1. **队列补投接线**：`queue.rs`（outbox/重试/死信）未接 Android 发送路径；BLE 路径无应用层 ack（iroh 路径已有 1 字节 ACK）。P2-8。
2. **mesh 多跳中转**：设计见 docs/BLE-RELAY-DESIGN.md 与 SP-9；转发票/治理器原语已备（relay.rs/governor.rs），传输未接。
3. **信箱/轮换接线**：mailbox.rs 门禁与 nodekey.rs 轮换公告为原语，读桶/公告推送未接传输。
4. **台账遗留缺陷**：P1-3 node.rs 无并发流上限、P1-4 配对链路收不了 MSG、P1-6 joiner 收 DCS1 即落库、P2-1 非常量时间比较、P2-2 AUTH_B 死代码、P2-3 ANDROID_ID 设备名、P2-5/6 配对竞态（完整台账见 docs/INDUSTRY-COMPARISON-2026-09-09.md 第 3 节，行号以编号检索为准）。
5. **设置中心**：settings.rs 模型已建（十二类字段中 strict_crypto/scope 等已生效），UI 仅「我的」页节点/存储/关于三块真实数据，其余子页面未铺开。
6. **SP-4 本地敏感操作**（生物识别双因子/自毁计时器）、SP-9 多跳推进、gossip 扇出/OpenMLS/arti——均设计意图，未实现。

---

## 7. 已知缺陷与技术债

> §7 旧清单（QR 占位载荷、无蓝牙连接代码、NodeService 桩、ChatScreen 内存消息、MeScreen 死链等）所列缺口已全部修复于 GLM-Zcode 分支；占位字符串（`add_friend_ble_pending`/`me_badge_unwired` 等）已从 strings.xml 移除，`ui/DemoData.kt` 已删除。以下为现存项。

功能性缺口：
- **BLE 射频未实测**：GATT/广播/扫描链路逻辑完整且有 JVM 单测，但两台真机的射频连通性未验证（阶段 4）。
- **队列补投未接**：`queue.rs` 已建但发送路径不经过它；BLE 发送无应用层 ack（对端不在线即失败返回，不落库）。
- **mesh 多跳/人群转发/信箱代存未接传输**：协议原语（relay.rs/governor.rs/mailbox.rs/nodekey.rs）齐备。
- **`AUTH_B` 反向认证为死代码**（P2-2）、**配对链路收不了聊天 MSG**（P1-4）、**node.rs 无并发流上限**（P1-3）——见台账。
- **群聊、OpenMLS、gossip 扇出、arti、SP-4 敏感操作、自毁计时器**：未开工。

工程债：
- **非常量时间 HMAC 比较**（P2-1）：FriendLink 挑战应答用 `contentEquals`。
- **deviceName 用 ANDROID_ID**（P2-3）：待改随机名（改名会影响既有 ProtocolAddress 会话，需迁移方案）。
- **配对竞态**（P2-5/6）：配对对象为单槽（pairingObj），并发配对行为未定义。
- **NDK/CI action 版本未固定**：build.yml 用 runner 预装 NDK 与 `@v5` action 标签，属 CI 脆弱点。
- **冗余逻辑未动**（历史工程债延续）：`governor.refill_all` 对同一 map 遍历两遍、`RelayGuard.accept` 多次全表 `retain`、扫码页 200ms 快照轮询循环。均非缺陷（行为正确），留待单独清理并配测试。
- CI 不跑 Android instrumented test（无模拟器）。

---

## 8. 环境与验证约束

- 开发机：Windows（win32，zh-CN，Asia/Shanghai）。
- **不在本机编译/运行**（所有者要求）。原因：本机 Python/curl 默认 SSL 校验失败（证书链含自签名，疑为安全软件 TLS 拦截）；Rust 交叉编译 + gradle 体积大。所有验证走 CI。
- **本机 git 到 `github.com:443` 间歇性连接重置/超时**：`fetch`/`push` 常需重试多次才成功；本地 `origin/*` ref 易滞后。**GitHub MCP（应用通道）稳定可用**，查远端真实状态（`list_commits`/`get_commit`/`pull_request_read`/`get_check_runs`）以 MCP 为准。
- CI 时长：缓存命中约 6–13 分钟；Cargo.lock 变更致缓存失效时约 20+ 分钟（libsignal 全量重编）。
- `uniffi-bindgen --library` 需主机架构 .so（Linux CI 无法 dlopen Android ARM .so）。
- 蓝牙射频连通性需两台真机，无法在 CI/本机验证。

---

## 9. 关键决策记录

- 加密走 vendored libsignal（不自研）；初始握手启用 **PQXDH（Kyber-1024/ML-KEM）**——该 libsignal 版本 `PreKeyBundle` 恒含 Kyber 预密钥，故初始协商天然抗量子；不手写 Frodo/Kyber。
- 密钥协商 = 临时-临时 **ECDH + HKDF**；纠正“从公钥算私钥”的错误设想（不可能）。
- **SAS** = libsignal `Fingerprint`；对外展示 **6 位短码**（由完整串 blake3 派生）+ 可展开完整 60 位；短码 6 位=10^6 空间，针对性 MITM 有极小碰撞概率，完整码抗碰撞更强。
- 首条握手消息在会话密钥存在前，用 **QR 一次性 token 的 keyed-BLAKE3 MAC** 做带外认证；token 只经当面二维码传递。
- **TOFU**：仅在 SAS 用户比对通过后才 pin 对方长期身份公钥；否则记住的可能是中间人身份。
- 防重放：nonce + 时间戳 + 双棘轮计数器；时钟偏移由 `clock.rs` 的限幅/冷却/法定人数约束。
- 加好友 **出示码与扫码绝不同屏**（安全）：拆为选角色入口 + 两个独立页；进入角色页即请求「发现附近的设备」权限。
- **节点密钥与长期身份解耦（已落地形态）**：iroh 节点用独立持久种子（Kotlin 随机 32 字节，Keystore AES-GCM 包裹落盘 dc.nodekey）；跨网寻址靠 QR/握手携带的 `dc://node?v=1` 地址快照（直连 IP + 可选自建中继），联系人表落盘快照；nodekey.rs 轮换公告为后续演进原语。
- **iroh 零 n0 依赖**：端点以 `presets::Minimal` 构建，无自建中继 URL 即 `RelayMode::Disabled`；中继 URL 用户可配（「我的」→节点服务，保存即重启）。
- **一消息一流 + 1 字节应用层 ACK**（iroh 通道）：send 返回即对端应用层已收。
- **动态分帧 + 蓝牙快连（SP-3 v3，2026-09-11）**：sid=载荷哈希绑定内容、帧级 CRC、f=2 搭线帧；token 只经 Signal 密文（QR_ID）交换，防偷拍 3 秒门槛双端执行。
- 协作工作流：每个改动走独立功能分支 → PR（base=main）→ CI 验证 → 绿则合并。`build.yml` 已加 `pull_request` 触发。绿 PR 可由所有者或助手合并。
- 注释规范：删自我表扬/工单编号（审计/红队/SP-N/风险登记）/品牌背书（微信支付/AWS/Briar/微信/Telegram）/用户权威归属等叙事，保留技术约束与不变量。

---

## 10. 术语

- PQXDH：Post-Quantum X3DH，X25519 ECDH 与 Kyber-1024 KEM 组合的初始密钥协商。
- Double Ratchet：Signal 的逐条消息换钥棘轮，提供前向保密与后向自愈。
- SAS：Short Authentication String，短认证串，用于带外肉眼比对防中间人。
- TOFU：Trust On First Use，首次信任；前提是首次必须带外验证过。
- PreKeyBundle：一次性预密钥 + 签名预密钥 + Kyber 预密钥 + 长期身份公钥的打包，供对方发起 X3DH。
- GATT：BLE 的通用属性协议，client/server 模型，用于承载字节通道。
