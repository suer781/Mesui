# Mesui 实现状态与待办 Wiki

本文件记录去中心化聊天项目 Mesui 的当前实现状态、已定稿的加密握手设计、剩余待办、已知缺陷、环境与验证约束、关键决策。仅陈述事实与工程判断，不含评价性措辞。

最后更新：2026-09-07（对应 main 提交 `d6f469b`）

---

## 1. 项目概况

- 定位：主打安全、去中心化、**不依赖中心服务器/网络**的端到端加密聊天。人人即节点，近距离靠蓝牙、远距离靠 P2P（iroh）与人群中继。
- 技术栈：Rust 核心（crate `dc-core`，edition 2024，AGPL-3.0-or-later）+ Android Kotlin/Compose 壳。
- 密码学原则：所有密码学原语来自第三方库（ed25519-dalek、blake3、getrandom、vendored libsignal-protocol、SQLCipher/rusqlite、iroh）；本仓只做编排，不自研原语。
- 仓库：`github.com/suer781/Mesui`，默认分支 `main`。

---

## 2. 代码结构

### 2.1 Rust 核心 `crates/core/src`

| 模块 | 职责 | 门控 feature |
|---|---|---|
| `identity.rs` | Ed25519 长期身份密钥；域分隔 BLAKE3-XOF 1024 位指纹 | 常开 |
| `entropy.rs` | 熵源：内核 CSPRNG 为主 + 传感器噪声 BLAKE3 搅拌增强 | 常开 |
| `envelope.rs` | CBOR 信封 + 4 字节大端长度分帧（4MiB 上限）+ FIFO 去重 + zstd 压缩 | 常开（压缩需 `compress`） |
| `nodekey.rs` | 节点密钥轮换公告：长期钥签名、单调 serial、过渡窗、按 serial 取钥匙、单身份公告数上限 | 常开 |
| `mailbox.rs` | 信箱桶门禁：keyed-BLAKE3 MAC、±5min 重放窗、msg_id 过期台账防重放、入站顺序「先验签后去重」 | 常开 |
| `queue.rs` | SQLCipher 整库加密的待发队列 + 收件去重；重试调度；u64→i64 钳制 | `db` |
| `relay.rs` | 陌生人人群转发票：握手挑战绑定 + 指纹缓存 + TTL 上限；缓存满 fail-closed 不驱逐活条目 | 常开 |
| `adaptive.rs` | 负载三档引擎（轻/中/重）：升档即时可跳级、降档逐级防抖；NaN 指标 fail-closed | 常开 |
| `governor.rs` | 陌生人中继资源治理：令牌桶；电量/负载 smoothstep 连续曲线降份额；保底连接 | 常开 |
| `clock.rs` | 内部单调时钟：网络双源交叉验证 + 蓝牙 3 人法定人数共识 + 高水位防回拨 + 采纳限幅/冷却 | 常开 |
| `retry.rs` | 指数退避 + 全抖动（纯计算） | 常开 |
| `settings.rs` | serde JSON 设置持久化 | 常开 |
| `handshake.rs` | **Signal 会话层**：PQXDH 初始协商 + Double Ratchet + SAS + TOFU + bundle 上线格式 | `signal` |
| `ffi.rs` | UniFFI 导出层：`CoreInfo`、`smoke_test_all_modules`、`SignalSession` 等 | `ffi` |
| `signal_backend` | 构建探针（证明 libsignal 可链接） | `signal` |

Feature：`default = ["db","compress","signal","iroh-net"]`；`ffi` 与 `vendored-openssl` 非默认。`signal` 追加依赖 `rand 0.9`（须与 libsignal 同版本，否则 `Rng/CryptoRng` 非同一 trait）+ `futures 0.3`（`block_on` 驱动 libsignal 的 `?Send` async trait）。

### 2.2 Android 壳 `android/app/src/main/java/chat/dc/app`

| 文件 | 职责 | 状态 |
|---|---|---|
| `MainActivity.kt` | Compose 底部三 tab（消息/联系人/我的）+ 导航图；启动前台 `NodeService` | 导航含 `add_friend`(选角色)/`add_friend_show`/`add_friend_scan`/`nearby`/`chat/{id}` |
| `service/NodeService.kt` | 前台常驻服务（START_STICKY） | **桩**：只有常驻通知，无节点逻辑 |
| `nearby/NearbyDiscovery.kt` | BLE 扫描/广播 + 经典蓝牙 bonded 列表；权限模型 | 只 scan/advertise，**无 connect** |
| `nearby/NearbyScreen.kt` | 附近设备页 | 功能可用（扫描/广播） |
| `addfriend/AddFriendPayload.kt` | QR 载荷 `dc://add`、动态分帧 `FrameCodec`、采集状态机 `FrameCollector` | **载荷是占位随机字节**（见 §7） |
| `addfriend/AddFriendScreen.kt` | `AddFriendRoleScreen`(选角色) / `ShowMyCodeScreen`(出示动态码) / `ScanToAddScreen`(扫码) | 出示/扫码已分屏；扫完无后续动作 |
| `ui/messages`、`ui/contacts`、`ui/chat`、`ui/me`、`ui/components`、`ui/theme` | 各主 tab 与聊天页 UI | 多为空态/占位；`MeScreen` 设置行为死链 |

---

## 3. 构建与 CI 事实

`.github/workflows/build.yml`，触发：`push:[main]` + `pull_request:[main]` + `workflow_dispatch`。

步骤：
1. Rust stable + Android 目标（arm64-v8a / armeabi-v7a / x86_64）。
2. `Swatinem/rust-cache`（键含 Cargo.lock；Cargo.toml 变更会导致缓存失效 → 全量重编 libsignal，约 20+ 分钟）。
3. 安装 `cargo-ndk`、`protoc`（libsignal 后量子棘轮的 protobuf 代码生成需要）。
4. 定位预装 NDK。
5. 补齐 vendored 依赖（`third_party/` 不入库）：libsignal 按 SHA `eb7864c4d15435ee33681ce828930d9a4296f155` 浅抓取；iroh/iroh-relay 从 crates.io 取 1.1.0 解包。
6. `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o android/app/src/main/jniLibs build --release --lib -p dc-core --features vendored-openssl,ffi`。
7. `cargo test --lib -p dc-core --features vendored-openssl`。
8. JDK 17 → `gradlew assembleDebug` → 上传 APK 制品。

**验证盲区（重要）**：
- `cargo test --lib` 只跑 lib 内 `#[cfg(test)]` 单元测试（含 `handshake.rs` 的 8 个测试）。**不编译/不运行** `tests/` 下集成测试（`redteam.rs`、`security_bruteforce.rs`、`iroh_pair.rs`）与 `examples/`。
- `assembleDebug` **只编译 main 源集，不编译也不运行 Android 单元测试**（`src/test/` 下的 Robolectric/JVM 测试从不被 CI 执行）。改测试文件不会被 CI 兜底。
- CI 只把 `libdc_core.so` 放进 jniLibs，**不生成 Kotlin 绑定、不接运行时**（阶段 2 第二刀要补）。
- `actions/upload-artifact@v4` 触发 GitHub 平台的 “Node.js 20 is deprecated … forced to run on Node.js 24” 警告，属平台弃用提示，非本项目代码问题，不影响构建结果。

---

## 4. 加密握手协议（已定稿设计）

参与者：被扫方 Bob（出示动态码）、扫码方 Alice（扫码）。

### 4.1 数据与流程
1. **QR 载荷**（Bob 出示，动态分帧）：Bob 长期身份公钥 + `PreKeyBundle`（签名预密钥 + 一次性预密钥 + Kyber-1024 预密钥，均由长期身份钥签名）+ 桶地址（32B 随机）+ 一次性 token（48B）+（待加）一个可与 BLE 广播匹配的 id。
2. **采集**：Alice 相机连续采集，集齐全部数据帧且 ≥3 秒 → 拼接 → `bundle_from_wire` 重建 `PreKeyBundle`。
3. **初始协商（PQXDH）**：Alice `process_prekey_bundle` → X25519 + Kyber-1024 组合，内部 HKDF 从共享点派生根密钥（**不直接用共享点当密钥**）。
4. **首条消息（带外认证）**：Alice 发 `PreKeySignalMessage`，附 **QR token 派生的 keyed-BLAKE3 MAC**；Bob 先验 MAC 再解密。token 只经当面二维码传递，未扫到码者无法为首条消息造出合法 MAC。
5. **逐条加密**：`message_encrypt`/`message_decrypt` 驱动 Double Ratchet，逐条换钥 → 前向保密 + 后向自愈（post-compromise security）。
6. **SAS 带外比对**：两端各用 libsignal `Fingerprint::new(version=2, iterations=5200, local_id, local_identity_key, remote_id, remote_identity_key)` → `display_string()`（60 位）+ 由完整串 blake3 派生的 **6 位短码**。SAS 绑定双方长期身份公钥且两端算出同一串；中间人与两边分别协商 → 码必不一致。
7. **TOFU 落盘**：SAS 用户比对通过后，才 `pin_identity`（`IdentityKeyStore.save_identity`）固定对方长期身份公钥。之后重连直接校验长期签名，免扫码；对方长期钥变更 → `is_trusted` 返回 false，需重新带外验证。
8. **防重放**：Double Ratchet 消息计数器 + `mailbox.rs` 的 nonce(16B) + 时间戳 + ±5min 窗，双重。

### 4.2 已纠正的错误认知
- “扫码方拿到公钥后自己算出对方私钥”**在数学上不可能**（否则公钥密码学整体失效）。正确机制：双方各生成临时密钥对，各自用「己方私钥 + 对方公钥」做 ECDH，得到**同一个共享点**，再经 HKDF 派生会话密钥。

### 4.3 已实现部分（`handshake.rs`，CI 绿）
- `Device`：`InMemSignalProtocolStore` 后端；方法 `generate / identity_key / prekey_bundle / process_bundle / encrypt / decrypt / pin_identity / is_trusted`。
- `bundle_to_wire` / `bundle_from_wire`：用 `PreKeyBundle` 公开 getter 抽字段（id 走 `Into<u32>`、curve/kem 公钥与身份钥走各自 serialize）+ CBOR 打包；对端 `PreKeyBundle::new` 精确重建。
- `sas_code`、`first_message_mac`、`verify_first_message_mac`。
- 8 个单元测试（lib 内，CI 会跑）：PQXDH+双棘轮往返、连续消息密钥互异、重放同一密文被拒、篡改密文被拒、SAS 两端一致且识别身份替换、TOFU pin 与身份变更、bundle wire 往返、端到端连接流程（`full_connection_flow_over_wire`：出示→上线格式→扫码重建→PQXDH→token-MAC→SAS 一致→TOFU→双向加密聊天）。

### 4.4 UniFFI 导出（`ffi.rs`，CI 绿，尚不可被 Kotlin 调用）
- `SignalSession`（`uniffi::Object`）：内部 `Mutex<Device>` 满足 UniFFI 的 `&self` 契约；导出 `generate / identity_key / prekey_bundle_wire / process_bundle / encrypt / decrypt / sas_with / pin_identity / is_trusted`。
- `WireMessage{msg_type:u8, ciphertext:Vec<u8>}`、`SasCode{full:String, six:String}`（`uniffi::Record`）；`DcError`（`uniffi::Error`，扁平消息）。
- 自由函数 `first_message_mac` / `verify_first_message_mac`。
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
| 阶段 2 · 第二刀 | CI 生成 Kotlin 绑定 + gradle 接入 | ⬜ 待做 | — |
| 阶段 0 | QR 载荷换真实密钥/真 SAS | ⬜ 待做 | — |
| 阶段 3 | BLE 传输 + 持久化 store + 联系人落盘 + 串起整条链 | ⬜ 待做 | — |
| 阶段 4 | 两台真机实测蓝牙射频 | ⬜ 待做（需硬件） | — |

---

## 6. 待办路线图（含验收标准与依赖）

### 阶段 2 · 第二刀：把绑定接进 App（CI 可验证编译，运行需设备）
目标：让 Kotlin 能真正调到 `SignalSession`。
任务：
1. CI 增加 **host 架构（x86_64-linux）** cdylib 构建：`cargo build --release --lib -p dc-core --features ffi`（`uniffi-bindgen --library` 需 dlopen 主机架构 .so，不能用 Android ARM .so）。
2. 生成 Kotlin 绑定：用 uniffi 的 `cli` feature 跑 `uniffi-bindgen generate --library target/release/libdc_core.so --language kotlin --out-dir <gen>`（确切调用方式待核实：`cargo run --features uniffi/cli --bin uniffi-bindgen …` 或 `cargo install uniffi_bindgen_cli --version 0.29.5`）。
3. 把生成的 `dc_core.kt` 纳入 `android/app` 源集（`sourceSets.main.java.srcDir(<gen>)` 或直接放入 `src/main/java`）。
4. `build.gradle.kts` 加运行时依赖：uniffi 0.29 默认 Kotlin 后端基于 JNA → `implementation("net.java.dev.jna:jna:<ver>@aar")`（确切坐标/版本待核实）；确认 `System.loadLibrary("dc_core")` 由生成代码触发。
5. jniLibs 已含三 ABI 的 `libdc_core.so`（CI 第 6 步产出）。
依赖：阶段 2 第一刀（已完成）。
验收：`assembleDebug` 编译通过（CI 可验）；设备上 `SignalSession.generate()` + `smoke_test_all_modules()` 返回正常（需设备/模拟器）。
风险：uniffi CLI 调用方式、JNA 坐标/版本为版本相关细节，可能需 1–2 轮 CI 迭代。

### 阶段 0：QR 换真实密钥（依赖阶段 2 第二刀）
目标：出示/扫描的是真身份与真 bundle，不再是占位随机字节。
任务：
1. Kotlin 侧建一个 `SignalSession` 持有者（应用级单例/仓库），启动时 `generate(deviceName)`。
2. `ShowMyCodeScreen`：QR 内容 = `prekey_bundle_wire()` + 长期身份公钥 + 桶地址 + token + BLE 匹配 id（编码为分帧）。
3. `ScanToAddScreen`：拼接后 `bundle_from_wire` → 交给连接流程（阶段 3）。
4. 安全码显示改用 `sas_with()`（真 SAS），替换 `AddFriendPayload.fingerprintGroups()` 占位。
5. `AddFriendPayload` 结构改为承载上述真实字段（bundle 含 Kyber 公钥约 1.7KB，需分帧，帧数会变多）。
验收：出示页 QR 可被扫描页解析出合法 bundle；SAS 两端一致。
备注：`deviceName`/地址命名规范需定（用于 `ProtocolAddress`）。

### 阶段 3：BLE 传输 + 持久化 + 串起整条链（核心工程量）
目标：扫完真的能连、能加为联系人、能加密收发。
任务：
1. **BLE 匹配 id**：QR 载荷与 BLE 广播（service data / manufacturer data）都带同一个 id；扫码方用它把「扫到的 QR」与「BLE 扫描到的设备」对应起来（现代 Android 经典蓝牙 MAC 被隐私隐藏，只能靠广播内可匹配 id 定位设备）。
2. **BLE GATT 传输**：出示侧做 GATT server（一个可读写/通知的特征承载握手与消息字节）；扫码侧做 GATT client，连接后收发。`NearbyDiscovery` 增加 connect / GATT server 能力。
3. **持久化 store（关键）**：把 libsignal 的 `IdentityKeyStore / SessionStore / PreKeyStore / SignedPreKeyStore / KyberPreKeyStore` 用 SQLCipher 实现（复用 `queue.rs` 的 `Db` 或新建），替换当前 `InMemSignalProtocolStore`；否则重启丢会话、TOFU pin 无法持久、重连免扫码不成立。
4. **联系人落盘**：联系人表（对方长期身份公钥、备注、SAS 校验状态、桶地址等），SQLCipher 加密；`ContactsScreen` 从空态改为读真实数据。
5. **串流程**：扫码→拼接→BLE 连接→首条 token-MAC 消息→PQXDH→双棘轮→两端弹 6 位 SAS→用户比对确认→TOFU pin + 存联系人→进入聊天；把 `add_friend_ble_pending` / `add_friend_pending_core` 等占位换成真实连接状态（连接中/已连接/失败原因）。
6. **聊天接真收发**：`ChatScreen` 从「仅本页内存」改为经 `SignalSession.encrypt/decrypt` + BLE 通道真实收发；消息落 `queue.rs` 队列。
7. 顺带修死链：`MeScreen` 设置行 `onClick` 为空 → 接真实设置子页或去掉可点affordance；去掉 `me_badge_unwired`「未接入」角标。
验收：见阶段 4。
风险：BLE GATT 在真实射频下的稳定性、MTU/分片、连接时序；持久化 store 与 libsignal trait 的 async 适配。

### 阶段 4：两台真机实测（需硬件，只能由所有者执行）
任务：两台 Android 设备，走「A 出示 / B 扫码 → BLE 连接 → SAS 比对一致 → 加为联系人 → 加密互发」全流程。
交付物：本 wiki 附一份手动测试步骤清单（待阶段 3 完成后补）。
说明：蓝牙射频连接无法在 Windows/无设备环境验证；CI 只能保证编译，不能保证射频连通。

---

## 7. 已知缺陷与技术债

功能性缺口：
- **无任何蓝牙连接代码**：`NearbyDiscovery` 只 scan/advertise，从不 connect；无 RFCOMM/GATT 客户端或服务端。这是“扫完连不上”的直接原因。
- **QR 载荷是占位随机字节**：`AddFriendPayload.generate()` 用 `random(32)` 造 identity/nodeKey、`random(48)` 造 token，非真实密钥；`fingerprintGroups()` 是占位（只取前 16 字节 hex），非真实 SAS。
- **扫码完成后无后续动作**：`ScanToAddScreen` 采集完成只弹一张卡片（安全码 + 占位文案），无连接、无保存、无导航；`peerPayload` 是丢弃型局部变量。
- **无联系人存储**：`ContactsScreen` 恒为空态；无数据源。
- **libsignal store 仅内存**：`InMemSignalProtocolStore`，重启丢会话/丢 TOFU pin。
- **`NodeService` 是桩**：只有常驻通知，无 iroh 端点/信箱/中继逻辑。
- **`ChatScreen` 消息仅本页内存**：不发送、不落盘；路由 `chat/{contactId}` 无真实入口（孤儿页）。
- **`MeScreen` 设置行死链**：`onClick` 为空但带 `›` 箭头，点击无反应。

占位/未完成文案（用户可见）：
- `add_friend_ble_pending`「采集完成；蓝牙协商将在核心接入后自动发起」
- `add_friend_pending_core`「真实身份与加密会话将在核心接入后建立」
- `me_status_placeholder`「尚未设置个人资料」
- `me_badge_unwired`「未接入」（挂在隐私与安全/数据与存储/关于三行）
- `chat_title_placeholder`「新会话」

工程债：
- 注释清理只做了「删自我表扬/工单编号/品牌背书叙事、保留技术信息」；**「冗余行为」逻辑未动**（`governor.refill_all` 对同一 map 遍历两遍、`RelayGuard.accept` 连续三次全表 `retain`、扫码页 200ms 轮询 + 280ms 换帧两循环并跑）。这些是逻辑改动，留待单独处理并配测试。
- CI 不跑集成测试与 Android 单测（见 §3 验证盲区）。
- `build.yml` 的 `upload-artifact@v4` 触发 Node.js 20 弃用警告（无害；如需消除可升到原生 node24 的版本）。

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
