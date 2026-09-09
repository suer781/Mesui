# 去中心化聊天

绝对 P2P 的去中心化加密聊天软件：**每个用户即是一个节点**，无账号、无推送服务、无内置中继、无中心目录。

```
Kotlin UI (Jetpack Compose, Material 3)
   ↕ UniFFI
Rust 核心（本仓库 crates/core）：身份 / Signal 信封 / 队列+去重 / 自适应策略引擎 / 通道编排
   ↕
管道层：iroh（QUIC 打洞 + mDNS 近场发现 + 加密介绍信广域发现 + 中继兜底，可走代理）+ iroh-gossip 广播树
        ｜蓝牙 RFCOMM｜二维码引导（NFC 已移除）｜可选 arti+桥（obfs4/webtunnel）
```

## 核心设计决策

| 关注点 | 选型 | 备注 |
|---|---|---|
| 端到端加密 | signalapp/libsignal（官方 monorepo，git 锁 commit） | PQXDH（Kyber-1024 + X25519）+ Double Ratchet |
| 群加密 | **隐私群 pairwise / 效率群 OpenMLS**（建群时定死，不随负载切换） | 隐私群保留选择性可见，人数上限默认 50 |
| 节点身份 | 长期身份密钥与发现身份解耦：对外用可轮换临时节点密钥 | 防止「公钥→IP」全网可查（见 ARCHITECTURE-RISKS.md A1） |
| P2P 连接 | iroh（构建时移除 n0 默认中继/DNS） | 打洞/中继/传输加密全内置，不自研 |
| 广域发现 | 加密介绍信沿联系人链传递 + mDNS 近场 | 不发布公共目录，仅联系人图谱可查 |
| 大群扇出 | iroh-gossip 广播树 | 效率群专用 |
| 本地存储 | rusqlite + SQLCipher | 密钥来自 Android Keystore |
| 哈希 | BLAKE3 XOF 1024 位 | 指纹/挑战/熵池全线统一 |
| 反封锁 | 默认 TLS 形态流量；可选 Tor 仅走桥 | 不裸连 Tor |
| 许可证 | AGPL-3.0-or-later | libsignal 传染，与 Briar/SimpleX 同路 |

详见 [docs/PLAN.md](docs/PLAN.md)（含「明确不做的事」四张清单与威胁模型诚实边界）。

## 仓库结构

```
crates/core        Rust 核心（主机单测覆盖）
android/           Android 工程（Jetpack Compose，SDK 已就绪，可构建 debug APK）
docs/PLAN.md       批准实施的完整方案
LICENSE            AGPL-3.0
```

## 构建与测试

> **前置条件（Windows / MSYS2 环境，缺一项即构建失败，照抄下面的命令会失败）：**
> - SQLCipher / zstd 的 C 代码由 MSYS2 的 gcc 编译，构建全功能目标前必须先把 MSYS2 的 bin 放进 PATH：
>
>   ```bash
>   export PATH="/c/Users/13682/msys64/mingw64/bin:/c/Users/13682/msys64/usr/bin:$PATH"
>   ```
>
>   否则链接期报 `dlltool.exe: program not found`。
> - libsignal 的 SparsePostQuantumRatchet 构建脚本需要 `protoc`，需安装 MSYS2 的
>   `mingw-w64-x86_64-protobuf`，否则报 `Could not find protoc`。

```bash
# 纯逻辑层（无需 MSVC/NDK）
cargo check --no-default-features
cargo test  --no-default-features

# 全功能（需 MSYS2 gcc + protoc：SQLCipher/zstd 的 C 代码 + libsignal 构建脚本）
cargo test
```

## 开发状态

- [x] 阶段 0：工程骨架 + 环境搭建（Rust GNU + MSYS2 gcc + Android SDK 命令行版，全程免提权免 Android Studio，详见 docs/ENVIRONMENT.md）
- [x] 核心纯逻辑层：身份/熵源/信封/自适应引擎/加密队列/设置 —— 核心逻辑层单测（src 内 85 + 集成测试 22；本机缺 protoc / dlltool，未实跑验证）
- [x] Spike A ✅：signalapp/libsignal 官方 monorepo（锁定 commit eb7864c，vendored）构建链接成功
- [x] Spike B ✅：iroh 两 endpoint 进程内按公钥对连、QUIC 双向流互发成功
- [x] Spike C ✅：UniFFI 脚手架编译通过；**APK 构建链路 ✅（已产出 `C:/Users/13682/dc-build/app/outputs/apk/debug/app-debug.apk`）**
- [x] Android 附近设备发现：BLE 扫描/广播（服务 UUID 过滤）+ 分版本权限 + Compose 子页
- [ ] Spike D：代理下 wss 连通性实测（pkarr 已废止，见 ARCHITECTURE-RISKS.md A1）；NDK + Rust 交叉编译（cargo-ndk）
- [x] 阶段 2：加密会话层 —— PQXDH 握手（Kyber-1024 + X25519，非原写的 X3DH）+ Double Ratchet 集成，另含 SAS 带外比对、TOFU pin、SQLCipher 持久化 store（`crates/core/src/handshake.rs`、`signal_store.rs`）
- [ ] 阶段 3-8：见 PLAN.md

## 构建命令速查（Android）

```bash
# 已配置：sdk.dir(local.properties) + 阿里云 Maven 镜像 + 腾讯 gradle 发行镜像
cd android
gradle assembleDebug      # 或 ./gradlew assembleDebug（wrapper 已指向国内镜像）
# 产物：C:/Users/13682/dc-build/app/outputs/apk/debug/app-debug.apk
# （android/app/build.gradle.kts 把构建目录迁出了工程树，故不在 app/build 下）
```

## 当前能力边界（实测）

- Rust 核心（`crates/core`）已有身份 / 熵源 / 信封 / 自适应 / 队列 / 中继 / Signal 会话（PQXDH + Double Ratchet + SAS + TOFU）、联系人落库（`contacts.rs`）与 iroh 传输层（`node.rs`），并配套单测。
- Android 侧聊天 / 联系人 / 消息 / 我的四页已接真实数据层（`ContactStore` 持久化），`NodeService` 宿主 `IrohNodeManager`，BLE 帧通道与好友回连在位（`BleMesh` / `FriendLink`）。
- 带外比对已闭环：扫码侧 `sasWith` + 出示侧经 `prekeySenderIdentity` 从首条 PreKey 消息取对方身份算 SAS。
- 以上均以代码调用点核对为准；**运行时端到端行为（真机互扫、跨 WiFi 收发）尚无自动化验证**，回归测试需在 CI 与真机实测补齐。
