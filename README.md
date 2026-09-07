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
| 端到端加密 | signalapp/libsignal（官方 monorepo，git 锁 commit） | 完整 X3DH + Double Ratchet |
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
android/           Android 工程（Jetpack Compose，待 Android SDK 就绪）
docs/PLAN.md       批准实施的完整方案
LICENSE            AGPL-3.0
```

## 构建与测试

```bash
# 纯逻辑层（无需 MSVC/NDK）
cargo check --no-default-features
cargo test  --no-default-features

# 全功能（需 VS Build Tools：SQLCipher/zstd 的 C 代码）
cargo test
```

## 开发状态

- [x] 阶段 0：工程骨架 + 环境搭建（Rust GNU + MSYS2 gcc + Android SDK 命令行版，全程免提权免 Android Studio，详见 docs/ENVIRONMENT.md）
- [x] 核心纯逻辑层：身份/熵源/信封/自适应引擎/加密队列/设置 —— **26 项单测全绿**
- [x] Spike A ✅：signalapp/libsignal 官方 monorepo（锁定 commit eb7864c，vendored）构建链接成功
- [x] Spike B ✅：iroh 两 endpoint 进程内按公钥对连、QUIC 双向流互发成功
- [x] Spike C ✅：UniFFI 脚手架编译通过；**APK 构建链路 ✅（app-debug.apk 已产出）**
- [x] Android 附近设备发现：BLE 扫描/广播（服务 UUID 过滤）+ 分版本权限 + Compose 子页
- [ ] Spike D：代理下 wss 连通性实测（pkarr 已废止，见 ARCHITECTURE-RISKS.md A1）；NDK + Rust 交叉编译（cargo-ndk）
- [ ] 阶段 2：加密会话层（X3DH 握手、Double Ratchet 集成）
- [ ] 阶段 3-8：见 PLAN.md

## 构建命令速查（Android）

```bash
# 已配置：sdk.dir(local.properties) + 阿里云 Maven 镜像 + 腾讯 gradle 发行镜像
cd android
gradle assembleDebug      # 或 ./gradlew assembleDebug（wrapper 已指向国内镜像）
# 产物：app/build/outputs/apk/debug/app-debug.apk
```
