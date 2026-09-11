# 第三方组件与许可证声明

本软件以 AGPL-3.0-or-later 许可发布。以下为主要第三方组件及其许可证。

## Rust 核心

| 组件 | 用途 | 许可证 | 来源 |
|---|---|---|---|
| libsignal-protocol / libsignal-core | Signal 协议（PQXDH、Double Ratchet） | AGPL-3.0-only | signalapp/libsignal @ eb7864c（vendored 浅抓取） |
| SparsePostQuantumRatchet (spqr) | 后量子棘轮（libsignal 依赖） | 见其仓库 | signalapp/SparsePostQuantumRatchet v1.5.3 |
| iroh | P2P QUIC 连接/打洞/中继 | MIT OR Apache-2.0 | n0-computer/iroh 1.1 |
| iroh-relay / iroh-base 等 | iroh 生态 | MIT OR Apache-2.0 | 同上 |
| zstd | 压缩 | MIT OR Apache-2.0 | gyscos/zstd-rs |
| rusqlite + SQLCipher | 加密本地存储 | MIT / BSD-style（各依其上游） | rusqlite 0.32 + SQLCipher |
| blake3 | 哈希（1024 位 XOF） | CC0-1.0 / Apache-2.0 / Apache-2.0 with LLVM exception | BLAKE3 team |
| ed25519-dalek | 签名 | BSD-3-Clause | dalek-cryptography |
| getrandom | 内核 CSPRNG 接口 | MIT OR Apache-2.0 | rust-random |
| ciborium | CBOR 序列化 | Apache-2.0 | dvc94ch/ciborium |
| serde / serde_json | 序列化框架 | MIT OR Apache-2.0 | serde-rs |
| thiserror | 错误派生 | MIT OR Apache-2.0 | dtolnay |
| tokio | 异步运行时 | MIT | tokio-rs |
| prost-build（构建期） | protobuf 编译 | Apache-2.0 | tokio-rs/prost |
| uniffi | Kotlin 绑定生成 | MPL-2.0 | mozilla/uniffi-rs |

## Android 侧（实际使用）

| 组件 | 用途 | 许可证 |
|---|---|---|
| Jetpack Compose / Material 3 | UI | Apache-2.0 |
| zxing core（3.5.3）+ zxing-android-embedded（4.3.0, journeyapps） | 二维码生成与扫描 | Apache-2.0 |
| JNA（net.java.dev.jna:jna 5.13.0 @aar） | UniFFI Kotlin 绑定的原生桥 | Apache-2.0 或 LGPL-2.1（双许可，随 UniFFI 默认后端采用 Apache 路径） |
| kotlinx-coroutines | 协程 | Apache-2.0 |
| Robolectric（测试期） | JVM Android 模拟测试 | MIT |
| Briar（蓝牙实现参考，不直接复制代码时无需遵守；若复制则 AGPL-3.0 与本项目兼容） | 蓝牙保活/前台服务策略参考 | AGPL-3.0 |

> 完整传递依赖清单由 `cargo license` / Gradle 许可报告在发布流程中自动生成后替换本文件。
