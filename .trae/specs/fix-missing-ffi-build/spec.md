# 修复编译链断裂（合入 PR#10 + 本地生成 UniFFI 绑定）Spec

## Why

当前 HEAD（PR#12，`feat/ble-friendlink`）的 Android 代码依赖 PR#10 引入的 Rust FFI 面
（`ContactStore`/`Contact`/`ChatMessage`/`WireMessage`/`encrypt`/`decrypt`/`DcError.RemoteIdentityChanged`），
但 PR#10 从未合入；同时本地 UniFFI 绑定目录 `android/app/src/main/uniffi`（不入库，每次构建生成）
不存在。两者叠加导致 `compileDebugKotlin` 出现 40+ 个 Unresolved reference，项目整体无法构建——
即用户感知的「全是 bug、根本不能用」。诊断结论：Rust 侧代码本身健康（带 protoc 后 85 单测 + 1 集成全绿），
Android/Kotlin 侧代码也无需改动，唯一断点是**合并缺失 + 生成物缺失**。

## What Changes

- 合并 `origin/feat/ffi-error-contacts`（PR#10）到 `feat/ble-friendlink`
  （已用 `git merge-tree --write-tree` 预检：**零冲突**）
- 本地按 CI 同流程生成 UniFFI Kotlin 绑定：host cdylib → `uniffi-bindgen generate --library`
  → `android/app/src/main/uniffi`（生成物不入库，与 CI 行为一致）
- 验证链：`cargo test --workspace` → `gradlew :app:compileDebugKotlin` → `gradlew :app:testDebugUnitTest`
- 推送更新后的 `feat/ble-friendlink`（PR#12 将自洽包含 PR#10 全部改动，合并 PR#12 后 PR#10 自动完成）

## Impact

- Affected code：`crates/core`（新增 contacts.rs，ffi.rs/handshake.rs/lib.rs 增量——全部来自 PR#10 原样合入）
- Android 侧 Kotlin 源码**零改动**（编译错误全部由缺失的 FFI 面/绑定引起，非 Kotlin 代码缺陷）
- 环境前提：shell PATH 需含 `C:\Users\13682\msys64\mingw64\bin`（protoc，ENVIRONMENT.md 第 11 条已记载）

## Out of Scope

- 本地安装 Android NDK / 本地 `assembleDebug` 出 APK：CI 已有完整 cargo-ndk 三 ABI 流程出 APK；
  本地验证到 `compileDebugKotlin` + 单测即可（ENVIRONMENT.md 既定路径：NDK 阶段 4 真机再装）

## ADDED Requirements

### Requirement: PR#10 合入后 Rust 全量测试保持绿色

The system SHALL 在合并 PR#10 后保持 `cargo test --workspace` 全部通过（含 PR#10 新增的
contacts CRUD/错误分类测试）。

#### Scenario: 合并后测试

- **WHEN** 在 PATH 含 msys64 的 shell 中执行 `cargo test --workspace`
- **THEN** 全部测试通过（合并前基线 85+1，合并后应 ≥ 该数且 0 失败）

### Requirement: 本地 UniFFI 绑定生成

The system SHALL 能从本地编译的 host cdylib 生成 Kotlin 绑定到 `android/app/src/main/uniffi`，
且绑定包含 `ContactStore`/`Contact`/`ChatMessage`/`WireMessage`/`DcException.RemoteIdentityChanged`。

#### Scenario: 生成并检查符号

- **WHEN** 执行 `cargo build --lib -p dc-core --features ffi` 后运行 `uniffi-bindgen generate --library`
- **THEN** `src/main/uniffi` 下生成 `chat/dc/core/*.kt`，且源码可检索到上述符号

### Requirement: Android Kotlin 编译恢复

The system SHALL 使 `gradlew :app:compileDebugKotlin` 编译通过（0 error）。

#### Scenario: 编译验证

- **WHEN** 绑定已生成且 PR#10 已合入
- **THEN** `compileDebugKotlin` BUILD SUCCESSFUL，BleMesh.kt/SignalCore.kt/NodeService.kt 无 Unresolved reference

### Requirement: Android 本地单测通过

The system SHALL 使 `gradlew :app:testDebugUnitTest` 通过（BleFrameTest/FriendLinkTest 等纯逻辑测试）。

#### Scenario: 单测验证

- **WHEN** 编译通过后执行 `gradlew :app:testDebugUnitTest`
- **THEN** BUILD SUCCESSFUL，0 测试失败

### Requirement: 远端 PR 状态收敛

The system SHALL 将合并后的 `feat/ble-friendlink` 推送至远端，使 PR#12 自洽可评审。

#### Scenario: 推送

- **WHEN** 本地验证全绿
- **THEN** `git push origin feat/ble-friendlink`，PR#12 包含 PR#10 全部 commit
