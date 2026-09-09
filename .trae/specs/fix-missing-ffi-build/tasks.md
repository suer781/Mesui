# Tasks

- [ ] Task 1: 合并 PR#10 分支到 feat/ble-friendlink
  - [ ] SubTask 1.1: `git merge origin/feat/ffi-error-contacts --no-ff`（merge-tree 已预检零冲突）
  - [ ] SubTask 1.2: 确认 crates/core 下出现 contacts.rs，ffi.rs 含 ContactStore/encrypt/decrypt/WireMessage 导出
- [ ] Task 2: Rust 全量验证
  - [ ] SubTask 2.1: PATH 含 msys64 执行 `cargo test --workspace`，全部通过（0 failed）
- [ ] Task 3: 生成 UniFFI Kotlin 绑定
  - [ ] SubTask 3.1: `cargo build --release --lib -p dc-core --features ffi`（host cdylib）
  - [ ] SubTask 3.2: `uniffi-bindgen generate --library target/release/dc_core.dll --config crates/core/uniffi.toml --language kotlin --out-dir android/app/src/main/uniffi`
  - [ ] SubTask 3.3: 检查生成物含 ContactStore/Contact/ChatMessage/WireMessage/RemoteIdentityChanged
- [ ] Task 4: Android 编译验证
  - [ ] SubTask 4.1: `gradlew :app:compileDebugKotlin` BUILD SUCCESSFUL
- [ ] Task 5: Android 本地单测
  - [ ] SubTask 5.1: `gradlew :app:testDebugUnitTest` BUILD SUCCESSFUL，0 失败
- [ ] Task 6: 推送远端
  - [ ] SubTask 6.1: `git push origin feat/ble-friendlink`，确认 PR#12 更新且包含 PR#10 commits

# Task Dependencies

- [Task 2] depends on [Task 1]
- [Task 3] depends on [Task 1]
- [Task 4] depends on [Task 3]
- [Task 5] depends on [Task 4]
- [Task 6] depends on [Task 2, Task 5]

# 备注

- 全程 shell 需 `$env:PATH = "C:\Users\13682\msys64\mingw64\bin;C:\Users\13682\msys64\usr\bin;" + $env:PATH`（protoc/gcc）
- Windows host cdylib 产物为 `dc_core.dll`（CI 是 libdc_core.so，路径按本机调整；CARGO_TARGET_DIR 为 .cargo/config.toml 配置的 `C:/Users/13682/cargo-target/dc-chat`）
- 本地 NDK / assembleDebug 出 APK 不在本次范围（CI 负责出 APK）
