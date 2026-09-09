# Checklist

- [ ] PR#10（feat/ffi-error-contacts）已合并进 feat/ble-friendlink，工作区无冲突残留
- [ ] crates/core/src/contacts.rs 存在，ffi.rs 导出 ContactStore/Contact/ChatMessage/WireMessage/DcError::RemoteIdentityChanged
- [ ] `cargo test --workspace`（PATH 含 msys64）0 失败
- [ ] android/app/src/main/uniffi 下生成 chat/dc/core/*.kt，含 ContactStore/WireMessage/RemoteIdentityChanged 符号
- [ ] `gradlew :app:compileDebugKotlin` BUILD SUCCESSFUL（BleMesh/SignalCore/NodeService 无 Unresolved reference）
- [ ] `gradlew :app:testDebugUnitTest` BUILD SUCCESSFUL，0 测试失败
- [ ] feat/ble-friendlink 已推送，PR#12 包含 PR#10 全部 commit
