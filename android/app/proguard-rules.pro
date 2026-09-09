# 应用自身代码不参与混淆/优化
-keep class chat.dc.app.** { *; }
-keep class uniffi.** { *; }
-dontwarn uniffi.**

# UniFFI 生成的 Kotlin 绑定实际位于 chat.dc.core 包（见 src/main/uniffi/chat/dc/core/dc_core.kt），
# 而非 uniffi.** 包——上面的 uniffi 规则是死规则，漏 keep 此包会导致 R8 重命名：
# 1) JNA Structure 子类（如 UniffiRustCallStatus）的 @JvmField 字段被反射映射 native 内存布局；
# 2) UniffiLib 接口方法按名字匹配 native 符号。
# 两者任一被混淆，release 包首次调用核心（SignalCore.session / ContactStore.open / IrohNode.start）
# 即抛 UnsatisfiedLinkError 或 struct 字段错位崩溃（debug 不开混淆故不复现）。
-keep class chat.dc.core.** { *; }
-keepclassmembers class chat.dc.core.** { *; }

# 兜底 keep JNA 运行时：项目依赖 jna:5.13.0@aar，其自带 consumer 规则是否完整存疑，
# 此规则成本为零，防止 JNA 内部反射被 R8 裁剪。
-keep class com.sun.jna.** { *; }
