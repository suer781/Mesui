# UniFFI 生成的 JNI 符号不参与混淆/优化
-keep class chat.dc.app.** { *; }
-keep class uniffi.** { *; }
-dontwarn uniffi.**
