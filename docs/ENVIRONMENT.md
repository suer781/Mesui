# 开发环境备忘（Windows 10, 本机实测）

> 本文档记录 2026-09-04 搭建过程中的全部环境坑位与解法。换机器时按此清单操作。

## 工具链清单

| 组件 | 版本 | 安装方式 | 备注 |
|---|---|---|---|
| Rust (x86_64-pc-windows-gnu) | 1.98.1 | rustup-init.exe 静默安装 | **GNU 工具链**，因 VS Build Tools 的 UAC 提权无人值守会失败 |
| MSYS2 (便携) | 2026-06-11 sfx | USTC 镜像 `distrib/x86_64/msys2-base-x86_64-*.sfx.exe` | `sfx.exe -y -o"C:/Users/13682/"` 解压即用，无需管理员 |
| mingw-w64 gcc | 16.2.0 | `pacman -Sy mingw-w64-x86_64-gcc` | 提供 gcc/dlltool/binutils |
| Java | OpenJDK 21 (Microsoft) | 预装 | Gradle/Android 可用 |
| Android SDK/NDK | 未安装 | 待装（Android Studio 或 sdkmanager） | 阶段 1 Android 构建前必须 |

## 踩坑记录（按遇到顺序）

1. **winget 源连接失败**（InternetOpenUrl 0x80072EFF）→ 不用 winget，直接 curl 微软/TUNA CDN。
2. **VS Build Tools 静默安装失败**：`User may have declined UAC prompt`（0x80070642）——
   无人值守会话无法响应 UAC。解法 = 改用 GNU 工具链 + MSYS2 gcc，全程免提权。
3. **GitHub 全量 clone 被 GFW 限速拖死**（libsignal 数百 MB）→ 浅抓取锁定 commit：
   `git init && git remote add origin <url> && git fetch --depth 1 origin <rev> && git checkout --detach FETCH_HEAD`
   （GitHub 支持 fetch-by-SHA）。HEAD 哈希 = 信任锚，篡改必破哈希链。
4. **cargo 对 git 依赖即使 feature 关闭也会解析** → libsignal 改为 path 依赖指向 third_party/。
5. **嵌套工作区继承被外层接管**：libsignal 的 `authors.workspace = true` 报
   `workspace.package.authors was not defined` → 我们的 `[workspace]` 加
   `exclude = ["third_party"]`（标准解法）。
6. **GNU ld 打不开含中文路径的 object 文件**（GBK/UTF-8 错位）→ `.cargo/config.toml`
   设 `target-dir = "C:/Users/13682/cargo-target/dc-chat"`（纯 ASCII）+ `linker = "rust-lld"`。
7. **杀毒软件拦截新建的 build-script 可执行文件**（os error 5 拒绝访问）→
   构建期间关闭实时防护，或给 target 目录加白名单。
8. **windows-gnu 缺 dlltool**（getrandom 等 crate 链接失败）→ MSYS2 装
   mingw-w64-x86_64-gcc（含 binutils/dlltool），并把 `msys64/mingw64/bin` 与
   `msys64/usr/bin` 加入 PATH。
9. **pacman 镜像 404/403**：MSYS2 的 `mirrorlist.<repo>` 一仓库一文件，且 `$arch`
   变量不展开（至少本机如此）→ 全部硬编码 `x86_64`，六仓库都写对：
   msys→`msys/x86_64/`，其余→`mingw/<环境>/`。USTC/NJU 可用，TUNA 会 403。
10. **cargo 输出被管道吞掉退出码** → 用 `${PIPESTATUS[0]}` 判断真实结果，
    否则 `| tail` 永远 exit 0。
11. **libsignal 依赖 SparsePostQuantumRatchet（后量子棘轮）需要 `protoc`** →
    `pacman -S mingw-w64-x86_64-protobuf`（进 /mingw64/bin，PATH 内自动被找到）。
12. **iroh/iroh-relay 官方 crate-type 含 `cdylib`，windows-gnu 下 PE 导出表 65535 上限**
    （iroh-relay 导出 6.7 万符号）链接失败 → vendored 两 crate 至 third_party/，
    crate-type 改为仅 `["lib"]`，经 `[patch.crates-io]` 接入（源码零改动）。
13. **装好真 gcc 后弃用 rust-lld**：rust 自带 self-contained CRT 与 MSYS2 运行时
    混用产生 `__mingw_oldexcpt_handler` 等未定义符号 → linker 改回
    `x86_64-w64-mingw32-gcc`（CRT 一致；中文路径问题已由 ASCII target-dir 解决）。
14. **std `SocketAddr` 没有 `is_loopback`**（只有 `ip()`/`is_ipv4/is_ipv6`；
    `is_loopback` 在 `IpAddr` 上）→ 用 `a.ip().is_loopback()`。
15. **Android SDK 免 Android Studio 安装**：dl.google.com 被墙，sdkmanager 不可用 →
    腾讯镜像 `mirrors.cloud.tencent.com/AndroidSDK/` 手动下组件 zip 解包到
    `%LOCALAPPDATA%\Android\Sdk`（cmdline-tools→cmdline-tools/latest、
    platform-35_r02.zip→platforms/android-35、build-tools_r34→build-tools/34.0.0）；
    许可证手写到 `$SDK/licenses/`（android-sdk-license 含 24333f8a63b6825ea9c5514f83c2829b004d1fee 等 hash）。
16. **Maven 仓库**：`maven.aliyun.com/repository/google` + `/public`（google() 原源被墙）；
    组合 AGP 8.7.3 + Gradle 8.10.2（腾讯镜像）+ JDK 17/21 实测通过。
17. **local.properties 的 sdk.dir 必须正斜杠**：`C\:` 后的 `\U` 等会被 properties
    转义规则吞掉 → AGP 报「文件名、目录名或卷标语法不正确」（极易误诊为中文路径问题）。
18. **AGP 中文路径**：junction 骗不过 Gradle 的 canonicalPath 检查（会解析回真实路径）；
    `android.overridePathCheck=true` 后 aapt2/d8 全链路实测可过。
19. **gradle wrapper 生成**会先校验 services.gradle.org（被墙）→
    `gradle wrapper --gradle-distribution-url <腾讯镜像URL>` 跳过官方源校验。
20. **构建产物**：`android/app/build/outputs/apk/debug/app-debug.apk`（16MB，debug 签名）；
    NDK 尚未安装（Rust 交叉编译阶段再从腾讯镜像取 android-ndk-r28b-windows.zip）。
21. **Gradle 测试 worker CNFE 之谜**（编码墙之四）：daemon→worker 的 classpath 经
    **@argfile** 传递，`java.exe` 的 C 启动器在 JVM 启动前按系统 ANSI(GBK) 解码该文件
    → classpath 里的中文路径（项目 build 目录）全部变乱码 → 所有测试类 CNFE，
    而 ASCII 的缓存 jar 正常。jvmArgs/联接路径均无效（Gradle 会规范化回真实路径）。
    **解法**：`layout.buildDirectory.set(File("C:/Users/13682/dc-build/app"))` 把构建
    目录迁到纯 ASCII；从 ASCII 联接路径 `C:\Users\13682\dc-chat\android` 执行构建。
    诊断手法：`test.doFirst { println(test.classpath.files) }` +
    `--info` 抓 worker 启动命令行看 @argfile。
22. **Robolectric + navigation-compose 转场**：动画在测试时钟下不结束，导航后的
    节点「存在但 display=false」→ 流程断言用 `assertExists`，「显示」只在静止
    元素（底栏）上断言；语义重名（tab 标签=页面标题）用 `testTag` 消歧。

## 构建命令速查

```bash
export PATH="/c/Users/13682/msys64/mingw64/bin:/c/Users/13682/msys64/usr/bin:$USERPROFILE/.cargo/bin:$PATH"

# 纯逻辑层（无 C 依赖）
cargo test --no-default-features

# 全量（libsignal + iroh + SQLCipher + zstd）
cargo check && cargo test
```

## 国内网络可达性速查（本机实测）

| 资源 | 可达性 |
|---|---|
| static.rust-lang.org / index.crates.io / static.crates.io | ✅ |
| github.com（git 协议 ls-remote / 浅 fetch） | ✅（全量 clone 慢/超时） |
| raw.githubusercontent.com（本地 curl） | ❌ RST（WebFetch 后端通道不受影响） |
| cdn.jsdelivr.net / mirrors.ustc.edu.cn / mirror.nju.edu.cn | ✅ |
| mirrors.tuna.tsinghua.edu.cn | ⚠️ 文件可下，目录列表与部分路径 403 |
| gnu.org / docs.rs（本地） | ❌ |
| release-assets.githubusercontent.com（GitHub Releases） | ✅ |
