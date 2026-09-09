# 盲区审计结果（2026-09-10，两遍）

> 范围：前两轮审计未深查的盲区 = IrohNodeManager + UI 四页 + Common.kt + 发布构建配置。
> 基线：`docs/APP-OVERVIEW.md`（设计红线、已知台账 P0-1…P2-8 不重复报）。
> **重要方法学修正**：第一遍由主理人"读基线后"核验，结论偏乐观（多处判为干净）；第二遍按用户要求派**不读基线文档**的独立 Explore 重扫，结果推翻了第一遍的多处结论——证明基线文档会把人锚定。以下以第二遍（独立盲扫）为准。

## 一、发布构建配置（审计第 3 块）—— 已结案，无需修复

- `Release 混淆验证` = 裸跑 `./gradlew assembleRelease`（`.github/workflows/build.yml:152-153`），无独立"是否真混淆"脚本；CI 失败即 R8 阶段退出。
- 已知根因（release 首调 JNA/UniFFI 崩溃，缺 `chat.dc.core.**` keep）**已在树修复**：提交 `976e311`，是当前 HEAD `2207026` 的祖先（`git log` 确认）。
- 三次失败（`4888fbb`/`b307ee4`/`7a195a3`）是 force-push 瞬态；含修复那次 CI 反为 success。
- 独立扫确认 `proguard-rules.pro:12-17` keep 规则正确、`build.gradle.kts` 配置正确。
- ⚠️ 唯一未坐实：HEAD `2207026` 的 CI run 卡 `in_progress` ~8.5h（疑似 runner 卡死）；且 `build.yml` 的 `actions/checkout@v5`/`setup-java@v5` 版本号、NDK 未固定（`build.yml:43-53`）属 CI 脆弱点，待核但非代码缺陷。

## 二、IrohNodeManager.kt（审计第 1 块）—— 发现真缺陷

- 世代守卫 `startGen`（`IrohNodeManager.kt:63-67,82-156`）扎实，启动/停止竞态已正确隔离（git 4e7e365）。✅
- **缺陷 B（高/存疑→已转工程师验证）**：`onMessage`（`IrohNodeManager.kt:90-98`）由 iroh tokio worker 线程回调，体内同步执行 `listContacts()`（SQLite 全表读）+ `BleMesh.deliverRemote`→`decryptAndStore`（`BleMesh.kt:583-594`，`session.decrypt()` 与 `appendMessage()`）。阻塞仅 2 个 worker 的 reactor，且 `ContactStore`/`SignalSession` 为进程单例，跨线程 SQLite 访问有数据竞争风险。修复方向：把回调体改到 `Dispatchers.IO` 协程执行。
- **缺陷 C（中，随 B 改）**：`IrohNodeManager.kt:94-96` 每条入站消息 `listContacts().firstOrNull{...}` 全表线性反查，与 B 叠加。
- **缺陷 D（中/存疑）**：`BleMesh.kt:478-483` 配对早于 iroh `onReady` → `state.value.naddr` 为空 → 握手退化 `"dc-hs"` → 该联系人永久无跨网快照。设计容许降级，但后果重，已转工程师核实时序窗口。

## 三、UI 四页 + Common.kt（审计第 2 块）—— 部分真缺陷

| 页面 | 排查点 | 结论（独立盲扫） |
|---|---|---|
| ChatScreen.kt | 发送后滚动 | **缺陷 A（确定）**：`LaunchedEffect(messages.size)` 在 `ChatScreen.kt:82-84` 无条件 `scrollToItem(size-1)`；入站消息使 size 变化即把列表拽回底部，**打断用户上翻历史浏览**。第一遍误判为正常。应改为"仅当用户已贴近底部才自动跟随" |
| ChatScreen.kt | 时间戳/长消息 | 干净（`HH:mm` 经 `remember` 缓存；`widthIn(0.78)` 换行正常） |
| ContactsScreen.kt | 在线点判定 | 干净：`peers[identityHex]` 与填充 key 均小写两位无分隔 hex，一致；仅 BLE 在位时亮（设计） |
| MessagesScreen.kt | 列表/搜索/返回刷新 | 干净 |
| MeScreen.kt | 设置是否全死 | 干净：节点/存储/关于均接真数据（红线"空态优先"非 bug） |
| MeScreen.kt | 二维码入口 | **缺陷 E（低/存疑）**：资料卡 `QrCode2`（`MeScreen.kt:121-134`）`clickable` 绑 `onOpenAddFriend`，语义上应是展示本人二维码，疑误绑 |
| 导航 contactId | 来源/非法 id | 干净：`MessagesScreen:158` 传 `chat.peer`、`ContactsScreen:112` 传 `c.name`，与 `incoming.peerName` 同源；非法 id → 空列表/不崩溃 |
| Common.kt | 通用组件 | 干净 |

## 四、已转修复工程师的缺陷单

| 单 | 严重度 | 文件:行 | 一句话 |
|---|---|---|---|
| A | 中/确定 | ChatScreen.kt:82-84 | 入站消息无条件滚到底部，打断历史浏览 |
| B | 高/存疑 | IrohNodeManager.kt:90-98 → BleMesh.kt:583-594 | iroh 网络线程同步 SQLite+解密，阻塞 reactor + 跨线程竞争 |
| C | 中 | IrohNodeManager.kt:94-96 | 每条消息全表 listContacts 反查 |
| D | 中/存疑 | BleMesh.kt:478-483 | 配对早于 onReady → 联系人永久无跨网快照 |
| E | 低/存疑 | MeScreen.kt:121-134 | 本人二维码入口误绑加好友页 |

工程师纪律：先现场验证 → 最小变更修复（中文注释）→ 回报 diff+实际代码文本；设计边界先回报不动手；分支 `workbuddy` 禁止 git 写。

## 五、总判定

- **第一遍（读基线）误判盲区"干净"；第二遍（独立盲扫）发现 5 处真缺陷**，印证"不读锚定文档"的价值。
- 第 3 块（构建配置）确为 force-push 瞬态失败、已在树修复，无需改代码。
- 5 张单已转修复工程师，待其回报 diff 后由主理人统一提交。
