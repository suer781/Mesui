# UI 设计规范（理念提炼 + 落地映射）

> 来源：Telegram（速度/极简/安全三原则）、ColorOS 水生设计（色阶分层、大圆角、
> 涟漪动效、动态取色双原色）、微信/QQ NT/飞书（卡片化收纳、清晰信息层级）、
> 抖音/豆包（沉浸式、大标题）。只借鉴公开设计理念，不使用任何私有资产。

## 原则 → 落地映射

| # | 原则 | 出处 | 本项目落地 |
|---|---|---|---|
| P1 | 速度感：转场干脆、主线程零重活 | Telegram | NavHost 统一 200ms 淡入+轻移；QR 编码在 Default 线程 |
| P2 | 极简 chrome：无框线、次要信息小字弱色 | Telegram | 输入框聚焦前无边框；副标题 onSurfaceVariant |
| P3 | 色阶分层，不靠描边阴影 | ColorOS 水生 | 容器色（surfaceVariant/primaryContainer）表达层级；卡片 20dp 大圆角 |
| P4 | 留白 4dp 网格、内外边距统一 | ColorOS | 页边 16dp、卡内 12dp、行距 10dp 全局一致 |
| P5 | 动效真实灵动（涟漪/流动） | ColorOS | clickable 默认涟漪保留；列表增减 animateItem；发送后滚动到底 |
| P6 | 动态取色双原色（日出蓝/日落橘 精神） | ColorOS | Material You primary→tertiary 渐变头像/入口卡 |
| P7 | 沉浸式内容优先、大标题 | 抖音/豆包 | enableEdgeToEdge + headlineMedium 页标题 + 键盘 imePadding |
| P8 | 卡片化收纳、信息分组 | QQ NT/飞书 | 我的页 SectionCard、联系人入口卡 |

## 组件规则

- 列表页整页滚动用 LazyColumn（头内容作 item），**禁止** verticalScroll 嵌 LazyColumn
- 语义重名用 testTag 消歧；所有可交互元素必须有 testTag（Robolectric 验收依赖；
  Kotlin 单测已入 CI `testDebugUnitTest`）
- ~~演示数据集中在 ui/DemoData.kt，核心接入后整文件退役~~ **DemoData.kt 已删除**；
  四页（消息/联系人/聊天/我的）全部读真实 SQLCipher 数据，空态仍优先（无数据即空态，
  不造演示条目）
- 重活全部离主线程：QR 编码在 `Dispatchers.Default`（自适应帧率节拍器）；
  `MeScreen`/`NodeService` 的会话初始化（SQLCipher 首开含 KDF）在 IO 线程——
  组合期同步开库会掉帧/ANR，属回归红线
