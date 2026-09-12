# 架构风险登记（2026-09-04 架构复审）

> 复审范围：v8 方案全部设计文档 + crates/core 全部源码 + Android 工程。
> 结论：发现两个架构级问题（A1、A2）与三处文档/实现缺口（A3–A5）。
> **处置决议（2026-09-04 用户确认）：A1 → 可轮换节点密钥方案；A2 → 隐私群/效率群分立。
> 两者已并入 PLAN.md v9；A3/A4 列入阶段 5 待办。（2026-09-11 更新：A3 已落地、
> A5 已随 pkarr 废止消解、A4 部分落地，见各节状态标注。）**

## A1 🔴 身份公钥 = 节点 ID + 公共发现服务 → 全局「公钥→IP」映射

**现状设计**：PLAN.md「身份密钥即 iroh 节点 ID」+「各节点把寻址信息发布到 pkarr/DHT，
联系人凭公钥即可找到对方」。

**问题**：
1. pkarr/DHT 发布内容 = 节点 ID → 当前 IP/中继地址，**无鉴权公开可查**。
   任何拿到你长期公钥的一方（联系人/中继/群成员/信箱桶/转发泄露）可永久追踪你的
   网络位置（换网/换城市/VPN 开关全部可见）。
2. pkarr 发布实际依赖 n0 运营的 `dns.iroh.link` —— 与「无强制目录服务器、无强制
   DNS」的第一原则**自相矛盾**，发现路径当前是中心化的。
3. GFW 视角：参与公共发现系统的流量本身是高价值指纹。
4. 威胁模型原文（「默认模式不承诺元数据匿名，仅时序可分析」）**低估了实际暴露面**：
   本设计是主动公开位置，不是被动可分析。

**修复方向（待定稿）**：发现身份与长期身份解耦——
- 长期 Signal 身份密钥永不进入任何发现系统
- 节点用可轮换临时密钥（per-epoch transport key）对外发布
- 广域寻址改为「加密介绍信」沿联系人 Signal 会话链传递（仅联系人图谱可查）
- mDNS 近场发现保持现状；代价：冷启动/换网后首连变慢，需 ≥1 条联系人链或近场碰面

## A2 🔴 群聊双特性协议层互斥：「选择性可见」vs「自适应切 MLS」

**现状设计**：同一套群既要求「长按选可见成员，未选中者零数据包」（pairwise 语义），
又要求「中载自动切 OpenMLS」（MLS 语义）。

**问题**：
1. MLS 对群树整树加密一次，树内成员人人可解；排除成员 = 每次发送做子群 rekey，
   开销与复杂度不可行。
2. 群规模/速率触发自适应后，招牌功能静默失效；反之保功能则 MLS 不可用。
3. PLAN.md「切换时端到端加密语义不变」对**通道切换**成立，对**加密档位切换**
   不成立——pairwise→MLS 是需要全群 rekey 的协议迁移，不是状态机换挡。

**修复方向**：群分两类——隐私群（pairwise，人数上限，保留选择性可见）
与效率群（MLS，无选择性可见）；自适应引擎只管传输通道，不再切换加密协议。
允许**隐私群 → 效率群 单向转换**：任一群成员发起（群无角色体系，不引入
管理员概念），在线成员即时确认并完成 MLS 加入；离线成员经信箱异步公告
（附 mailbox secret 的 HMAC 证明，同 B1–B5 约束），上线时由任意已入树
成员替其完成 MLS Add+Commit。过渡期（尚有成员未入 MLS 树）群消息
**双写**：pairwise 逐成员单发与 MLS 整树加密并存，全员入树后结束。
转换后选择性可见功能永久丧失；**不允许反向转换**——技术上旧 pairwise
会话仍在、可重建逐成员加密，但反向转换会让元数据重新暴露给中继、功能
语义反复摇摆，故属产品/隐私策略层面的永久禁止（实现不复原任何 pairwise
群状态）。

## A3 🟡 n0 公共中继「构建时移除」未落地 → ✅ 已落地（2026-09，GLM-Zcode）
~~文档承诺移除 iroh 默认 n0 中继，代码未实现（spike 测试使用 `presets::N0`）。~~
已修：`node.rs` 端点以 `presets::Minimal` 构建（无 n0 DNS 发现/默认中继）；
未配置自建中继 URL 时 `RelayMode::Disabled`，配置后 `RelayMode::custom([url])`。
中继 URL 由用户在「节点服务」面板配置。

## A4 🟡 队列表无限增长 → 🔶 部分（原语已备，清理调度未接）
`inbox_seen` 有 `prune_seen()` 裁剪原语（注释强制保留窗口 ≥7 天）；outbox 死信
清理仍缺。~~「数据与存储」设置仅有模型未接逻辑~~——「我的」页存储面板已显示
dc-signal.db / dc.dbkey / dc.nodekey 真实大小。剩余：清理策略接线（注意：清理
inbox_seen 会放松去重窗口，需与 TTL 联动）。

## A5 🟡 发现路径的中心化依赖未在文档标注 → ✅ 已消解
「pkarr/DHT」方案已整体废止（A1 决议），n0 依赖随之消失；现行发现路径
（QR/配对握手携带 dc://node 快照、BLE 布隆广播）无任何中心目录，PLAN.md
第一原则处已如实标注。

---

# 第八轮：台账清账与安全修复落地（2026-09-07 ~ 2026-09-11，GLM-Zcode 分支）

| 项 | 状态 | 证据 |
|---|---|---|
| P0-1 BLE AUTH 32/33 契约 | ✅ 已修（`befb1d8`） | BleMesh.kt IDENTITY_LEN=33 全流程引用 + Rust 33 契约回归测试 |
| P0-2 contacts.rs 拒 33 | ✅ 已修（`f06df7b`） | upsert 接受 33（32 兼容），33 原样往返测试 |
| P1-1 TOFU pin 静默换钥 | ✅ 已修（`7a195a3`） | signal_store save_identity 异钥拒绝 + 旧记录保留测试 |
| iroh 启动失败无自愈 | ✅ 已修（`b307ee4`） | IrohNodeManager 5s/15s/45s 退避 + 世代守卫（`4e7e365`） |
| 前台服务 5 秒死线/销毁后复活 | ✅ 已修（`cff51c6`/`2207026`） | NodeService 先占位后初始化 + 步骤边界取消 |
| MeScreen 主线程开库 | ✅ 已修（`4888fbb`） | LaunchedEffect + IO 线程 |
| 盲区审计 A/B/C/D/E | ✅ 已修（`c58d466`/`d07a458`） | 滚动跟随、iroh 回调投 IO、nodeIdIndex 缓存、naddr 等待、QR 入口直达 |
| A3 n0 中继移除 | ✅ 已落地 | node.rs presets::Minimal（见上） |
| Release R8 混淆验证 | ✅ CI 已加 | assembleRelease 步骤 + proguard keep `chat.dc.core`（`976e311`/`dbd0dde`） |

仍开放：A4 清理调度接线、P1-3/P1-4/P2-1/P2-2/P2-3 等（台账见
docs/APP-OVERVIEW.md 第五节）。

## 已接受的剩余风险（复审确认，维持原判）
- 中继运营者可见「节点 ID 对 + 时序」，不可见内容（威胁模型已声明）
- 冷启动需自建中继/邀请节点（去中心化固有代价，UI 引导）
- UDP 被 QoS/封锁 → wss:443 兜底（已内建）
- 手机节点机会性在线，稳定中继推荐自建 iroh-relay（互补）
- **B6** 联系人节点代缓存的节点公告构成历史轨迹快照（设备查扣+解密后可见联系人
  过去地址）；缓解：公告短有效期 + 及时删除；信箱模型固有代价（SimpleX 同）

---

# 第二轮复审（2026-09-04，攻击者视角，聚焦 v9 新设计与近场协议）

## B1 🔴 信箱桶无写入/读取鉴权规格
按收件人节点 ID 分桶 + 任何人可写 = 存储灌注攻击（塞爆联系人信箱）与桶存在性/
增长时序探测。**修复**：Signal 握手时为每对联系人派生 mailbox secret（HKDF），
写桶必须附 HMAC 证明，中继只验 HMAC 不解内容；读取鉴权同源。列入阶段 5 协议规格。

## B2 🔴 节点密钥轮换分发协议缺失（v9 A1 修复方案自身遗留）
轮换后联系人如何得知新节点密钥？信箱桶按节点密钥寻址，旧桶悬挂 → 联系人失联。
**修复协议**：轮换公告由长期身份密钥签名（可验证）→ 推送至所有联系人信箱并由其
节点代缓存 → 旧节点密钥保留 N 天只读过渡窗 → 彻底失联走重新介绍信。
列入阶段 5 协议规格。

## B3 🟠 NFC→蓝牙流程未规定「token 绑定蓝牙信道认证」
物理在场 ≠ 无中间人（附近可有伪造广播设备抢连）。**修复**：首条蓝牙消息必须含
NFC token 派生的密钥确认（token 即带外秘密），安全码核对在添加流程中强制展示。
列入阶段 3 协议规格。

## B4 🟠 BLE 广播泄露手机蓝牙名（已修）
`setIncludeDeviceName(true)` → `false`（服务 UUID 足够过滤；设备名常含真名）。
代码已改并重新打包验证。

## B5 🟡 协议卫生约束（写入规格）
- NFC bootstrap token 单次有效，HCE 仅在加好友流程期间开启
- 消息 sent_at_ms 仅作显示排序，不得作为任何安全判定输入（设备时钟可调）

## 第二轮复审后状态
B1/B2/B3 已立项为对应阶段协议规格；B4 已修复；B5/B6 记录在案。
待办集中在阶段 3（NFC/蓝牙协议规格）与阶段 5（信箱鉴权 + 轮换协议）。

---

# 第三轮处置（2026-09-04，微信支付安全模式移植）

用户要求参考微信支付的安全做法后，B1/B2 的修复已从「规格立项」升级为
「代码原语 + 正式规格」：`mailbox.rs`（SP-1 信箱门禁）、`nodekey.rs`
（SP-2 轮换公告 + 密钥环）共 12 项新测试全绿，clippy 零警告；
完整规格与微信支付机制映射见 [SECURITY-PROTOCOL.md](SECURITY-PROTOCOL.md)。
关键教训：微信自研 mmtls 被 Citizen Lab 审出魔改 TLS 1.3 引入的弱点——
反证本项目「不自研密码协议」红线正确，只移植其工程模式（serial 选钥、
规范化签名串、±5 分钟重放窗、AEAD 上下文绑定、风控限速、双因子兜底）。

---

# 第四轮：全面审查 + 线上方案对照（2026-09-04）

**本地审查结论**：35+1 测试全绿、clippy 0、非测试库代码零 unwrap、零 TODO/FIXME、
APK 可复现构建；修复 3 处文档残留（README/PLAN 中已废止的 pkarr 表述）。

**线上对照结论**（详见会话报告）：
- iroh 1.1.0 即 crates.io 最新版，无更新可取；libsignal 内含 SPQR 后量子棘轮
  （已在编译树），对标 SimpleX v5.6+ 的 PQ 混合不落后
- BitChat（开源）验证了 BLE 广播发现路线；其 Nostr 公共中继兜底违反本项目零中心
  原则，不采纳；其 BLE mesh 泛洪与 A2/用户决议的「直连+牵手」是不同取舍
- SimpleX 三项对照收获：①**桶地址随机分发**（防服务方按身份串联桶）已采纳为
  SP-1 v9.1；②联系人间中继可发展为可选 2 跳 onion 式转发（SimpleX v6.0 默认），
  列为远期增强；③SimpleX 经 Trail of Bits 外部审计——本项目发布前应设立
  外部审计目标

---

# 第五轮：Telegram 对照（2026-09-04，用户指示）

**反面证据（红线 A 证据链第三例）**：MTProto 1.0 非 IND-CCA 安全（Jakobsen &
Orlandi 2015）；MTProto 2.0 仍被审出四个攻击（Albrecht et al., Journal of
Cryptology 2026——源于 Encrypt&MAC 构造与 IGE 可延展性）；von Arx 2023 进一步
证明**第三方客户端生态频繁把 MTProto 2.0 实现错**——自研协议连「协议对、实现难对」
都躲不过。米TLS（腾讯）+ MTProto（Telegram）两案足够定案：密码协议只用经过
学术审计的标准件（我们用 iroh 的标准 QUIC+TLS 与 libsignal）。

**采纳三项（全部为通用工程/UX 模式，先例独立于 Telegram）**：
1. SP-3 安全码可视化（先例：OpenSSH randomart）
2. SP-4 会话级消息自毁计时器（B6 缓解；先例：各类带 TTL 的消息协议）
3. SP-5 中继抗主动探测（先例：MTProxy fake-tls、Trojan fallback 网页）

**明确不采纳**：云端聊天/DC 中心化架构（违背第一原则）、自研协议、
多设备授权（MVP 外）。


---

# 第六轮：零上下文子 Agent 独立审计对账（2026-09-04）

> 应用户要求，派出未接触本项目上下文的子 Agent 盲审 crates/core 全部源码
> （刻意不提供 ARCHITECTURE-RISKS.md 防锚定）。其发现逐条核实如下——
> 独立视角确实找到了作者「知识的诅咒」之外的问题。

| 编号 | 严重度 | 发现 | 核实 | 处置 |
|---|---|---|---|---|
| C1 | **P0** | RelayGuard 缓存满即整体清空 → 灌满后重放旧票成功 | 属实（正是模块自述的最致命攻击） | ✅已修：按过期逐出+来源限占，回归测试覆盖 |
| C2 | P1 | MAC 未绑定 group/kind/sent_at/ttl；持钥中继可伪造写入 | 属实 | ✅已修：MAC 绑定全部字段+常量时间比较；持钥中继伪造仍被内层 Signal AEAD 兜底（防御纵深） |
| A1 | P1 | SP-1.5 nonce 缓存只有注释没有实现 | 属实 | ✅已修：NonceCache 原语+测试 |
| C3 | P1 | 时钟毒偏移被高水位棘轮固化（+24h 后撤毒仍钉死 24h） | 属实（高水位设计缺陷） | ✅已修：偏移变化即重置基线+本地回拨单独检测 |
| B1 | P1 | RelayGuard 不校验挑战、TTL 无强制 | 属实 | ✅已修：accept 带期望挑战+issued_at 入签+TTL≤2h 强制 |
| A2 | P1 | 安全状态（密钥环/高水位/票缓存）无持久化 → 回滚攻击 | 属实（部分） | 📋 阶段 5 落地：随队列层序列化+serial 地板；时钟高水位恢复接口已有 |
| B3 | P2 | 公告有效期无上限（可铸百年公告） | 属实 | ✅已修：MAX_VALIDITY 30 天 |
| C4 | P1 | SP-7 路径 envelope.sender 即长期身份，暴露给陌生人 | 属实（与 A1 矛盾） | 📋 阶段 4：外层改节点密钥化名，身份入内层密文 |
| C5 | P2 | 网络校时单点无交叉验证 | 属实 | 📋 阶段 5：双源+TLS 强制；当前依赖 Android 系统 NTP 的信任 |
| C6 | P2 | 蓝牙校时对端未验证是否联系人 | 属实 | 📋 阶段 4：仅接受已验证联系人（加好友流程产出） |
| D1 | P2 | MAC 比较非常量时间 | 属实 | ✅已修：XOR 折叠常量时间比较 |
| D2 | P2 | Db::open 无密钥静默明文建库 | 属实 | ✅已修：strict 模式拒绝 |
| D3 | P3 | Dedup cap=0 失效 / from_cbor 单播群播互斥缺失 / clock 溢出 | 属实 | ✅已修全部三项 |
| A3/B2/B4 | P2/P3 | 限速未接线 / 桶地址未随机化落地 / scope 第三档注释 | 属实（已有排期） | 📋 阶段 5（governor 原语已就绪） |

**统计**：子 Agent 报告 14 项发现，核实全部属实（0 误报），其中 9 项当场修复、
5 项按阶段排期。**结论：用户的「知识诅咒」假设被证实**——作者三轮自查未发现
C1/C3 这两个 P0/P1，盲审一次命中。

---

# 第七轮：排期项逐一清零（2026-09-07，用户指示「一个一个修」）

| 原排期项 | 状态 | 落点 |
|---|---|---|
| B4 scope 第三档注释 | ✅ | settings.rs 注释更新 |
| C6 蓝牙校时限已验证联系人 | ✅ | clock.rs 信任名单（trust/distrust/is_trusted）+ UntrustedPeer 拒绝 + 回归测试 |
| C5 网络校时双源交叉验证 | ✅ | clock.rs：双源偏移差 ≤5s 才采纳，单源永不采纳，分歧双弃 + 2 回归测试 |
| B2 桶地址随机化（v9.1） | ✅ | mailbox.rs：generate_bucket_address() 随机 256 位，不再由身份派生 |
| A2 安全状态持久化 | ✅(部分) | nodekey.rs state()/restore()（恢复时逐条验签）；时钟高水位恢复接口已有；NonceCache/票缓存持久化随阶段 5 |
| C4 外层化名 | ✅(规格) | envelope.rs sender 字段语义分流写死；SP-7 第 6 条 |
| A3 限速接线 | ✅(原语+入口) | verify_inbound() 强制 MAC→窗口→nonce 顺序；prune_seen() 裁剪；governor 已就绪待传输层调用 |

**当前全仓**：70 lib 测试 + iroh 对连 + 暴力验证 = 全绿；clippy 0 警告。
剩余未实现项均为「等核心接入」的功能项（Signal 会话、RFCOMM、UniFFI），无安全缺口。

**做得好（子 Agent 确认）**：verify_strict、指纹域分隔、MAX_FRAME_SIZE 先检后缓冲、
full-jitter 退避、DB 损坏行报错、时钟残余风险的诚实注释。

---

# 第九轮：红队二轮（BLE/QR/iroh/投递链，2026-09-13）

> 应用户「后端也要找」要求，红队 Agent 从全新角度攻击传输链与投递链。
> 产出 crates/core/tests/redteam2.rs（12 测试：7 RED + 5 GREEN）。

| 编号 | 严重度 | 发现 | 处置 |
|---|---|---|---|
| R2-1 | P1 | QR_OFFER 明文帧无认证灌 TOFU 信任表，抢注真名 → 真人扫码永久 IdentityChanged | ✅ 同名 30s 限频（BleMesh.kt）+ upsert_identity_confirmed 覆盖保护（signal_store.rs） |
| R2-2 | P1 | iroh sink 丢弃消息但 send 返回 Ok → mark_sent → 消息永久丢失（假投递回执） | ✅ ACK 协议重做：sink 判定 Option<bool> + 9 字节判定帧 + Node::ack + 5s 超时按 NAK，仅 Ok(true) 才 mark_sent |
| R2-3 | P1 | 信箱重放台账（NonceCache）无持久化，进程重启 ±5min 窗内重放复活 | ✅ export/import_state + FFI export_ledger/import_ledger（JSON 落盘）。**当前 Android 壳 MailboxManager 尚无宿主接线 → 实际暴露面为零；接线时须同步接持久化循环（遗留登记）** |
| R2-4 | P2 | 读桶 nonce 台账全局 FIFO 无限速，洪泛挤掉他桶未过期 nonce（读侧重放复活） | ✅ ReadLedger 按桶对分区（pair_key 指纹为键）+ 分区表 4096 硬顶，洪泛只占自己分区 |
| R2-5 | P2 | outbox sent 行连密文永不清理；revive 无 state 守卫可复活已送达消息 | ✅ revive 守卫进 SQL WHERE 同语句（AND state='dead'，无 TOCTOU）+ prune_sent 7 天接入 delivery::cleanup |
| R2-6 | P2 | inbox_seen 台账无容量上限（与 NonceCache 防御强度不一致） | ✅ INBOX_SEEN_CAP=16384，满员先补裁剪窗外记录，仍满 fail-closed 拒收不驱逐 |
| R2-7 | P2 | 首条握手 token-MAC 无一次性/无上下文绑定，拍下载荷=永久握手能力 | ✅ 域分隔 v2：长度前缀 name + expiry 大端进 MAC 输入；过期先拒；无 v1 回退门 |

**独立验证官裁决（2026-09-13，新开 Agent、不带修复者结论）**：8/8 修复项真实、完整、
无绕过、无回归；208 测试通过（lib 156 / redteam2 12 / redteam 20 / adversarial 18 /
bruteforce 1 / iroh_pair 1）、clippy 0 错误。**通过**。

验证官附带 P3 登记（均不重开攻击路径）：
- P3-1 ~~文档状态未回写~~（本节即回写）
- P3-2 QR_OFFER 限频键用 32 位 contentHashCode，可构造碰撞换包；伤害被 Rust 覆盖保护封顶，残余仅为 PQXDH 算力消耗
- P3-3 不同假名仍可按名累积信任行（TOFU 首次信任的设计取舍，测试注释明示）
- P3-4 NonceCache::import_state 不重验 expiry（本地可信写入者可达，方向 fail-closed）
- P3-5 node.rs on_message panic 时 pending 表项泄漏（方向安全：发送方超时重试）
- P3-6 本地 dc_core.kt 为陈旧生成物（git-ignored，CI 构建前重生成）；本地构建需先 uniffi-bindgen
- 遗留登记：upsert_identity_confirmed 的用户确认恢复通道未暴露 FFI（同 R2-3「核心就绪、宿主待接线」）
- 越界观察：BleMesh.sendText BLE 分支 GATT 写成功即记「已发送」无应用层 ACK = 已知 A4 待办（非本批回归）

**Kotlin 侧独立二轮审查（同日）**：1 P0 + 2 P1 + 4 P2 + 7 P3，共 14 项，
已登记 .project-memory/MEMORY.md（K2-1~K2-14），修复 Agent 进行中。

最狠两条：K2-1（AUTH_CAND 解析无上界 → 未认证远程崩溃于 GATT binder 线程）、
K2-2（joiner 配对完成后 MSG 静默丢弃 → 单向聊天失效）。
