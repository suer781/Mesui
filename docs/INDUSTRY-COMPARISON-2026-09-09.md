# 业界对标与代码审查综合报告（2026-09-09）

> 三路输入交叉比对：①七款去中心化聊天软件实现调研（Briar/SimpleX/Session/Jami/Tox/Meshtastic+bitChat/Matrix，来源见文内引用）②Rust 核心逐文件安全审查 ③Android 传输层逐文件安全审查。
> 本文只写「比对后有依据的结论」，每条缺点带文件:行号。

## 0. 结论速览

| 维度 | 判断 |
|---|---|
| 相对业界的亮点 | 匿名发现层、governor 双曲线节流、sealed-sender 信封语义——**三点优于多数同行** |
| 最严重的缺点 | **P0×2：BLE 重连握手失效 + 联系人落库断链**——「33/32 幽灵」三处现形，加好友→持久化→重连→聊天整条链路在集成层断掉 |
| 系统性根因 | ①身份长度契约无单一事实源 ②乐观落库无 ack ③安全决策单侧把关 ④零外部审计 |
| 横向定位 | 密码学选型第一梯队（vendored libsignal），工程完成度第二梯队，**审计与消息可靠性垫底** |

## 1. 业界对标（七维度横评）

| 维度 | Briar | SimpleX | Session | Jami | Tox | Meshtastic | bitChat | **本项目** |
|---|---|---|---|---|---|---|---|---|
| 传输 | BLE/WiFi直连+Tor | SMP中继+Tor | onion 3跳 | OpenDHT+ICE | DHT+TCP中继 | LoRa flooding | BLE mesh TTL7 | **BLE+iroh(QUIC)** |
| 发现/加友 | 当面扫码 | 一次性邀请 | Session ID | DHT | DHT+onion | 无需(广播) | 随机peer ID | **扫码+布隆回连** |
| 离线投递 | store-forward+Mailbox | 单向队列投递即删 | swarm 14天 | ❌需双在线 | ❌(扩展有) | ~30包 | store-forward | **设计有/未接线** |
| 群加密 | 发布订阅 | 逐成员fanout | ClosedGroup | Swarm(git式) | DHT群 | 每信道PSK | Argon2id+GCM | **❌未实现** |
| 元数据保护 | Tor但直连暴露 | **无任何ID** | onion | DHT暴露IP | onion | **明文路由头** | 静态公钥可关联 | **化名节点钥+随机桶** |
| 多设备 | ❌(离线迁移) | ❌(导出) | ✅恢复短语 | ✅证书链 | ❌ | n/a | ❌ | ❌ |
| 外部审计 | ✅Cure53 | ✅ToB×2 | ✅Quarkslab | 部分 | ❌ | 自承非专家 | ❌(被曝冒充) | **❌零审计** |

## 2. 本项目的相对亮点（比对后确认领先处）

1. **匿名发现层**：FriendLink 的「HKDF 每日钥 + 10 分钟槽位 + 布隆填充隐藏好友数」**优于 bitChat**（静态 Noise 公钥可关联）和 **Meshtastic**（To/From 节点号明文广播）——这两家的教训我们避开了一半（MAC 暴露刚修完）。
2. **governor 双曲线节流**：电量(40%→5% smoothstep 至 3% 地板)×负载(0.6→1.0)取 min + 每发送者 6 条/分钟保底 + fail-closed——七款里没有一家做到这个细度。
3. **sealed-sender 语义**：envelope 按路径分流 sender（联系人=长期钥/陌生人=化名节点钥）+ 256 位随机桶地址——SimpleX「无 ID」哲学的部分同源，比 Session 依赖服务节点网络更去中心。
4. **密码学选型**：vendored libsignal 官方栈（PQXDH+Double Ratchet），强于 Tox（无审计）、Meshtastic（默认明文）、bitChat（无审计且被曝冒充漏洞）。
5. **测试基线**：107 项测试随 CI 真实执行——bitChat/Meshtastic 级别的项目普遍没有这个纪律。

## 3. 缺点清单（两路审查合并去重，按严重度）

### P0（发布硬阻断，两条独立死链，缺一不可）

**P0-1 BLE 重连握手失效——「33/32 幽灵」现形①**
- `BleMesh.kt:319-321`：AUTH_CHA body = nonce(16)+identityKey(33)=49B，但断言 48B 且只切 32B 比对，永不匹配 → 布隆命中后回连握手两端都建不起来。

**P0-2 联系人落库在 App 集成层完全失败——「33/32 幽灵」现形②（经两路审查交叉确认）**
- 事实链（已逐点核对）：Android 传给 `upsert_contact` 的 identity 是 **33 字节**（来源 `prekeySenderIdentity` = `IdentityKey::serialize()`，或二维码 `AddFriendPayload.identity`，两处均已钉 33）→ FFI `upsert_contact`（ffi.rs:324）**原样转发** → Rust `upsert`（contacts.rs:117）断言 32 → `Err` 被 Android `runCatching` 吞掉。
- 后果：配对 UI 显示「完成」但联系人**从未入库**；`listContacts()` 恒空 → 布隆广播无好友、重连/sendText/在线点全死。**即便修好 P0-1，也没有任何联系人可重连。**
- 为什么 Rust 单测没拦住：测试用 `&[1u8;32]`（contacts.rs:254-285），固化了与 FFI 现实相悖的契约。
- 修复方向：**在 Rust 侧**放宽/归一化 `upsert` 接受 33（入库取 `[1..]` 归一、读取补回前缀，或直接存 33 字节 BLOB，`listContacts` 返回 33）；**严禁** Android 侧剥离成 32——`sas_with`(ffi.rs:206)/`pin_identity`(ffi.rs:226) 走 `IdentityKey::decode` 要求 33，剥离即断 SAS/TOFU。bucket/link_secret 均为 32 无需动。

**根因收口（对两处 P0 一并生效）**：全仓统一 `ID_LEN=33` 常量单点定义 + 补「Kotlin 构造真实载荷 → Rust 解析」的跨 FFI 集成测试（此前审计建议 #7，正是本类缺陷唯一可靠的拦截网）。另注：QR 路径的同类缺陷（AddFriendPayload 32→33）已在 earlier PR 修复，幽灵现共三处、已修一处。

### P1（可上线前必修）

| # | 缺点 | 位置 | 一句话场景 |
|---|---|---|---|
| P1-1 | TOFU pin 可被静默覆盖，换钥告警被丢弃 | signal_store.rs:173-197 | 攻击者重新 pin 即顶替已信任联系人，MITM 无告警 |
| ~~P1-2~~ | **已升级并入 P0-2**（两路审查交叉确认 Kotlin 确实传 33，且错误被吞） | contacts.rs:117 | 见 P0-2 |
| P1-3 | iroh 端点无连接/流上限，阻塞回调可饿死 runtime | node.rs:77-105 | 知道节点 id 即可 DoS：大量 QUIC 流 + 256KiB 无界分配 |
| P1-4 | 配对完成后首聊消息静默丢 | BleMesh.kt:439,588 | 配对链路未接聊天通道，需断开重连才能收发 |
| P1-5 | Keystore 解不开 → 静默清空全部联系人+历史 | SignalCore.kt:92-97 | 换机/系统重置凭据即毁灭性数据丢失，无二次确认 |
| P1-6 | joiner 收 DCS1 即自动落库，SAS 单侧把关 | BleMesh.kt:494-499 | joiner 的「确认」按钮形同虚设，MITM 下 host 误点即双双中招 |

### P2（合并精选，10 条）

1. HMAC 非恒定时间比较（BleMesh.kt:384,396 → `MessageDigest.isEqual`）
2. 反向挑战 AUTH_B_* 是死代码，相互认证不完整（BleMesh.kt:390-392）
3. deviceName 用 ANDROID_ID 写进二维码（SignalCore.kt:54-55 → 换随机名）
4. 熵池不累积：`finalize_xof` 每次重置（entropy.rs:30-37）
5. 内部钟非严格单调，偏离 SP-8 声明（clock.rs:257-280）
6. 预密钥 id 用 MAX+1，乱序消费可复用（signal_store.rs:128-146）
7. parse_naddr 无地址数上限（node.rs:209-252）；SignalSession Mutex 毒化即瘫（ffi.rs:142-238）
8. governor 保底可超卖总预算（100 人×6 >> 预算），缺全局硬桶（governor.rs:120-126）
9. 双指纹体系：identity_fingerprint vs libsignal SAS，UI 比对闭环可能错位（identity.rs:70 vs handshake.rs:275）
10. 发送无 ack + 乐观落库（BleMesh.kt:613）——「我发了但对方没收到」的静默丢失，IM 生命线

### 系统性根因（比单条缺陷更重要）

1. **跨语言字节契约无单一事实源** → 幽灵 bug 三处现形（QR 已修 / contacts.rs / BleMesh AUTH），且 Rust 单测用 32 字节反而**固化**了错误契约。解法：`ID_LEN` 单点定义 + 跨 FFI 集成测试（单测拦不住 FFI 边界）。
2. **安全决策单侧把关**：SAS 只有 host 确认、TOFU 告警被丢弃、`prekey_sender_identity` 无认证抽取——多处「另一端的确认」形同虚设。
3. **消息可靠性层缺失**：无应用层 ack、无离线队列接线（queue.rs 空转）、配对链路与聊天链路割裂。
4. **零外部审计**：Briar/SimpleX/Session 都花了真金白银做审计并靠它活着；本项目连一次内部红队都没做过。

## 4. 从业界该抄的作业（按优先级）

1. **bitChat 的链路会话**：Noise XX 握手 + 临时密钥 5-15 分钟轮换 + cover traffic——正对应我们设计文档 5.3 的「ephemeral 链路会话」待补项；它的「静态公钥可关联」教训我们已在 FriendLink 里避开，但 cover traffic 值得抄。
2. **SimpleX 单向队列**：接收方建队列、投递即删、padding + channel binding——信箱代存（设计文档 2.5）的参考范式。
3. **Briar Mailbox**：备用设备经 Tor 代存拉取——「共同联系人代存」的同构方案，验证了我们 2.5 的方向。
4. **Megolm 发送方棘轮**：群聊是**全项目最大功能空白**（PLAN.md 承诺 OpenMLS，代码零行）。效率群照 Megolm 思路做发送方单向棘轮，省带宽。
5. **Meshtastic 反面教材**：路由头明文（我们 envelope 已避免）、默认通道明文（我们不会犯）、密集同频拥塞（对我们 5.4 的拥塞退避是直接验证）。
6. **多设备债**：Briar/Tox/bitChat 都因纯 P2P 牺牲多设备；若要补救，Jami 证书链或 Matrix 密钥备份是成熟范式——建议 MVP 后再议。

## 5. 行动路线（合并重排）

| 阶段 | 内容 | 验证 |
|---|---|---|
| Hotfix | P0-1（BleMesh AUTH 33）+ P0-2（upsert 接受 33）+ P1-1（TOFU pin）+ P1-4 首聊丢消息 + P1-5 静默清库；修完立即补端到端冒烟：扫码加好友→重启→联系人仍在→能发消息 | 单测 + 真机两台重连 |
| 硬化 | P1-3 端点限流 + P1-6 joiner 双侧确认 + P2-1/2/3 | 单测 + 审计清单 |
| 可靠性 | 应用层 ack + 队列接线（queue.rs 已有）+ 长度校验提示 | 弱网真机 |
| 中转 | A0 信封签名 → A1 FFI → A2 四道闸+扩散凭证 → A3 三台验收（设计文档第三/五节） | 三台真机（A-B-C） |
| 空白 | 群聊（Megolm 路线）+ 通知可达性 + 多设备（后议） | — |

## 6. 来源

调研来源 URL 由调研员实测检索：briarproject.org、simplex.chat、docs.oxen.io、docs.jami.net、zetok.github.io/tox-spec、meshtastic.org、github.com/permissionlesstech/bitchat、spec.matrix.org 等（审计：Cure53 2017 / Trail of Bits 2022+2024 / Quarkslab）。代码审查发现均带文件:行号，可复核。
