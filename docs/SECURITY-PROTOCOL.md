# 安全协议规格（阶段 3/5 实现基线；2026-09-11 按代码现状标注）

> 本文档是阶段 3（二维码/蓝牙添加）与阶段 5（iroh/信箱/节点服务）的**协议规格**，
> 模式移植自微信支付公开文档的成熟实践，原语一律使用现有密码库（红线 A：
> 连腾讯魔改 TLS 1.3 都被 Citizen Lab 审出弱点，我们不自研任何密码协议）。
> 状态标注：【已实现】= 代码可查证；【未实现】= 规格先行，等接线。

## 〇、来源与合规边界（防闭源审计，2026-09-04）

**借鉴的合法性分级**——本项目只借鉴「公开协议契约 + 开源参考实现」层面的模式：

| 借鉴项 | 来源性质 | 独立先例（证明是通用工程模式，非微信私产） |
|---|---|---|
| serial 选钥（Wechatpay-Serial） | 公开商户文档 + [官方 Apache-2.0 开源 SDK](https://github.com/wechatpay-apiv3/wechatpay-java) | X.509 证书序列号、TLS 证书选择、Signal PreKeyId |
| ±5 分钟重放窗 + nonce 去重 | 同上 | **Kerberos 时钟偏移正是 ±5min**、TLS 1.3 0-RTT 防重放、JWT iat/exp |
| 规范化签名串（timestamp\nnonce\nbody） | 同上 | RFC 2104 HMAC、TLS 1.2 签名输入、Signal 域分隔 |
| AEAD associated_data 上下文绑定 | 同上 | RFC 5116 AEAD 标准组成部分 |
| 风控限速 / 双因子兜底 | 公开最佳实践文档 | 通用风控模式（速率限制、TOTP/生物+口令） |

**明确不碰的闭源物（红线）**：
- ❌ **mmtls 协议实现与线格式**——闭源，Citizen Lab 靠逆向才分析，且审出弱点；我们
  的传输加密只用 iroh（MIT/Apache，标准 QUIC+TLS 1.3），一行不模仿 mmtls
- ❌ 微信客户端内部实现（闭源，无公开规格）
- ❌ 微信支付服务端密钥体系（闭源基础设施，本就不适用 P2P）
- ❌ 任何逆向工程得来的行为细节

**本项目自身保持 100% 开源**：AGPL-3.0 许可（libsignal 传染所致，已确认接受）；
全部依赖均为开源（AGPL/MIT/Apache/BSD/CC0，见 THIRD-PARTY-NOTICES.md）；
不含微信 SDK、不含 FCM/GMS 等任何闭源二进制。AGPL 保证本软件永不闭源。

## 微信支付机制 → 本项目映射总表

| 微信支付机制 | 官方出处 | 本项目对应 | 状态 |
|---|---|---|---|
| `Wechatpay-Serial` 头：报文携带钥匙版本号 | [平台证书切换](https://pay.weixin.qq.com/doc/v3/merchant/4012154180) | `serial` 字段贯穿信箱门禁与节点密钥公告 | ✅ 代码原语 |
| 平台证书 5 年有效期 + 并行接受期 | 同上 | 节点密钥公告 `not_before/not_after` + 7 天过渡窗 | ✅ 代码原语 |
| 签名串 `timestamp\nnonce\nbody` 规范化 | [APIv3 签名指南](https://pay.weixin.qq.com/doc/v3/merchant/4012071382) | `mac_input()`/`signing_payload()` 规范化串 | ✅ 代码原语 |
| 回调时间偏差 ±5 分钟 + nonce 缓存去重（防重放） | 同上 | `REPLAY_WINDOW_MS` ±5min + 调用方 nonce 去重 | ✅ 代码原语 |
| AES-256-GCM 的 `associated_data` 绑定上下文 | [回调解密](https://pay.weixin.qq.com/doc/v3/merchant/4012071382) | MAC 输入绑定 桶+serial+发送方+内容 | ✅ 代码原语 |
| 幂等 `out_trade_no` | APIv3 通用规则 | 消息 `msg_id` 去重（envelope + inbox_seen） | ✅ 已有 |
| 风控限额分级（小额免密/大额验证） | [最佳安全实践](https://pay.weixin.qq.com/doc/v3/partner/4012082456) | 信箱按写入方限速 + 节点服务流量上限 | 📋 规格见 SP-1 |
| 生物识别 + 支付密码双因子兜底 | [指纹支付说明](https://www.honor.com/cn/support/content/zh-cn00779218/) | 身份重置/密钥轮换 = 生物识别 + 冷却期 | 📋 规格见 SP-4 |
| 强制 TLS 1.2+ / 输入有效性校验 | [扫码支付最佳实践](https://pay.weixin.qq.com/doc/v3/partner/4012166490) | iroh(QUIC+TLS) / wss:443；全输入经验证结构体 | ✅ 架构自带 |
| mmtls 教训：魔改 TLS 1.3 引入弱点（[Citizen Lab 审计](https://citizenlab.ca/research/should-we-chat-too-security-analysis-of-wechats-mmtls-encryption-protocol/)） | 第三方审计 | **反证我们的红线：只用 iroh/标准 TLS，不魔改** | ✅ 架构铁律 |

## SP-1 信箱桶门禁（B1，代码原语：`mailbox.rs`）

1. ~~桶地址 = 收件人**长期身份公钥**的 1024 位指纹~~
   **v9.1 修订（2026-09-04 全面审查，采纳 SimpleX SMP 原则）**：桶地址改为
   **随机 256 位值，经介绍信/二维码分发**——不任何人可从身份推算（防服务方按
   身份枚举/串联桶），只有被告知地址的联系人能定位桶；mailbox secret 派生
   相应绑定该随机地址。
   【已实现】`mailbox.rs` `generate_bucket_address()`（随机 256 位，不再由身份派生）；
   QR 载荷的 bucket 字段即此值
2. 密钥派生：`derive_mailbox_secret(handshake_secret, bucket, serial)`，域分隔 +
   绑定桶与版本；【已实现】（handshake 首条消息 token-MAC 已复用同一派生函数）
3. **线上单元 = `BucketWrite` 整体**（envelope + serial + nonce + ts_ms + mac），
   不传裸信封——运行时冒烟（e2e_demo）曾实证：只传信封则接收方无从验 MAC，
   篡改不可检测。验收顺序：解帧 → 解析 BucketWrite → 验 MAC/时间窗 →
   **之后**才查 msg_id 去重（防用重复响应探测信 ID 存在性）→ 入桶
   【已实现】`verify_inbound()` 在代码里强制该顺序
4. 写桶 = `BucketWrite { envelope, serial, nonce, ts_ms, mac }`；MAC 为 keyed-BLAKE3
   规范化串（绑定 serial/nonce/时间/msg_id/发送方/收件方/正文）
   【已实现】`mac_input()` 绑定信封全部字段（含 Option 存在标志），常量时间比较
5. 中继侧：验 MAC（不过=门口拒绝）→ 验时间窗（±5min，B5：时间戳不作其他安全事实）
   → nonce 去重缓存 → **按写入方限速**（默认 ≤30 封/分钟/对，风控模式移植）→ 入桶
   【MAC/时间窗/nonce 台账已实现】（NonceCache 键=msg_id、逐过期条、满 fail-closed）；
   【未实现】按写入方限速（governor.rs 只治理陌生人转发份额，信箱限速未接线）
6. 读桶：同 secret 的读取 MAC + 序号游标；中继不可见任何明文【未实现——读桶路径整体未开工】

## SP-2 节点密钥轮换（B2，代码原语：`nodekey.rs`）

1. 公告 `NodeKeyAnnouncement { identity, node_key, serial, not_before, not_after, sig }`
   由**长期身份密钥**签名——任何人可验「这是本人签的」，但只有联系人知道
   「identity ↔ node_key」的绑定关系（A1 解耦决议）
   【已实现】公告有效期另受 30 天上限约束（`MAX_VALIDITY_MS`，防铸「百年公告」）、
   单身份缓存 32 条上限、serial=0 拒绝
2. 联系人侧 `NodeKeyRing`：按 serial 选当前钥匙（最高未过期 serial = 微信支付
   「按 Serial 取证书」同款）；7 天过渡窗内旧钥仍可拨（对端未切换的兼容期）
   【已实现】`current()`/`accepts()` + `state()`/`restore()`（恢复逐条验签）持久化接口
3. 分发：公告经联系人信箱推送并由其节点代缓存；彻底失联 → 重新介绍信
   【推送路径已实现】`nodekey::AnnouncementDispatcher`（rotate 产 serial+1 签名公告）
   + `maildrop::seal_announcement_write`/`distribute_announcement`（公告 CBOR 作
   SessionMgmt 信封 body 经联系人信箱桶推送，不加密、中继只验信箱 MAC）
   + FFI `AnnouncementDispatcherHandle`（new/rotate/current_key/distribute）；
   【未实现】节点代缓存（联系人代转发/离线缓存公告）与彻底失联的重新介绍信
4. 危险操作约束：手动轮换 = 生物识别 + 冷却期（双因子兜底，见 SP-4）【未实现】
5. UI 约束（模式借自「新设备登录提醒」，通用先例：SSH known-hosts 变更警告）：
   联系人节点密钥轮换生效时在会话内提示，并提供「重新核对安全码」入口【未实现】

## SP-3 动态分帧二维码→信道绑定（B3，阶段 3 实现规格；v3 动态码，v2 起 NFC 已移除）

> NFC 移除原因：Android 10+ 移除 Beam、HCE 需用户手动设默认应用，碰一碰流程不可靠。

1. 二维码载荷 = `dc://add?v=2` URI（App 已实现生成与解析，AddFriendPayload）：
   name（地址名，ProtocolAddress/SAS 本地标识）+ identity（长期身份公钥，33 字节
   = libsignal `IdentityKey::serialize()`）+ bundle（PreKeyBundle 上线格式 CBOR，含
   Kyber-1024 公钥，约 1.8KB）+ bucket（随机 256 位信箱桶）+ token（384 bit bootstrap
   token）+ ble（8 字节 BLE 配对 id，与出示端 PAIR_UUID 广播同值）+ naddr（iroh
   `dc://node?v=1` 地址快照，可选；节点未就绪时省略）。**当前实现不携带节点密钥本体
   ——跨网寻址走 naddr 快照**（nodekey.rs 轮换公告未接入 QR）
2. **动态分帧（v3，v2 帧格式）**：载荷切为 256 字符/帧的 `dc://addframe` 数据帧
   （`s=$sid&i=$i&n=$n&f=$f&c=$crc&d=$data`），混入随机噪声帧（f=0）循环播放——
   **单帧/单张截图不含完整信息**；模式为公开的 animated-QR airgap 技术
   （ElectronCash/Coldcard 同款，先例独立于任何厂商）；**帧率自适应**：实测单帧
   编码耗时（EWMA）→ 帧间隔 = max(实测耗时, 150ms 最小视觉间隔)，好机器自动
   跑满能力、慢机器自动拉长；位图写入用 `setPixels` 批量填充（弃逐像素
   `setPixel`）；App 已实现（FrameCodec/FrameCollector/AdaptiveFramePacer + JVM 测试）
3. **会话 id 绑定内容（反串行换码）**：`sid = SHA-256(载荷文本) 截断 64 bit`——
   载荷含每场 SecureRandom 的 token/bucket/ble，sid 每次播放必然重生成，攻击者
   既无法预测未开播的 sid，也无法为给定 sid 造出异内容帧组（哈希原像）；扫描端
   **首帧锁定**，锁定后 15 秒集不齐**自动重置**允许新会话（防占锁/防卡死）；
   集齐后校验**内容门** `H(重组文本) == sid`——中途被顶替/拼接的码组过不了门，
   门不过不清锁、等展示端循环重播以真帧逐槽覆盖
4. **帧级 CRC32 校验**：每帧携带 `c=`（CRC32 over sid|i|n|f|d），误读/损坏/拼接帧
   当场拒收入库、等待循环重播补齐（**丢帧可检测、可恢复，不静默收错**），扫描端
   UI 显示缺帧明细；CRC 非密钥校验（防误读不防伪造），恶意替换由第 3 条内容门兜住
5. 扫描端**连续采集**：**采集时长 ≥3 秒**且（**蓝牙搭线帧已扫到** 或 数据帧集齐
   重组成功）才算完成（时长门槛防偷拍），异会话帧/噪声帧/非本协议文本一律忽略
   → 安全码核对 → 蓝牙协商【已实现，含出示端同步的 3 秒 QR_REQ 门槛（双端执行）】
5b. **蓝牙搭线帧（f=2，快连；2026-09-11 增补）**：出示序列混入蓝牙连接帧
   `dc://addframe?v=2&s=$sid&f=2&c=$crc&d=$data`（d = b64 的
   `dc://bledial?v=1&n=设备名&b=8B 配对 id&u=服务 UUID&c=16B 当场挑战`；无 i/n 段，
   旧版扫描端解析失败自动忽略）——扫码端读到即经常驻 BLE 扫描回连（配对 id 与
   PAIR_UUID 广播同值；Android 6+ 拿不到本机蓝牙 MAC 且地址轮换，动态配对 id
   即连接凭据），**二维码只负责搭线，完整身份（含 token）经蓝牙上的既有 Signal
   加密通道交换**（QR_DIAL 挑战回传→QR_OFFER 出示端回公开 PreKeyBundle→扫码端
   PQXDH 建会话→QR_REQ 经密文索要完整身份→QR_ID 密文下发→既有 token-MAC 握手
   +SAS）。防偷拍时长门槛**双端执行**：扫码端 3 秒到期才发 QR_REQ，出示端配对
   开始 3 秒内不答 QR_REQ（合法时序下扫码窗口必然包含于出示窗口）——拍单帧+
   回连拿不到 token，须与拍全数据帧同样持续在场；token 从不出现在密文之外，
   第 6 条 token 绑定与第 7 条安全码核对原则不变
6. 链路建立后，**首条消息必须携带 token 派生的密钥确认**（`HKDF(token)` 作带外秘密）
   ——在场的第三方没有该 token，无法顶替
   【已实现】`first_message_mac`/`verify_first_message_mac`（token+桶地址派生
   keyed-BLAKE3，常量时间比较），BLE HS 帧（Wire.HS）强制校验
7. 交换完成后**强制展示安全码**（双方 1024 位指纹分组），用户核对通过才算加好友
   【已实现（SAS 形态）：libsignal Fingerprint 完整串 + blake3 派生 6 位短码，
   双方各自点「一致」后才 pin 身份 + 落库】；「1024 位指纹分组展示」由
   identity.rs 的指纹函数支撑，UI 当前展示 SAS 短码 + 完整串
8. **外层化名（审计 C4）**：人群转发路径的外层信封 `sender` 字段填**来源轮换
   节点密钥**，长期身份只存在于内层 Signal 密文中——转发者与观察者均无法
   将传输流量关联到长期身份【已实现（规格层）】envelope.rs sender 字段语义按
   联系人/陌生人路径分流；转发传输路径本身未接
9. **安全码可视化**（模式借自 Telegram Secret Chats 的钥匙指纹图形；通用先例：
   OpenSSH randomart）：安全码除 hex 分组外，渲染为可人眼比对的图案（取指纹字节
   驱动 4×4 emoji/色块网格）——人类比对图案远比比对 64 位 hex 串可靠，且抗
   相似字符串欺骗（0/O、l/1 类攻击）【设计意图，未实现——UI 现为 6 位短码 + 完整串】

## SP-4 本地敏感操作（双因子兜底）【全部为设计意图，未实现（等阶段 8）】

- 身份重置、手动密钥轮换、导出备份 = 生物识别 + 15 秒冷却 + 二次确认
- 应用锁与敏感操作授权共用 Keystore 中的生物凭据入口（阶段 8 接入）
- **会话级消息自毁计时器**（模式借自 Telegram Secret Chats；B6 的缓解手段）：
  每会话可选 TTL（关/1h/1d/1w/1M），到期双向删除本地明文与信封，
  设置中心「隐私与安全」暴露该选项（阶段 8）
- 现状备注：库密钥不可解（Keystore 与密文不匹配）时 SignalCore 自动重置身份并
  以一次性 UI 提示明示（非静默）——与上条「身份重置 = 主动敏感操作」是两回事

## SP-5 中继抗主动探测（模式借自 MTProxy FakeTLS 与 Trojan 生态 fallback；阶段 5）

- 中继 = 标准 wss:443（本就与普通 HTTPS 无异），但须通过主动探测考验：
  **未携带本协议标记的 HTTP(S) 请求一律返回一个内容正常的静态网页**
  （伪装站，先例：MTProxy fake-tls 的「DPI 眼里是真实 TLS 会话」、Trojan 的
  fallback 页面）——让 GFW 主动探测无法把中继与普通网站区分开
- 中继域名由节点自选（可前置 CDN）；此为自建 iroh-relay 的部署规格，App 侧无感
  （App 侧接线已实现：node.rs 无自建中继 URL 即 `RelayMode::Disabled`，有则
  `RelayMode::custom`；中继 URL 在「节点服务」面板配置，保存即重启生效）；
  伪装站 fallback 属中继服务器部署要求，本仓未含服务端实现

## 实现状态（2026-09-11）

- ✅ `mailbox.rs`（SP-1 原语 + 8 测试）、`nodekey.rs`（SP-2 原语 + 4 测试）
- ✅ SP-3 已随阶段 3 落地：动态分帧（FrameCodec/FrameCollector/AdaptiveFramePacer，
  JVM 单测）、蓝牙搭线快连（f=2 帧 → QR_DIAL/QR_OFFER/QR_REQ/QR_ID → token-MAC
  握手 + SAS）、扫码/出示双页配对 UI；载荷/帧格式见上文第 1/2/5b 条
- ✅ SP-7 原语：`relay.rs`（转发票 + RelayGuard，8 测试）+ `governor.rs`（资源治理，
  9 测试）+ `settings.rs` scope 第三档；**转发传输路径未接**（mesh 多跳未实现）
- ✅ SP-8：`clock.rs` 全部护栏已实现（12 测试），见该节状态标注
- 📋 SP-1 限速与读桶、SP-2 分发/双因子、SP-4 全部、SP-5 服务端伪装站、SP-9 整体未实现


## SP-7 人群转发（限额陌生人中继；用户提议，2026-09-04 定稿）

> 联系人图谱中继的可用性盲区（冷启动/被孤立）由「陌生人帮转」补齐；隐私反而更优：
> 陌生人只见轮换节点密钥与密文，比朋友知道得更少。模式先例：Tor（陌生节点转发）、
> BitChat（任意节点 mesh）、SimpleX（二跳转发）——均为公开技术，实现各自原创。

1. **转发票（relay.rs 已实现）**：{目的=收件方轮换节点密钥, 来源节点密钥, 过期时间,
   单次 nonce, 中继挑战哈希, 来源签名}——票由来源节点密钥签署，陌生人可见但不可伪造
2. **三重防重放**（重放=最致命攻击：中继读不到内文 msg_id，无法自行去重）：
   - 逐次握手挑战：中继先发随机盐，票内必须含其哈希——旧票对新握手无效
   - nonce 指纹缓存：同一张票全网只收一次（RelayGuard）
   - 过期窗：TTL ≤2h + 2 分钟时钟偏移容差，超窗即焚
3. **限额**：每节点 ≤N 封/小时、单封 ≤S KB、**RAM 常驻不落盘**、不在线即丢弃
   （人群转发是活转发，不做代存——代存仅限联系人信箱）
3b. **资源治理曲线（用户定稿，governor.rs）**：陌生人中继占用节点容量 **15%**；
   电量 <40% 起**沿 smoothstep 曲线**缓慢滑向 **3%**（5% 触地板），无断崖——
   本节点缓慢让速后，mesh 会自动把流量优选到其他端点，全程无毁灭性断联；
   负载 0.6→1.0 同构曲线；每发送者定价 = max(保底 6 条/分, 预算/人数)，
   发送/接收独立令牌桶，降档立即收缩既有令牌
4. **假载荷顶替兜底**：安全码比对 + B 侧棘轮解密（采集层不做信任判断，
   信任由端到端层完成）
5. 设置档位接入：`NodeServiceCfg.scope` 扩展第 3 档 = 任何人（限额人群转发）
   【已实现】settings.rs scope 字段（0=关/1=联系人/2=联系人+二度/3=任何人）；
   传输层尚未按 scope 分流


## SP-8 软件内部独立时钟（clock.rs 已实现；用户设计，2026-09-04 定稿）

> 内部钟 = 系统钟读数 + 校准偏移，**永不修改系统时间**。重放窗（SP-1）、
> 票据过期（SP-7）、消息排序全部消费这个钟——所以时钟本身是安全组件。
> 【已实现】全部护栏 + 回归测试（clock.rs 12 测试）。

1. **校准优先级**（用户设计）：网络优先（Android 系统自同步的 NTP 时间/
   HTTPS 时间接口），无网时蓝牙联系人交换（NTP 四时间戳：t1 本地发出、
   t2 对端收到、t3 对端回复、t4 本地收到）
   【已实现（消费接口）】`on_network_sync(source_id,…)` 由调用方喂入双源读数、
   `on_peer_exchange(t1..t4)` 走蓝牙；本仓未内置 NTP/HTTPS 客户端
2. **偏移计算**：offset = ((t2-t1)+(t3-t4))/2，RTT = (t4-t1)-(t3-t2)；
   RTT >5s 或 t3<t2 判为畸形交换拒绝【已实现（饱和运算防溢出）】
3. **护栏**（代码现状比定稿时多出后四道，均配套测试）：
   - 蓝牙样本需 **3 人法定人数**且最大共识簇内一致（±60s）——单个/成对毒联系人无法拨动
   - 一切校准偏移**限幅 ±24h**（网络与蓝牙同限）
   - **高水位防回拨**：内部钟单调不降，高水位持久化（`restore_high_water` 带合理性
     钳制）——系统钟回拨无效；**本地钟回拨单独检测**（>1 分钟判 rollback_detected，
     回拨期间内部钟钉在高水位）
   - 网络校准新鲜期 6h 内覆盖蓝牙共识，过期后蓝牙接管（用户设计的优先级）
   - **网络双源交叉验证**：两个不同来源偏移差 ≤5s 才采纳，单源永不采纳，分歧双弃
   - **网络采纳限幅**：无认证源单次采纳变化 ≤±2min（更大幅挪钟走 3 人联系人共识），
     且距上次采纳 10 分钟冷却
   - **校时对端须为已验证联系人**：`trust_peer` 名单外的蓝牙校时交换直接拒绝
     （防范围内女巫设备凑法定人数）
4. **残余风险（诚实记录）**：≥3 个串通毒联系人 + 最大簇恰为毒簇时仍可偏移
   （限幅一天封顶）；缓解=样本仅来自联系人 + 用户可在设置页看到当前
   校准源与偏移（阶段 8，未实现），异常偏移提示


## SP-9 蓝牙多跳推进策略（阶段 4 实现规格；设计意图，未实现——当前 BLE 为 1对1 直连链路，mesh 多跳未开工，见 docs/BLE-RELAY-DESIGN.md）

> 问题：BLE 无定位、无路由表，「延伸的路线是否靠近对方」不可直接判定。
> 解法：不做地理路由，改用三层机会主义推进（先例：RFC 6693 PRoPHET、
> BitChat 泛洪、DTN store-carry-forward——均为公开技术）。

1. **最后一跳 RSSI 门槛**：任意持信节点在扫描中看到「目标轮换节点密钥
   出现在广播 + RSSI ≥ -75dBm」→ 直接交付，不再转发
2. **中间跳遭遇概率（PRoPHET 式）**：节点维护「与各联系人/常遇节点的
   遭遇频率表」，节点相遇时交换表；持信节点只在「对方对该目的地概率
   严格更高」时转发——概率表本身不包含目的地身份，只含节点密钥
3. **中段存储携带**：消息跟随持信人的日常移动（DTN），TTL ≤2h（SP-7）
4. **兜底**：TTL 逐跳递减 + msg_id 去重（已有）防打转；链上任一节点有网
   → 立即转 iroh 按公钥直达（蓝牙段只需填补「最后一个无网缺口」）
5. **安全不变量**：信封全程不透明——推错方向只损失效率；概率表仅含
   节点密钥与频率，不暴露长期身份（A1）；RSSI 只做在场判定，不做
   距离测量（人体遮挡/多径不可靠）
