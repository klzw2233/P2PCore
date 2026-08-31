# P2PCore

一个 P2P 传输核心库:让任意两个对等端在各自的 NAT 之后建立一条**经过双向认证的加密通道**,服务端全程无法读取通道内容。它是未来 P2P 应用的地基,本身不包含任何应用语义。

## Language

术语以英文为准(代码中即以此命名),定义用中文。

### 参与者

**Peer(对等端)**:
运行本核心的一个端点,由其 Identity Key 唯一标识。
_Avoid_: 客户端 / Client、用户 / User、节点 / Node

**Identity Key(身份密钥)**:
Peer 的长期非对称密钥对。私钥不离开设备;**公钥就是这个 Peer 的身份本身**,不存在"身份"与"密钥"分离的概念。
_Avoid_: 账号密钥、用户密钥、证书

**Peer ID(对等端标识)**:
由 Identity Key 的公钥确定性推导出的短标识符。可公开传播,不含机密。
_Avoid_: 用户 ID、账号、UUID

**User(用户)——刻意不属于本上下文**:
"一个人拥有多台设备"这种聚合关系**不是本项目的概念**。一个 Identity Key 对应一台设备,不对应一个人;核心库不提供也不承认用户级别的身份。把若干 Peer 呈现为同一个人,是上层应用的展示逻辑。见 [ADR-0003](./docs/adr/0003-identity-per-device.md)。

### 服务端设施

服务端由下面两种职责构成。它们在概念上分离,即使部署在同一台机器上。**两者都不掌握任何密钥,也都不参与身份的建立。**

**Discovery Server(发现服务器)**:
回答"某个 Peer ID 当前可以在哪些网络地址上找到"的服务端。它只解析地址,不参与 Session 的建立协商,也不接触 Session 内容。
_Avoid_: 信令服务器 / Signaling Server(信令指转发建连协商消息,本项目不做这件事)、中心服务器、Broker

**Relay(中继)**:
当 Hole Punching 失败时代为转发 Session 流量的服务端。它只搬运密文,无法解密。
_Avoid_: 代理 / Proxy、转发服务器、Gateway

**Key Directory(公钥目录)——刻意不属于本上下文**:
"人类可读标识 → 公钥"的映射**不是本项目的概念**。Peer ID 即公钥,拨号本身就是自认证的,不存在需要查询公钥的环节。需要用户名的应用应在上层自建目录并自行承担其风险。见 [ADR-0004](./docs/adr/0004-no-key-directory.md)。

### 连接

**Session(会话)**:
两个 Peer 之间一条已认证、已加密的活动连接。**Session 要求双方同时在线**;任一方离线即终止,不存在挂起或离线投递的 Session。
_Avoid_: 连接 / Connection(指底层网络连接)、通道、会晤

**Hole Punching(打洞)**:
两个 Peer 借助 Discovery Server / Relay 提供的地址信息,各自向对方发包以在自身 NAT 上打开映射,从而建立直连的过程。本项目**没有**转发建连协商消息的信令角色;打洞由 iroh 实现。
_Avoid_: NAT 穿透(指整个问题域,不指这个具体手段)、P2P 直连、信令 / Signaling(本项目不做)

### 信任

**Verification(验证)**:
一个 Peer 通过**不经过服务端的带外渠道**确认对方 Identity Key 真实性的行为。这是 Authenticity 的唯一来源。带外渠道可以是面对面扫码,也可以是电话中比对 SAS。
_Avoid_: 认证 / Authentication(指连接握手时的密码学证明,不含人的参与)、鉴权

**SAS(安全码,Short Authentication String)**:
由**双方 Identity Key 公钥对**确定性推导出的短字符串,两端必然相同。用户通过带外渠道比对它来完成 Verification。
绑定的是长期公钥而非单次 Session,因此**验证一次即永久有效**。推导前必须对两个公钥做**规范排序**(按字节序排序后再拼接),否则两端因"我方/对方"顺序相反而算出不同的串。
核心库只负责**导出**它,如何展示与比对由上层应用决定。
_Avoid_: 验证码(易与一次性口令混淆)、指纹(指公钥哈希本身,不指用于比对的呈现形式)

**TOFU(首次使用即信任)**:
在没有 Verification 的情况下,接受首次见到的 Identity Key 并记住它的策略。**它只能发现日后的密钥更换,无法发现首次接触时就已存在的冒充。**
_Avoid_: 信任、自动信任

**Trust State(信任状态)**:
本地记录的、对某个 Peer 的 Identity Key 的信任级别:**Verified**(经 SAS 比对确认)或 **TOFU**(仅记住未确认)。密钥变更时两者行为不同:Verified 状态下拒绝建立 Session,TOFU 状态下告警并交由上层决定。
_Avoid_: 信任等级、白名单

### 安全性质

这五个词必须严格区分,不可混用为笼统的"安全"。

**Content Confidentiality(内容机密性)**:
Session 中传输的数据只有两端可读。**这是本项目的核心承诺**,对被动监听者、恶意服务端、Relay 一律成立。

**Authenticity(认证性)**:
每一端都确信对端持有其所声称的 Identity Key。这是最容易做错的一环,且依赖 Verification 而非 Key Directory。

**Forward Secrecy(前向保密)**:
Identity Key 日后泄露,不能用于解密此前已捕获的 Session 流量。对手是经典的,拿到的是长期身份密钥。不覆盖量子破密钥交换,那是 Harvest-Now Resistance。

**Harvest-Now Resistance(先存后破抗性)**:
对手今天录下 Session 密文,量子计算机成熟后破的是**当时的密钥交换**,也读不出内容。兑现方式是 Session 握手 prefer 混合 KEM(`X25519MLKEM768`),见 [ADR-0007](./docs/adr/0007-prefer-hybrid-pq-kx.md)。
**不包含** Identity Key 抗量子:Peer ID 仍是 Ed25519 公钥,量子破签名明确不做。
_Avoid_: 抗量子、量子安全、post-quantum(笼统使用会让人以为身份也抗量子)

**Metadata Privacy(元数据隐私)**:
第三方无法得知"谁在与谁通信、何时、通信量多少"。
**本项目明确不提供这项性质。** Discovery Server 与 Relay 必然知晓 Peer 之间的通信关系图。任何声称本项目"完全匿名"的表述都是错误的。
