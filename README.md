# P2PCore

一个 Rust 实现的 P2P 传输核心库:让任意两台设备之间建立**经过双向认证的加密通道**,服务端读不到通道内的任何内容。

它是未来 P2P 应用的地基,本身**不包含任何应用语义**。

> **当前状态:`p2p-trust` 与 `p2p-core` Session 已立([#1](https://github.com/klzw2233/P2PCore/issues/1) / [#2](https://github.com/klzw2233/P2PCore/issues/2))。** 应用怎么接见 [notes/04-app-layer.md](./notes/04-app-layer.md)。

---

## 它解决什么问题

P2P 通信里真正难的从来不是"把字节送过去",而是两件事:

1. **穿透 NAT** —— 苦工,但已被解决。本项目直接采用 [iroh](https://github.com/n0-computer/iroh),不重复造轮子。
2. **"这个公钥真的属于这个人吗"** —— 没有任何库能替你回答。**这才是本项目自研的部分。**

## 核心洞察

**Peer ID 就是公钥。**

因此只要持有对方的 Peer ID,就已经持有其公钥,拨号在密码学上是自认证的——**中间人攻击在结构上无法发生**,而不是"被缓解"。

这个洞察消除了整个公钥目录子系统,连带消除了它引入的全部攻击面。服务端因此**不掌握任何密钥,也不参与身份的建立**。

---

## 威胁模型

| | 威胁 | 处置 |
|---|---|---|
| a | 被动网络监听(ISP、公共 WiFi) | ✅ 防御 |
| b | 恶意或被入侵的服务端 | ✅ **结构上消除** |
| c | 主动中间人(篡改、重放、降级) | ✅ 防御 |
| e | 端点密钥泄露 | ✅ 前向保密 |
| g | Harvest-now / 量子破密钥交换 | ✅ 混合 KEM([ADR-0007](./docs/adr/0007-prefer-hybrid-pq-kx.md)) |
| d | 元数据隐私 | ❌ **明确不提供**([ADR-0001](./docs/adr/0001-no-metadata-privacy.md)) |
| f | 抗审查、流量分析 | ❌ 不做;混淆不是稳定承诺,见 [ADR-0002](./docs/adr/0002-transport-on-iroh.md) |

> ⚠️ **不得对外宣称本项目提供"匿名"或"无法追踪"。** 准确的措辞是:**服务端无法读取通信内容**。Discovery Server 与 Relay 必然掌握完整的通信关系图。
>
> ⚠️ **不得对外宣称本项目"抗量子"或"量子安全"。** 准确的措辞是:**Session 握手 prefer 混合 KEM,Identity Key 仍是 Ed25519。**

---

## 架构

```
┌─────────────────────────────────────────────┐
│  应用层    用户名 · 好友 · UI · 验证界面      │  ← 不属于本项目
├─────────────────────────────────────────────┤
│  p2p-core   把信任层接到 iroh 上 · async     │
├─────────────────────────────────────────────┤
│  p2p-trust  纯逻辑 · 零网络 · 同步            │  ← 项目的核心价值
├─────────────────────────────────────────────┤
│  iroh 1.1.0 QUIC · 打洞 · Relay · Discovery  │  ← 外部依赖
└─────────────────────────────────────────────┘
```

**`p2p-trust` 的 `Cargo.toml` 中不得出现 iroh、tokio 或任何网络库。** 这条边界由编译器强制,不靠自律([ADR-0005](./docs/adr/0005-two-crate-boundary.md))。

### 服务端

只有两个组件,均需**自建**,不使用 n0 的公共设施:

- **Discovery Server**(`iroh-dns-server`)—— 回答"某个 Peer ID 现在在哪些地址上"
- **Relay**(`iroh-relay`)—— 打洞失败时转发密文

两者都不掌握密钥。自建的理由见 [ADR-0001](./docs/adr/0001-no-metadata-privacy.md):我们接受服务端掌握通信关系图,但那必须是自己的服务端。

> 生产必须在配置里提供自建 Relay URL,默认**不是** n0 公共设施。开发期可显式 opt-in 公共 Relay。越晚切到自建,客户端配置的迁移成本越高。

---

## 信任模型

这是本项目的核心。

### 状态机

```
                    ┌─────────┐
                    │ Unknown │
                    └────┬────┘
            面对面扫码     │     首次连接(渠道不可信)
         ┌───────────────┴───────────────┐
         ▼                               ▼
   ┌──────────┐   SAS 带外比对通过    ┌──────┐
   │ Verified │ ◄──────────────────── │ TOFU │
   └────┬─────┘                       └───┬──┘
        │ 公钥变更                         │ 公钥变更
        ▼                                 ▼
   ❌ 硬失败,拒绝建立 Session         ⚠️ 告警,交上层决定
      必须重新验证
```

### 规则

1. **获取 Peer ID 的渠道决定初始状态**
   - 面对面扫二维码 = 可信渠道 → 直接 `Verified`
   - 粘贴、转发、网页 = 不可信渠道 → `TOFU`
2. **`TOFU` → `Verified` 唯一路径是 SAS 带外比对**
3. **公钥变更时行为分级**
   - `Verified` 状态 → **硬失败**,拒绝连接
   - `TOFU` 状态 → 显著告警,由上层应用决定
4. **`TOFU` 只能发现日后的密钥更换,无法发现首次接触时就已存在的冒充**

### SAS(安全码)

```
SAS = 编码( 哈希( 规范排序(公钥_A, 公钥_B) ) )
```

- **绑定长期公钥对,不绑定单次 Session** → 验证一次,永久有效
- ⚠️ **推导前必须对两个公钥按字节序规范排序**。否则两端因"我方/对方"顺序相反而算出不同的串,**且这个 bug 在单机测试中发现不了**
- 核心库只负责**导出** SAS,如何展示、是否强制比对由上层应用决定

### 信任层没有任何网络代码

SAS 两端各自本地计算,Trust State 本地存储,公钥就在 Peer ID 里。因此信任层**不定义任何线上协议**——零解析代码、零解析漏洞、**降级攻击面直接消失**([ADR-0006](./docs/adr/0006-no-wire-protocol.md))。

---

## 关键决定速查

| 项 | 决定 | 依据 |
|---|---|---|
| 传输层 | iroh 1.1.0,不自研 | [ADR-0002](./docs/adr/0002-transport-on-iroh.md) |
| Session KX | prefer `X25519MLKEM768`;身份仍 Ed25519 | [ADR-0007](./docs/adr/0007-prefer-hybrid-pq-kx.md) |
| 身份粒度 | 一个 Identity Key = **一台设备**,不是一个人 | [ADR-0003](./docs/adr/0003-identity-per-device.md) |
| 公钥目录 | **不存在** | [ADR-0004](./docs/adr/0004-no-key-directory.md) |
| crate 划分 | 两个,边界由编译器强制 | [ADR-0005](./docs/adr/0005-two-crate-boundary.md) |
| 信任层协议 | **零线上协议** | [ADR-0006](./docs/adr/0006-no-wire-protocol.md) |
| 元数据隐私 | 不提供 | [ADR-0001](./docs/adr/0001-no-metadata-privacy.md) |
| 在线模型 | 双方必须**同时在线**,无离线投递 | — |
| 平台 | 桌面 + 移动;**不支持浏览器** | — |
| 密钥存储 | `KeyStore` trait,默认 Argon2 加密文件,平台原生实现由上层注入 | — |
| Trust State 存储 | `TrustStore` trait,用私钥**签名保完整性**(不加密,里面没有机密) | — |

---

## 明确不做的事

拒绝这些不是因为做不到,而是每一条都会挤占本该用在 Authenticity 上的预算:

- **元数据隐私** —— 代价是重写一个 Tor
- **离线消息投递** —— 需要 X3DH + Double Ratchet,是 Signal 协议的全部内容
- **多设备聚合**(一个人的多台设备)—— 终局是主身份 + 交叉签名,复杂度与整个信任层相当
- **用户名 / 公钥目录** —— 应用语义,且是唯一的结构性弱点
- **浏览器支持** —— 会强制整个传输层绑定 WebRTC
- **群组加密** —— 需要 MLS
- **量子破身份** —— Identity Key 保持 Ed25519;PQ 签名会推翻 Peer ID / SAS / TrustStore

**"一台设备一个身份"的诚实代价**:双方各有 N 台设备时,人工验证是 N² 的成本。可接受,但必须向上层应用说明。

---

## 工程纪律

这些不是建议,是"安全第一"的兑现方式:

- **威胁模型 a/b/c/e/g 每一条都必须有一个"攻击者视角"的对抗性测试**,断言攻击失败。这是把威胁模型从文档变成代码的唯一手段。g 测的是 provider 要约顺序与禁止 0-RTT,不 downcast 握手。
- 核心 crate 加 `#![forbid(unsafe_code)]`
- CI 跑 `cargo-deny` / `cargo-audit`。**依赖链漏洞是比密码学缺陷现实得多的风险。**
- CI 断言 `p2p-trust` 的依赖树中没有网络库
- 公开 API 恪守可 FFI 导出纪律:具体类型、无泛型、错误用 enum、回调用 trait object
- 双平台 CI:ubuntu + windows

---

## 目录结构

```
/
├── CONTEXT.md          ← 术语表,先读这个
├── README.md           ← 本文件
├── HANDOFF.md          ← 当前工作状态
├── CLAUDE.md           ← 给 Claude Code 的仓库级指引
├── docs/
│   ├── adr/            ← 架构决策记录
│   ├── architecture-review.md  ← 审阅发现,不是第二份 README
│   └── agents/         ← issue tracker / 三方约定
├── crates/
│   ├── p2p-trust/      ← 信任层(issue #1)
│   └── p2p-core/       ← Session API,接 iroh 见 issue #2 / #14
└── notes/              ← 学习者导读
```

---

## 开发环境

| 需求 | 说明 |
|---|---|
| Rust | 稳定版工具链 |
| 平台 | 开发与 CI 需 Linux + Windows |
| 网络测试 | **不需要** NAT 模拟环境——打洞归 iroh,信任层是纯逻辑 |

---

## 文档索引

| 文件 | 内容 |
|---|---|
| [CONTEXT.md](./CONTEXT.md) | **术语表。动手前必读**,所有文档用词以它为准 |
| [HANDOFF.md](./HANDOFF.md) | 当前进度、未决事项、下一步 |
| [ADR-0001](./docs/adr/0001-no-metadata-privacy.md) | 不提供元数据隐私 |
| [ADR-0002](./docs/adr/0002-transport-on-iroh.md) | 传输层采用 iroh |
| [ADR-0003](./docs/adr/0003-identity-per-device.md) | 一个身份对应一台设备 |
| [ADR-0004](./docs/adr/0004-no-key-directory.md) | 移除公钥目录 |
| [ADR-0005](./docs/adr/0005-two-crate-boundary.md) | 两个 crate 的硬边界 |
| [ADR-0006](./docs/adr/0006-no-wire-protocol.md) | 信任层零线上协议 |
| [ADR-0007](./docs/adr/0007-prefer-hybrid-pq-kx.md) | Session prefer 混合 PQ;身份仍 Ed25519 |
