# 工作状态交接

**最后更新:2026-09-01**
**当前阶段:#8 已合;正在 #13 Endpoint。实现入口:[#13](https://github.com/klzw2233/P2PCore/issues/13) → [#14](https://github.com/klzw2233/P2PCore/issues/14) → [#2](https://github.com/klzw2233/P2PCore/issues/2)。**

本文件供接手的 Claude Code 会话阅读。

---

## 给接手者的三条硬规则

1. **先读 [CONTEXT.md](./CONTEXT.md),再读 [README.md](./README.md),再读 `docs/adr/` 全部七篇。** 所有用词以 CONTEXT.md 为准。
2. **不要重新讨论已定的决定。** 下面"已锁定"的每一项都经过完整论证并写进了 ADR。若确有充分理由推翻,写一篇新 ADR 标注 supersedes,不要静默改掉。
3. **`p2p-trust` 的 `Cargo.toml` 里永远不能出现 iroh、tokio 或任何网络库。** 这是整个架构唯一由编译器保护的约束,打穿它等于废掉 ADR-0002 和 ADR-0005。

---

## 已完成

一次完整的设计 grilling(17 个决策点),加上 iroh 核实与 PQ grilling,产出:

| 文件 | 状态 |
|---|---|
| `CONTEXT.md` | ✅ 术语表,含参与者/服务端/连接/信任/安全性质(含 Harvest-Now Resistance) |
| `README.md` | ✅ 完整架构文档 |
| `docs/adr/0001` ~ `0007` | ✅ 七篇架构决策记录 |
| `docs/agents/*.md` | ✅ issue tracker / triage 标签 / domain docs 约定 |
| `CLAUDE.md` | ✅ 仓库级指引 |
| GitHub | ✅ `klzw2233/P2PCore`;issue #1 / #2 已发,`ready-for-agent` |

## 未开始

- ✅ 代码:workspace + `p2p-trust` / `p2p-core` 空壳(#5);信任逻辑尚未写
- ✅ `Cargo.toml` / workspace
- ✅ CI:ubuntu + windows、`cargo-deny`(禁 p2p-trust 网络库)、`cargo-audit`
- ✅ `notes/` 学习者导读(不是规格)

---

## 已锁定的决定(勿重开)

| 决策点 | 结论 |
|---|---|
| 范围 | 传输层完整核心,**不含任何应用语义** |
| 语言 | Rust |
| 威胁模型 | 防 a 被动监听 / b 恶意服务端 / c 主动 MITM / e 密钥泄露 / g harvest-now;**不做** d 元数据隐私、f 抗审查、量子破身份 |
| 传输层 | iroh **1.1.0**,不自研(ADR-0002) |
| Session KX | prefer `X25519MLKEM768`;Identity Key 仍 Ed25519(ADR-0007) |
| 在线模型 | 双方必须同时在线,**无离线投递** |
| 平台 | 桌面 + 移动,**不支持浏览器**(这解放了 WebRTC 依赖) |
| 身份粒度 | 一个 Identity Key = 一台设备;承诺可演进到主身份背书但现在不做(ADR-0003) |
| 公钥目录 | **不存在**(ADR-0004) |
| 信任建立 | 扫码 → Verified;粘贴 → TOFU + SAS 补验 |
| SAS | 绑长期公钥对;**推导前必须规范排序** |
| 密钥变更 | Verified → 硬失败;TOFU → 告警 |
| crate 划分 | `p2p-trust`(纯逻辑)+ `p2p-core`(接 iroh)(ADR-0005) |
| 信任层协议 | **零线上协议**(ADR-0006) |
| 移动端绑定 | 暂不做,但公开 API 恪守 FFI 可导出纪律 |
| 存储 | `KeyStore` / `TrustStore` 两个 trait,默认实现自带,平台原生由上层注入 |
| 测试 | 威胁模型每条都要有对抗性测试;g 测 provider 顺序 + 禁止 0-RTT |

---

## iroh 核实结果(原"未决"三项,2026-09-01 已关闭)

来源:iroh v1.1.0 源码与 README,写入 ADR-0002。

1. **不能**包装底层 UDP socket。`CustomTransport` 存在但是 `unstable-custom-transports`,不受 semver 保护。混淆不进第一版。
2. **`noq` 不是 Noise。** Quinn 的 fork,RFC 9001 / TLS 1.3 over QUIC。e 对 1-RTT 成立。
3. 版本是 **1.1.0**,不是 1.10。自建文档:`iroh-relay` README、`iroh-dns-server` 的 config 示例。uniffi 不阻塞。

---

## 建议的下一步顺序

1. ~~核实 iroh 三件事实~~ ✅
2. ~~GitHub 远程~~ ✅ `klzw2233/P2PCore`
3. ~~workspace + CI~~ ✅ [#5](https://github.com/klzw2233/P2PCore/issues/5) / PR #9
4. ~~[#6](https://github.com/klzw2233/P2PCore/issues/6) Identity Key / Peer ID / SAS~~ ✅
5. ~~[#7](https://github.com/klzw2233/P2PCore/issues/7) introduce / evaluate / mark_verified~~ ✅
6. ~~[#8](https://github.com/klzw2233/P2PCore/issues/8) 文件 KeyStore / TrustStore~~ ✅
7. [#13](https://github.com/klzw2233/P2PCore/issues/13) `p2p-core` Endpoint 身份对齐 + prefer 混合 PQ + Relay 配置
8. [#14](https://github.com/klzw2233/P2PCore/issues/14) Session 拨号 / 接受 / 字节流 + 信任门闩
9. [#15](https://github.com/klzw2233/P2PCore/issues/15) Session 生命周期与对抗性 a/b/c

> 顺序的逻辑:`p2p-trust` 零依赖、零网络、纯函数,**可以在完全不碰 iroh 的情况下写完并测透**。先把项目真正的核心价值做扎实,再接传输层。#2 被 #1 阻塞。

---

## 上下文:这次设计的净效果

最初的设想是服务端提供"信令 + STUN + TURN + 公钥目录",信任层需要设计一整套验证协议。

推演之后:**服务端不碰任何密钥,信任层收缩成一个零网络、零协议的纯函数 crate。**

关键转折是意识到 **Peer ID 就是公钥**——于是公钥目录整个消失,"防御恶意服务端"从"需要用户老实比对 SAS 才安全"变成"不存在这个攻击面"。

**接手时请保持这个方向:每砍掉一个组件,就砍掉了它的全部攻击面。** 遇到"要不要加个 X"的问题,默认答案是不加,除非能论证它带来的价值超过它打开的攻击面。
