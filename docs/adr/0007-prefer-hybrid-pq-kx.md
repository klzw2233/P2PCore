# Session 密钥交换 prefer 混合 PQ;Identity Key 保持 Ed25519

`p2p-core` 的 Session 握手把 `X25519MLKEM768` 放在密钥交换组的第一位(prefer,不是 require)。Identity Key 仍是 Ed25519。这防御的是 **Harvest-Now Resistance**(威胁模型 g),不是量子破身份。

## 为什么记录这个决定

"抗量子"会把两件不同的事混成一句对外承诺。读者看到混合 KEM,会以为 Peer ID 也抗量子。它不是。

## 考虑过的替代方案

- **什么都不做**:Session 密文可被今天录下、量子计算机成熟后破当时的经典密钥交换。g 是真实的近期威胁,iroh 1.1.0 已经提供混合 KX,成本是换 `tls-aws-lc-rs`,不是自研协议。
- **PQ-only(只提供 `X25519MLKEM768`)**:更硬,但 iroh 的 `crypto_provider` 同时用于 Peer QUIC 和 Relay/Discovery 的 HTTPS。n0 公共设施不吃 PQ-only;自建 Relay 与进程内 test-utils 的 HTTPS 也是经典 TLS。iroh 1.1.0 没有"P2P 一套、Relay 一套"的稳定开关。
- **给应用 prefer/require 旋钮**:第一版没有旧客户端要兼容,旋钮只制造两端策略不一致。
- **Identity Key 也换 PQ 签名**:会改 Peer ID、SAS、TrustStore、扫码载荷,等于换一代身份系统,与已锁定的信任层骨架冲突。默认答案是不加。

Prefer 写死:两个 `p2p-core` 端点都会把 PQ 放第一,彼此之间谈成混合 KEM;连 Relay 时若对端没有 PQ,退回经典。g 保护的是端到端 Session 内容,不是 Relay 控制面。

`p2p-core` 默认 `tls-aws-lc-rs`(ML-KEM 目前只有这条 rustls 后端)。Windows CI 编不过就修 CI,不把 PQ 藏进 feature flag。

公开 API 不暴露"这次是不是 PQ"。展示"抗量子"而不把量子破身份排除在外,是措辞事故。

## 后果

- 威胁模型增加 **g**(Harvest-now / 量子破密钥交换)→ 防御。e(Forward Secrecy)不扩写:e 的对手是经典的,拿到的是 Identity Key。
- **量子破身份明确不做。** 不得对外使用笼统的"抗量子""量子安全""post-quantum"。
- 测试断言 `crypto_provider.kx_groups[0]` 是 `X25519MLKEM768`,以及公开 API 没有 0-RTT 入口。不 downcast rustls 握手去读 named group。
- 实现落在 [issue #2](https://github.com/klzw2233/P2PCore/issues/2)。术语见 CONTEXT 的 Harvest-Now Resistance。
