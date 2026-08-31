# 传输层采用 iroh,自研信任层

传输层(QUIC 连接、Hole Punching、Relay 兜底、地址发现)直接采用 [iroh](https://github.com/n0-computer/iroh) **1.1.0**,不自行实现。自研的范围收窄为 **Trust Layer**:Identity Key 管理、TOFU 存储、SAS 推导、Trust State 状态机。

Session 密钥交换的 PQ 策略见 [0007](./0007-prefer-hybrid-pq-kx.md),不在本篇展开。

## 为什么记录这个决定

项目的立项目的是"为将来的 P2P 开发建立基础",一个合理的读者会预期我们亲手实现 NAT 穿透,并疑惑为什么直接用了现成的库。

## 考虑过的替代方案

- **基于 `quinn` 自拼**(自己写身份绑定、STUN、打洞、Relay 协议):最初的倾向,但被两个事实推翻。其一,iroh 已发布 **1.1.0**(2026-08-25;1.0.0 于 2026-06-15),受 semver 保护;而 `quinn` 仍是 0.x,即"自己拼更可控"的直觉在版本稳定性上是反的。其二,QUIC 连接迁移(移动端 WiFi↔蜂窝切换的刚需)与 TLS 1.3 带来的 Forward Secrecy,iroh 同样白送,这条论据并不区分两个方案。文档曾误写为 1.10,那是对 1.1.0 的误读。
- **裸 UDP + Noise 全自研**:需要自己实现拥塞控制与重传。写错的后果是性能崩溃并可能成为 DDoS 放大器,与"安全可靠"的目标直接冲突。

真正决定性的理由是分工:**Hole Punching 是已被解决的苦工,而"这个公钥真的属于这个人吗"没有任何库能替我们回答。** iroh 保证"你连上的确实是该公钥的持有者",但公钥与真实世界中某个人的对应关系、TOFU 与 SAS 验证、Trust State 的演变,完全在它的范围之外——而那正是威胁模型中 Authenticity 一条的全部要害。把精力放在无人替代的部分。

iroh 采用 MIT / Apache-2.0 双授权。

## 已核实的事实(iroh v1.1.0 源码与 README)

- **`noq` 不是 Noise over QUIC。** [n0-computer/noq](https://github.com/n0-computer/noq) 是 Quinn 的 fork,实现 RFC 9001(TLS 1.3 over QUIC),默认 rustls。iroh 的端到端认证是 TLS 1.3 + RFC 7250 Raw Public Keys,身份就是 Ed25519 公钥。威胁模型 e 的前向保密对 **1-RTT** 成立;0-RTT 应用数据禁止,见 issue #2。
- **不能 bring-your-own UDP socket。** `bind_addr` 只指定本机 IP:port。可插拔的是 `CustomTransport`(packet 级 bind/recv/send),挂在 `unstable-custom-transports`,不受 semver 保护。`iroh-tor` 证明这条路存在,但是实验性的。
- 因此 [0001](./0001-no-metadata-privacy.md) 中"保留可加装混淆层的接口"**不是今天的稳定承诺**,只是这条不稳定能力。混淆不进第一版。
- 自建:`iroh-relay`(server feature、`--dev`、进程内 `test_utils::run_relay_server`);`iroh-dns-server`(pkarr + DNS)。测试用前者的进程内路径。

## 后果

- **分层边界必须是硬的。** Trust Layer 的类型与逻辑不得依赖任何 iroh 类型。若日后需要更换传输层,信任层应当原样存活。
- **基础设施自建。** `iroh-relay` 与 `iroh-dns-server` 均需自行部署,不使用 n0 的公共设施。原因见 [0001](./0001-no-metadata-privacy.md)。开发期可用公共设施,但必须显式 opt-in,不能当默认——Relay 地址在客户端配置中,越晚切换成本越高。
- Session 的混合 PQ 密钥交换与 `tls-aws-lc-rs` 后端见 [0007](./0007-prefer-hybrid-pq-kx.md)。
