# 传输层 iroh

NAT 打洞是苦工,iroh 已经做了。本项目不自研 QUIC / STUN / TURN。[ADR-0002](../docs/adr/0002-transport-on-iroh.md)。

## 核实过的事实(不要再用旧传闻)

| 传闻 | 事实 |
|---|---|
| iroh 1.10 | **1.1.0**(2026-08-25)。1.10 是误读 |
| `noq` = Noise over QUIC | Quinn 的 fork,RFC 9001,**TLS 1.3 over QUIC** |
| 可以换底层 UDP socket 做混淆 | **不能** BYO socket。`CustomTransport` 存在但 unstable,不受 semver 保护 |

身份:Ed25519,Raw Public Keys(RFC 7250)。`p2p-core` 必须用 `p2p-trust` 的同一把种子构造 iroh `SecretKey`,禁止让 iroh 自己 `generate()`。

## 两条「保密」不要混

**Forward Secrecy(e):** 今天的 Identity Key 明天泄露,不能拿去解**以前**的 Session。靠 TLS 1.3 的 1-RTT 临时密钥。所以禁止 0-RTT 应用数据。

**Harvest-Now Resistance(g):** 对手**今天**录下密文,等量子计算机去破**当时的密钥交换**。靠握手 prefer `X25519MLKEM768`(混合 KEM)。Identity Key 仍是 Ed25519——量子破**签名/冒充**明确不做。[ADR-0007](../docs/adr/0007-prefer-hybrid-pq-kx.md)。

prefer 不是 require:两个 `p2p-core` 端点会谈成混合 KEM;连 Relay 的 HTTPS 若对端没有 PQ,退回经典。g 保护的是端到端内容,不是 Relay 控制面。

后端必须是 `tls-aws-lc-rs`(ring 没有 ML-KEM)。这是默认,不是 feature flag。

## 现在能做什么(#14 / #15)

Relay:`RelayConfig::disabled()` 是默认;`custom(["https://…"])` 才出网;`n0_public()` 必须显式调用。测试走 iroh `test-utils` 进程内 Relay,不模拟真实 NAT。

`p2p-core::Endpoint::bind` 之后:`dial(peer_id, DialHints)` / `accept()` 得到一条 Session。握手后走 `p2p-trust::evaluate`;硬失败或告警都不把 Session 交给应用,并关掉底层连接。

`DialHints::relays(["https://…"])` 是无 Address Lookup 时的寻址提示(URL 字符串,不是 iroh 类型)。测试两端同一 runtime + 进程内 Relay。

`Session::close` 后对端 `recv` 看到结束,再 `send` 失败。同一端点对同一 Peer 同时最多一条 Session,重复拨号是 `Error::AlreadyConnected`(close 后可再拨)。对端离线时 `dial` 在约 5 秒内以 `Error::PeerOffline` 结束。未配 Relay 且不可直连是 `Error::RelayUnreachable`(可据此断言默认不断 n0)。身份解锁失败是 `Error::UnlockFailed`,与 `evaluate` 拒绝分开。

对抗性 a:同一 Relay 上的旁路 Peer D 拿不到 A↔B 的字节(内容机密性由 TLS 1.3 提供,测试防的是误把明文交给旁路)。b:拨 B 得到的 remote 必须是 B。c:Mallory 没有 B 的私钥,无法作为 B 完成握手。

## Session 长什么样(#2 / #14 / #15)

一条已认证 QUIC 连接 + **一条**双向可靠字节流。没有多流、没有数据报、没有 0-RTT。双方必须同时在线。
