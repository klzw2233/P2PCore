# 用 p2p-core 写应用层

本库是传输地基:**没有**好友、用户名、聊天记录、离线消息。应用只拿到一条**双方同时在线**的加密字节流,语义全在你这边。

用词以 [CONTEXT.md](../CONTEXT.md) 为准。架构在 [README.md](../README.md)。

## 你依赖什么

```toml
[dependencies]
p2p-core = { path = "…" }   # 或日后 crates.io
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

日常只碰 `p2p-core`。需要自己算 SAS、或换存储实现时再直接用 `p2p-trust`。**不要** `use iroh::…`:换传输层时应用不该跟着改。

MSRV:Rust **1.91**。

## 最小回路

1. 选一个本机目录,用密码打开 `FileKeyStore`;用同一把 Identity Key 打开 `FileTrustStore`。
2. `Endpoint::bind(keystore, truststore, relay)`。空 KeyStore 会生成一把 Identity Key 并写入。
3. 把 `endpoint.peer_id()` 交给对方(扫码 / 粘贴)。
4. 对方在线时:`dial(peer_id, DialHints::relays(["https://relay.example"]))` 或 `accept()`。
5. `session.send` / `session.recv_exact` 传你的应用帧。关掉用 `session.close()`。

```rust
use p2p_core::{Endpoint, Error, RelayConfig};
use p2p_trust::{FileKeyStore, FileTrustStore, IdentityKey, KeyStore};

async fn bind(root: &str, password: &[u8], relay_url: &str) -> Result<Endpoint, Error> {
    let mut keys = FileKeyStore::new(root, password);
    let identity = match keys.load().map_err(Error::Trust)? {
        Some(id) => id,
        None => {
            let id = IdentityKey::generate();
            keys.save(&id).map_err(Error::Trust)?;
            id
        }
    };
    // TrustStore 用同一把 Identity Key 验签名;bind 会再从 KeyStore 读一次。
    let trust = FileTrustStore::open(root, identity).map_err(Error::Trust)?;
    Endpoint::bind(&mut keys, Box::new(trust), RelayConfig::custom([relay_url])?).await
}
```

`FileTrustStore::open` 需要 Identity Key,所以**先**从 KeyStore 取出(或生成)身份,再 bind。密码错 → `Error::Trust(WrongPassword)`。

开发期可 `RelayConfig::n0_public()`,**必须显式调用**。生产默认是 `RelayConfig::disabled()`,不断 n0。

## 信任是你的 UI,不是库的协议

库**不发**「我已验证你」的线上消息([ADR-0006](../docs/adr/0006-no-wire-protocol.md))。

| 用户怎么拿到对方 Peer ID | 你该调用 |
|---|---|
| 面对面扫码 | `endpoint.introduce(peer, IntroductionChannel::Trusted)` → Verified,以后拨号不再比 SAS |
| 粘贴 / 链接 / 网页 | `endpoint.introduce(peer, Untrusted)` 或什么都不做:首次 `dial`/`accept` 成功会记 **TOFU** |
| 用户对照 SAS 通过 | `endpoint.mark_verified(peer)`。这是 TOFU → Verified **唯一**升级路径。再扫一次码**不会**升级 |

导出 SAS(两端各自算,必然相同;库已按公钥字节排序):

```rust
use p2p_trust::sas;

let mine = endpoint.peer_id().public_key();
let theirs = peer.public_key();
let code = sas(mine, theirs); // Display: 8 组 5 位数字
```

把 `code.as_str()` 画在屏幕上,让人打电话对。库不检查他们是否真的对过。

TOFU **挡不住第一次冒充**,只能发现「以后钥匙换了」。跟用户说清楚。

## 拨号失败时 UI 怎么分

```rust
match endpoint.dial(peer, hints).await {
    Ok(session) => { /* 传字节 */ }
    Err(Error::PeerOffline) => { /* 对方不在线;约 5 秒内返回,不会挂死 */ }
    Err(Error::RelayUnreachable) => { /* 没配 Relay,或 Relay 不可达。默认不是 n0 */ }
    Err(Error::UnlockFailed) => { /* 本机身份解锁失败 */ }
    Err(Error::Rejected { intended, presented }) => { /* Verified 对不上,硬失败,没有 Session */ }
    Err(Error::Alert { intended, presented, previous }) => {
        // TOFU 钥匙变了。不要自动当 Verified。
        // 用户同意后:
        //   endpoint.accept_tofu_replacement(presented)?;
        //   再决定是否重拨 presented.peer_id()
    }
    Err(Error::AlreadyConnected { peer }) => { /* 这条 Peer 已有一条 Session */ }
    Err(e) => { /* Bind / Accept / Stream / Io / Closed / Trust / InvalidRelayUrl */ }
}
```

硬失败和告警都**不把 Session 交给你**,底层连接已关。

同一端点对同一远程 Peer **同时最多一条** Session。要再拨,先 `close` 掉手里那条。

可同时和 **不同** Peer 各持一条。

## 字节流与数据报

一条 Session = 一条已认证 QUIC 连接 + **一条**可靠双向流 + 不可靠数据报。没有多流、没有 0-RTT。

### 可靠流（文字消息、文件块、信令）

- `send(&[u8])`:写完才返回。对端按序收到。
- `recv(&mut buf) -> usize`:`Ok(0)` 或 `Err` = 结束。
- `recv_exact(&mut buf)`:凑满才返回。
- `close()` / `Drop`:对端下一次 recv 看到结束;再 send 失败。

**帧格式是应用的事。** 库不帮你加长度前缀。两端必须约定同一套(例如 4 字节大端长度 + payload)。任一方离线,Session 就没了——不要在这里做离线队列。

### 数据报（实时音视频）

```rust
// 发送一个不可靠数据报（成功不保证对端收到）
session.send_datagram(opus_frame)?;

// 阻塞接收一个数据报（等待直到数据到达或连接关闭）
let frame = session.recv_datagram().await?;
decode_and_play(frame);

// 检查路径是否支持数据报及最大载荷
if let Some(mtu) = session.max_datagram_size() {
    // 根据 MTU 切片大帧或降码率
}
```

- **不保证送达、不保证顺序、不保证不重复。** 应用自己处理（音视频：丢包弃帧 + 序号 + 周期关键帧）。
- **与可靠流共存**：文字消息 / 文件块 / 通话信令继续走 `send`/`recv`，媒体帧走数据报。
- **路径 MTU 自动探测**：`max_datagram_size()` 反映当前路径（直连 / Relay）的实际容量。Relay 路径可能不支持数据报（返回 `None`），应用据此决定降级策略。

`accept()` 一次收一条传入拨号。要一直听,自己 `loop { accept().await }`。

没有 Address Lookup 时,拨号带 `DialHints::relays(["https://你的-relay"])`,两端共享 **Peer ID + Relay URL** 就能连。接自建 `iroh-dns-server` 是后续工作,本库第一版不要求。

## 应用该做 / 不该做

**做:**

- 用户名、好友列表、头像、聊天 UI
- 扫码 / 粘贴 Peer ID;展示 SAS;问「要不要接受这把新钥匙」
- 自己的消息帧、文件传输、多设备「这是同一个人」的展示(核心不承认 User,[ADR-0003](../docs/adr/0003-identity-per-device.md))
- 自建 Relay / Discovery;生产把 Custom Relay URL 写进配置

**不要做(也别求库做):**

- 把 iroh 类型漏进应用、绕过 `evaluate` 直连
- 当库提供「匿名」或「抗量子」。准确说法:**服务端读不到内容**;Session 握手 prefer 混合 KEM,Identity Key 仍是 Ed25519
- 公钥目录当核心身份(要用户名就上层自建,并承担投毒风险,[ADR-0004](../docs/adr/0004-no-key-directory.md))
- 离线投递、群组、浏览器 / WebRTC、0-RTT 应用数据

## 存储落盘

| | 文件 | 保护 |
|---|---|---|
| Identity Key | `{root}/identity.key` | Argon2id + ChaCha20-Poly1305,密码加密 |
| Trust State | `{root}/trust.store` | 用本机私钥**签名**(不加密:里面没有机密) |

目录由应用选(配置目录 / 平台 keychain 旁)。要换安全芯片 / 系统钥匙串:实现 `KeyStore` / `TrustStore` 再注入 `bind`。
