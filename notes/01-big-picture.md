# 大图

P2PCore 让两台设备在 NAT 后面建一条**双向认证的加密通道**,服务端读不到内容。它是地基,**没有**好友、用户名、聊天、离线消息。

## 先建立的直觉

**Peer ID 就是公钥。** 拿到对方的 Peer ID,就已经拿到用来认证的钥匙。所以核心库不需要「用户名 → 公钥」目录。目录一旦存在,恶意服务端就能把你指向假钥匙——那是整个系统里唯一必须靠用户比对才能补上的结构性弱点。砍掉目录,弱点消失。见 [ADR-0004](../docs/adr/0004-no-key-directory.md)。

一台设备一把 Identity Key,不是「一个人一把」。手机和电脑是两个 Peer,要分别验证。[ADR-0003](../docs/adr/0003-identity-per-device.md)。

## 两层

```
应用(好友、UI、扫码)     ← 不是本仓库
p2p-core   async,接 iroh  ← issue #2
p2p-trust  同步,零网络    ← issue #1,真正自研的部分
iroh 1.1.0                ← 打洞 / QUIC / Relay
```

`p2p-trust` 的 Cargo.toml 里不能出现 iroh 或 tokio。这不是洁癖:crate 边界是编译器会强制的唯一边界。[ADR-0005](../docs/adr/0005-two-crate-boundary.md)。

## 服务端只有两件事

- **Discovery Server**:「这个 Peer ID 现在在哪」
- **Relay**:打洞失败时转发**密文**

两者都不碰密钥。我们接受它们看得到「谁和谁在说话」,所以必须是**自己的**服务端,不能默认用别人的公共 Relay。[ADR-0001](../docs/adr/0001-no-metadata-privacy.md)。

## 口头禅(对外别说错)

| 别说 | 说 |
|---|---|
| 匿名 / 无法追踪 | 服务端无法读取通信内容 |
| 抗量子 / 量子安全 | Session 握手 prefer 混合 KEM;Identity Key 仍是 Ed25519 |

## 明确不做

元数据隐私、离线投递、多设备聚合、浏览器、群组、量子破身份、流量混淆(第一版)。每一条都会挤掉 Authenticity 的预算。
