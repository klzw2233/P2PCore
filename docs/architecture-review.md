# 架构审阅(2026-09-01)

对照 CONTEXT、README、ADR-0001～0007、issue #1 / #2。
**结论:骨架成立,不要另写一套架构。** README 仍是架构正文;本文件只记审阅发现。

## 成立、不要重开

- Peer ID 就是公钥 → 无 Key Directory → 恶意服务端投毒身份的攻击面消失(ADR-0004)
- 信任层零线上协议(ADR-0006);crate 边界由编译器强制(ADR-0005)
- 一设备一身份(ADR-0003);不提供元数据隐私(ADR-0001)
- Forward Secrecy(e)与 Harvest-Now Resistance(g)分开;身份仍 Ed25519(ADR-0007)
- 实现顺序 #1 → #2 正确:`p2p-trust` 可在零网络下测透

## 文档错误(本 PR 修)

1. **CONTEXT 打洞定义仍写 Signaling Server。** 本项目没有信令;打洞由 iroh 用 Discovery / Relay 协助。已改 CONTEXT。
2. **README「Relay 地址硬编码」。** #2 要求生产必须注入 Custom URL、默认不是 n0。已改成「配置里提供,默认不是公共设施」。
3. **#1 Out of Scope 仍把 iroh 三件事实当未决。** 已在 ADR-0002 关闭。实现 #1 时删那三行即可,不阻塞 #1。

## 规格漏洞(实现 #1 / #2 时锁死,不要静默发明)

4. **SAS「哈希前 40 字节」不可能。** SHA-256 只有 32 字节。与「短字符串」也不符。
   **实现时用:** 规范排序拼接 → SHA-256 → **前 16 字节** → 每 2 字节大端成 1 个 0–65535 的十进制数,不足 5 位补零,8 组空格分隔。128 bit,电话可读。改 #1 正文,不要既写 40 字节又写 8×5 位。
5. **#1「私钥永不出现在公开 API」与 #2「把 32 字节种子交给 iroh」冲突。**
   **实现时用:** `IdentityKey` 提供 `to_seed_bytes() -> [u8; 32]`,文档写明仅供 `p2p-core` 绑定传输层与 TrustStore 签名,**禁止日志**。不另做导出类型,也不 `pub use iroh::SecretKey`。
6. **iroh 上 `evaluate` 的 intended ≠ presented 几乎走不到。** EndpointId 就是公钥,拨号成功则两者相同。密钥更换在 iroh 上表现为**新 Peer ID**(新 TOFU),旧 Verified 记录留在店里不会被自动打掉。mismatch 路径是给可替换传输层和测试的,不要为了「测到 iroh 密钥变更」去伪造握手。

## 刻意代价(不是漏洞)

- 人工验证 N²;TOFU 挡不住首次冒充;`mark_verified` 是应用的诚实调用
- 默认 `tls-aws-lc-rs`(C/汇编)是 g 的代价;Windows CI 编不过就修 CI
- 混淆 / BYO socket 不是稳定承诺
- `p2p-core` 在 #1 里先占位是为 ADR-0005;#13 绑 Endpoint,#14 交出 Session,#15 锁生命周期。空壳不再是现状;#2 已关

## 不要做的

- 不把 README 再抄成第二份架构
- 不把 #1 / #2 复制进仓库(issue 是规格,复制会漂)
- 不加 Key Directory、线上信任协议、PQ 身份、0-RTT、n0 默认 Relay
