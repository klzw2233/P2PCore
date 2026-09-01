# 信任层

「连上的是这把公钥的持有者」由 iroh 保证。「这把公钥是不是你以为的那个人」没有任何库能替你回答。那是 `p2p-trust` 的全部工作。

## 状态

```
Unknown ──扫码(可信渠道)──► Verified ──公钥对不上──► 拒绝
    └──粘贴/首次连接──────► TOFU     ──公钥对不上──► 告警,上层决定
                              └──SAS 带外比对──► Verified
```

- 扫码 = 你亲眼看见对方设备上的码 → 直接 Verified
- 粘贴、网页、转发 = 渠道不可信 → TOFU
- TOFU **只能**发现「以后钥匙换了」,**不能**发现「第一次见到的就是假的」
- TOFU → Verified **只有**应用在用户比对 SAS 之后调用 `mark_verified`。再扫一次码不能当升级路径(防止「不可信渠道伪造 Trusted 介绍」)。库不验证用户是否真的比对了——信任层没有线上协议,[ADR-0006](../docs/adr/0006-no-wire-protocol.md)

## SAS

两端各自用**两把长期公钥**算同一个短串,打电话对一下。

必须先按公钥原始字节排序再拼接,否则 A 侧「我+你」和 B 侧「我+你」顺序相反,永远对不上。这个 bug 单机测不出来,测试必须角色对调。

绑定的是长期身份,不是某一次 Session:验证一次,一直有效。

展示格式(实现 #1 时用,修正了「40 字节」笔误):SHA-256 的**前 16 字节**,每 2 字节 → 5 位十进制(补零),8 组空格分开。Identity Key / Peer ID / SAS 见 issue #6。

## 和 iroh 对接时容易想错的一点

iroh 的 EndpointId 就是公钥。拨号成功,「我想连的人」和「握手认证的人」是同一个。TrustStore 里「这把钥匙变了」在 iroh 上几乎不会以 mismatch 出现;对方换设备 = **新 Peer ID** = 新的 TOFU。旧的 Verified 记录不会自动删。mismatch 门闩是给以后换传输层和测试用的。

`p2p-core`(#14) 在握手后调用 `evaluate`:出站 `evaluate(intended, presented)`,入站 `intended = presented`。硬失败 / TOFU 告警都不把 Session 交给应用,并关掉底层连接。接受告警是显式 `accept_tofu_replacement`,只把新公钥记成 TOFU。
