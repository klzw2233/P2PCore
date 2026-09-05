# Session 增加数据报 API 支持实时媒体传输

`p2p-core` 的 `Session` 增加 `send_datagram` / `recv_datagram` / `max_datagram_size` 三个方法，暴露 iroh `Connection` 底层的 QUIC 不可靠数据报能力。这是为上层应用的实时音视频通话提供传输通道。

## 为什么记录这个决定

ADR-0002 选择 iroh 时，Session 被设计为"一条 QUIC 连接 + 一条可靠双向流"。`notes/04-app-layer.md` 明确写道"没有多流、没有数据报"。现在要打开数据报，这是 API 承诺的变化。

## 问题

实时音视频对延迟敏感。丢包时，可靠流的队头阻塞会让延迟滚雪球——前面的包在重传，后面的新帧被堵住。WebRTC 用不可靠传输 + 应用层弃帧解决这个问题。

iroh 1.1.0 的 `Connection` 本来就暴露 `send_datagram` / `read_datagram`（QUIC RFC 9221 数据报扩展），但 `p2p-core` 的 `Session` 没有暴露它。

## 决定

Session 增加三个方法：

```rust
impl Session {
    /// 发送一个不可靠数据报。成功不保证对端收到；失败表示拥塞或超长。
    pub fn send_datagram(&self, data: &[u8]) -> Result<(), Error>;
    
    /// 接收一个数据报。阻塞等待直到数据报到达或连接关闭。
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, Error>;
    
    /// 当前路径支持的最大数据报载荷（字节）。None = 路径不支持数据报。
    pub fn max_datagram_size(&self) -> Option<usize>;
}
```

- **不保证送达、不保证顺序、不保证不重复**。应用自己处理（音视频：丢包弃帧 + 序号 + 关键帧）。
- **与可靠流共存**：文字消息 / 文件块 / 通话信令继续走 `send` / `recv`，媒体帧走数据报。
- **路径 MTU 自动探测**：`max_datagram_size` 反映当前路径（直连 / Relay）的实际容量，应用据此切片大帧或降码率。

命名对齐 iroh `Connection`，不发明新词。

## 考虑过的替代方案

- **开第二条可靠流**（文件独占一条，避免堵文字）：文件传输切成 64 KiB 块、块之间让文字消息插队即可，文字最多等一个块（微秒级），单流够用。这是未来优化项，不挡 v1。
- **什么都不做**（媒体走可靠流）：延迟在丢包时不可控，视频通话基本不可用，排除。
- **require 数据报可用**：Relay 路径可能不支持（取决于 `iroh-relay` 版本 / 配置）。`max_datagram_size() -> Option` 让应用自己决定降级策略（拒绝通话 / 切回纯音频 / 提示网络质量差）。

## 后果

- `notes/04-app-layer.md` 同步删掉"没有数据报"表述，增加数据报使用示例（音视频场景）。
- 增加双端互发数据报的探针测试，实测直连 + n0 Relay 两条路径的延迟 / 丢包 / MTU。
- 上层应用（p2p-comm）的媒体栈基于此 API 实现 Opus（音频）+ openh264（视频）传输。
- 实现落在本 issue。
