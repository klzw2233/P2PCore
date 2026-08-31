# CLAUDE.md

P2PCore 仓库级指引。细化全局 `~/.claude/CLAUDE.md`。

## 项目状态

**设计完成,尚未写一行代码。** 接手前先读 [HANDOFF.md](./HANDOFF.md)。

## 动手前必读(按顺序)

1. **[CONTEXT.md](./CONTEXT.md)** — 术语表。所有文档和代码用词以它为准,不要漂移到同义词。
2. **[README.md](./README.md)** — 架构、威胁模型、信任模型。
3. **`docs/adr/0001` ~ `0006`** — 六篇决策记录,解释了每一个"为什么不做 X"。

## 三条硬约束

1. **`crates/p2p-trust/Cargo.toml` 中不得出现 iroh、tokio 或任何网络库。** 这是整个架构唯一由编译器保护的边界,打穿它等于废掉 ADR-0002 和 ADR-0005。
2. **不要静默推翻已定的决定。** 六篇 ADR 里的每一条都经过完整论证。确有理由推翻时,写新 ADR 并标注 supersedes。
3. **默认答案是"不加"。** 本项目的设计方向是砍组件——每砍掉一个组件就砍掉它的全部攻击面。提议新增任何东西时,先论证其价值超过它打开的攻击面。

## 措辞红线

对外描述本项目时,**不得**使用"匿名""无法追踪"。准确措辞是"**服务端无法读取通信内容**"。服务端确实掌握完整的通信关系图,这是刻意接受的(ADR-0001)。

## 待核实

三个事实因 web 工具限流一直未能确认,**动工前必须查**,详见 HANDOFF.md:iroh 能否包装底层 socket、`noq` 是什么、iroh 版本与 API 稳定性。

## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI (**no git remote configured yet — all `gh` commands currently fail**). See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical roles, used verbatim as label strings. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
