# Kaggle AI Agent Security — Multi-Step Tool Attacks

> Kaggle AI Agent Security 竞赛方案整理与赛后工程归档。
> 本项目聚焦 **Tool-Using Agent 的自动化安全测试与多步攻击搜索**：通过对目标 Agent 的执行轨迹、工具调用行为和模型差异进行分析，自动搜索可稳定复现的安全失效路径。

## 项目简介

随着 LLM Agent 开始具备工具调用、任务规划和多步执行能力，其安全问题不再局限于单轮 Prompt Injection，而逐渐演化为：

- 多轮交互中的指令劫持；
- 工具调用链上的权限与上下文混淆；
- Agent 在复杂执行轨迹中的错误决策传播；
- 不同模型面对相同攻击策略时表现出的差异化脆弱性。

本项目基于 Kaggle **AI Agent Security — Multi-Step Tool Attacks** 竞赛环境，设计了一套自动化攻击搜索方法，让攻击策略不再依赖人工逐条编写 Prompt，而是通过在线探测、执行轨迹分析和候选策略搜索，自动寻找更稳定的攻击路径。

竞赛页面：
[AI Agent Security — Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)

---

## 核心方案

最终方案可以概括为：

**Model-Specific Routing + Online Probing + Trace-Guided Search + Deterministic Candidate Generation**

整体流程如下：

```text
Target Agent
    ↓
识别目标模型（GPT-OSS / Gemma）
    ↓
加载对应攻击策略池
    ↓
在线 Sandbox 探测
    ↓
收集 Tool Call / Execution Trace / Latency
    ↓
对候选攻击 Profile 进行评分与筛选
    ↓
选择当前目标模型下的最优策略
    ↓
确定性扩展生成大规模候选攻击序列
    ↓
官方环境独立 Replay 与评分
```

与普通 Prompt Engineering 不同，这里的优化对象不是某一条固定 Prompt，而是一个能够根据目标模型和执行反馈动态选择攻击策略的 **Attack Algorithm**。

---

## 技术亮点

### 1. 模型差异化攻击策略

针对 GPT-OSS 与 Gemma 分别维护独立的攻击 Profile Pool，避免假设“一套 Prompt 可以迁移到所有模型”。

通过模型级路由，将攻击策略选择从静态模板升级为 **model-aware search**。

### 2. 基于执行轨迹的在线搜索

候选攻击策略会先在官方 Sandbox 中进行多轮探测，并记录：

- 工具调用行为；
- 有效 Action 数量；
- 执行轨迹；
- 请求耗时；
- 多次执行的稳定性。

随后利用这些观测信号构造本地搜索指标，对攻击 Profile 进行排序，从而在正式生成候选攻击前完成一次轻量级在线策略选择。

### 3. Search-Then-Generate

项目没有直接暴力生成大量 Prompt，而是将流程拆成两个阶段：

```text
Search Phase
找到当前模型下表现更稳定的攻击策略

        ↓

Generation Phase
基于选中的策略进行确定性参数扩展
```

这种方式减少了低质量候选在有限评测预算中的占比，同时提高攻击候选的可复现性。

### 4. 从 Marker 依赖到 Non-Marker 方案

早期实验使用过依赖特定 `SECRET_MARKER` 行为的攻击路线。

赛后分析发现，这种策略对评测环境中的特定可观察行为依赖较强，泛化风险较高。因此最终方案进一步转向 **non-marker / confused-deputy-style** 攻击路径，使攻击策略更依赖 Agent 本身的工具执行逻辑，而不是单一触发标记。

### 5. 可复现的候选生成

最终候选采用确定性参数展开，而不是完全随机搜索。

这保证了：

- 相同输入能够重新生成一致候选；
- 更容易定位有效攻击路径；
- 便于进行赛后复盘、单元测试与策略审计。

---

## 竞赛结果

根据赛后保留的比赛记录：

- **Private Leaderboard：31**
- **Public Leaderboard：148**
- **Silver Medal**

Public / Private 排名差异也反映出 Agent Security 任务中的一个重要问题：

> 对公开评测环境过度拟合的攻击策略，并不一定能稳定迁移到隐藏评测环境。

因此本项目赛后重点复盘了 **攻击策略的稳定性、模型差异、环境依赖与 hidden-evaluation generalization**。

---

## 项目结构

仓库中的完整代码、实验模块和技术文档位于：

[`aas_repo/`](./aas_repo/)

其中包含：

```text
aas_repo/
├── submission/      # 最终比赛提交代码
├── src/             # 赛后工程化拆分
├── experiments/     # GPT / Gemma Profile 实验
├── baselines/       # 早期攻击基线
├── tests/           # 单元测试与静态校验
├── scripts/         # 提交重建与审计脚本
└── docs/            # 架构、算法、风险分析与赛后复盘
```

如果希望进一步了解具体实现，请阅读：

**[工程 README](./aas_repo/README.md)**

---

## 项目关注的问题

这个项目本质上关注的不是“如何写一个更强的越狱 Prompt”，而是如何将 Agent Security 建模成一个可搜索、可评估、可复现的系统问题：

```text
Agent Security
    = Model Behavior
    + Tool Permissions
    + Execution Trace
    + Context / State
    + Search Strategy
    + Evaluation Environment
```

因此它同时涉及：

- AI Agent / Tool Calling
- Automated Red Teaming
- Prompt Injection
- Multi-Step Attack
- Execution Trace Analysis
- Search & Ranking
- AI Safety Evaluation

---

## 说明

本仓库仅用于：

- Kaggle 官方竞赛环境；
- AI Agent 安全研究；
- 授权 Red Team 测试；
- 防御与安全评测方法研究。

请勿将其中的方法用于未经授权的真实系统攻击。

更详细的安全说明见：
[SECURITY.md](./aas_repo/SECURITY.md)

---

## Acknowledgements

感谢 Kaggle **AI Agent Security — Multi-Step Tool Attacks** 竞赛提供的 Agent Security 测试环境与评测框架。

该仓库为赛后代码整理版本，重点保留比赛方案、实验过程以及对 Agent 自动化安全测试方法的工程化复盘。
