# Kaggle AI Agent Security - Multi-Step Tool Attacks

这是对应 Kaggle **AI Agent Security - Multi-Step Tool Attacks**的 GitHub 仓库。
竞赛：在官方离线沙箱中构建自动化攻击算法，寻找工具调用智能体可稳定复现的安全失效。

> **使用范围：** 仅限 Kaggle 官方沙箱、授权红队测试与防御研究，详见 [SECURITY.md](ass_repo/SECURITY.md)。

## 赛后记录

上传文件中的赛后材料记录：最终 non-marker 方案为 **公榜第 148 / 私榜第 31 / 银牌**。本仓库只负责整理、
保留和工程化这些文件，不重新声称或推导 Kaggle 排名。

## 最终方案的工程主线

该项目不是训练模型权重，而是一个**分模型、轨迹驱动的策略搜索系统**：

1. 识别当前目标模型为 GPT-OSS 或 Gemma；
2. 两个模型分别维护 20 个 k1 Profile；
3. 每个 Profile 在线探测 30 次，取尾部 20 次统计；
4. 从真实执行轨迹统计成功工具动作与耗时，以 `raw/s` 为主指标选型；
5. 对选出的 Profile 使用确定性索引扩展到每模型最多 2,000 个单消息候选；
6. 在提交前执行候选形状检查与 marker 排除检查，再交给官方环境独立回放。

赛后材料中最关键的策略变化，是从依赖固定 marker 的高公榜 EXFILTRATION 路线，切换到不依赖 marker 的
`CONFUSED_DEPUTY` 路线，以降低隐藏防护下整条路径失效的迁移风险。

## 仓库结构

```text
.
├── submission/attack.py             # 从最终 CD.py 中精确提取的独立提交文件
├── notebooks/final_submission.py    # 最终 notebook 导出源码
├── src/aas_solution/                # 重构后的路由、计分、审计等可测试核心逻辑
├── experiments/extracted_modules/   # 原始 Profile / Builder 实验模块
├── baselines/secret_marker.py       # 早期 marker 基线
├── scripts/                          # 提交重建、静态校验、Profile 审计
├── tests/                            # 不依赖官方 SDK 的单测
├── docs/                             # 架构、算法、风险、已知问题、来源映射
└── .github/workflows/ci.yml          # GitHub Actions CI
```

## 本地检查

```bash
export PYTHONPATH=src
python -m unittest discover -s tests -v
python scripts/verify_submission.py
python scripts/profile_audit.py
```

或者：

```bash
make test
make verify
make audit
make compile
```

## 重新生成最终 `attack.py`

```bash
python scripts/extract_final_attack.py \
  notebooks/final_submission.py \
  --output submission/attack.py
```

`submission/attack.py` 是比赛产物，建议视为**只读历史版本**。`src/aas_solution/` 是为了 GitHub 可读性与测试性
整理出的参考实现，不应与最终 Kaggle 运行文件混为一谈。

## 进一步阅读

- [架构说明](docs/architecture.md)
- [算法说明](docs/algorithm.md)
- [赛后风险分析](docs/risk-analysis.md)
- [已知问题](docs/known-issues.md)
- [原始文件到仓库文件的映射](docs/provenance.md)

竞赛主页：<https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks>

## License
