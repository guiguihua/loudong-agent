# Phase 0 / Phase 1 Verified Patch Baseline

评估日期：2026-07-17  
分支：`具有路由器的agent`

## 阶段结论

- 阶段 0：100%。假成功、占位 artifact、fuzzy apply、硬编码边界和 Web blocked 状态问题已完成治理。
- 阶段 1：100%（按原计划的工程范围）。首批 SQL 注入、命令注入、路径穿越均已进入独立 SAST 工作区执行器。
- 阶段 2：100%。完整验收见 `outputs/evaluations/phase2-baseline.md`。

“阶段 1 100%”表示原计划的工程能力全部实现并通过本地验收，不表示已经证明跨所有框架、驱动和代码风格的生产泛化率。

## 阶段 1 验收范围

执行路径：

```text
Normalizer
→ EvidenceCollector
→ VulnerabilityRouter / family VerificationProfile
→ Python AST 完整符号上下文
→ ChangeSet
→ 隔离 Git 工作区
→ LLM 结构化编辑或保守确定性 AST 兜底
→ 语法检查
→ 漏洞家族安全 Oracle
→ 聚焦攻击/合法行为测试
→ Git 生成 Unified Diff
→ git apply --check
```

已满足：

1. 工作区在生成补丁前创建，原始仓库不被写入。
2. 目标函数按 AST 完整范围读取，不再受 24,000 字符截断影响。
3. 先形成 ChangeSet，再执行符号级编辑。
4. 模型不计算 hunk 行号，最终 diff 由 Git 生成。
5. 每轮编辑后执行 Python 语法检查、家族安全 Oracle 和可用的聚焦测试。
6. SQL 注入、命令注入、路径穿越分别使用独立安全不变量。
7. SQL、命令、路径三类均有无 LLM 的保守确定性路径；不能证明安全改写时返回 `blocked`。
8. 命令注入和路径遍历生成的攻击/合法行为测试已在隔离工作区真实执行。

## 回归结果

| 指标 | 结果 | 门槛 |
|---|---:|---:|
| 本项目自动化测试 | 120/120（100%） | 100% |
| 参数化子样本 | 34/34（100%） | 100% |
| 阶段 1 三类稳定性矩阵 | 32/32（100%） | ≥60% |
| SQL 注入样本 | 12/12 | — |
| 命令注入样本 | 10/10 | — |
| 路径穿越样本 | 10/10 | — |
| 候选补丁精确应用 | 32/32 | 100% |
| blocked/failed 误报 success | 0 | 0 |
| 通用 Prompt 特例污染数 | 0 | 0 |

测试命令：

```text
python -m pytest tests -q -p no:cacheprovider
```

结果：

```text
120 passed, 58 subtests passed
```

## 三类安全 Oracle

### SQL 注入

- 拒绝 f-string、字符串拼接、`format()` 或 `%` 格式化结果直接到达 `execute`。
- 要求查询占位符具有第二个绑定参数。
- 确定性兜底把简单 DB-API 拼接改为参数绑定。
- 生成攻击输入和合法输入双向回归测试。

### 命令注入

- 拒绝 `os.system`、`os.popen`、`shell=True`。
- 要求 `subprocess` 的命令为结构化 list/tuple argv。
- 确定性兜底只处理能够证明 token 边界的简单 shell 表达式。
- 对 `os.system` 返回路径保留 return-code 语义。
- 攻击 payload 必须作为单一 argv 元素，合法主机输入仍可执行。

### 路径遍历

- 候选路径与根目录都必须先 `resolve()`。
- 目标符号内必须存在真实的 `is_relative_to`、`relative_to` 或 `commonpath` containment 检查。
- 字符串注释或 marker 不能骗过 AST Oracle。
- 攻击路径 `../outside` 被拒绝，根目录内合法文件仍可访问。

## 适用性说明

当前 32 个矩阵样本是可重复的本地工程验收集，用于防止执行器和安全 Oracle 回归；它不是隐藏的生产统计集。现有证据能够证明阶段 1 执行链闭环，但不能单独代表跨项目泛化准确率。后续持续评估仍应引入不进入 Prompt 的外部项目样本，并分开报告：

- executor acceptance rate；
- full mandatory validation pass rate；
- Verified Patch Rate；
- false-block 与 false-accept rate。

## 阶段 2 当前证据

- 15 个 SCA 测试全部通过，包含 17 个多生态参数化子样本。
- 支持 requirements、PEP 621/Poetry pyproject、npm package.json、Maven pom、go.mod、Cargo.toml。
- 固定版本只能从报告的 `fixed_versions` 中选择；`breaking_upgrade=false` 时优先并要求同主版本。
- manifest 会重新解析并检查目标版本存在、旧版本消失。
- 匹配的锁文件无法在当前环境可靠重建时明确 `blocked`，不会伪造 integrity、checksum 或解析结果。
- 内置 Struts 案例已生成 `2.3.31 → 2.3.32` 的精确 Maven diff；由于 fixture 不是完整 Maven 工程，mandatory build/business validation 未配置，因此结果保持 `blocked/review`，没有误报 verified。
- 自包含 Python 依赖案例已完整通过 exact apply、build、consumer regression 和 differential risk mandatory validation。
