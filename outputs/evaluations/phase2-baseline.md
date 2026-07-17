# Phase 2 Routing / SCA Completion Baseline

评估日期：2026-07-17  
分支：`具有路由器的agent`  
阶段状态：100%

## 完成定义

阶段 2 按以下五项原始目标验收：

1. 新增确定性的 `RepairTaskClassifier`。
2. 输出漏洞家族、证据完整度、执行器、自动化资格和 Verification Profile。
3. 接入独立的 SCA 依赖升级执行器。
4. 信息不足或能力未接入时停止生成补丁。
5. 失败按类别回退到具体节点，不固定重跑整条流水线。

五项均已实现并具有自动化测试。

## RepairTaskClassifier

路由结果包含：

- `family`
- `preferred_executor`
- `active_executor`
- `verification_profile`
- `confidence`
- `missing_evidence`
- `automation_eligible`
- `blocking_reasons`
- `fallback_reason`

自动化资格为 false 时，`PatchGenerationAgent` 在任何 LLM 或专业执行器调用前直接生成 `blocked` 结果。

当前真实专业执行能力：

| 家族 | Active Executor | 自动化条件 |
|---|---|---|
| SQL/命令注入/路径遍历 | SASTCodeRepairExecutor | 目标源码存在 |
| 依赖漏洞 | SCADependencyRepairExecutor | 当前版本、修复版本、直接依赖 manifest 存在 |
| 尚未实现的 XSS/SSRF/配置/内存/权限执行器 | 无 | 明确 `automation_eligible=false` |

路由器不再把尚未接入的专业能力标成 active，也不会静默落到通用补丁生成。

## SCADependencyRepairExecutor

### 支持的直接依赖声明

- Python：`requirements.txt`、PEP 621/Poetry `pyproject.toml`
- Node.js：`package.json`
- Maven：`pom.xml`
- Go：`go.mod`
- Rust：`Cargo.toml`

### 版本选择

- 目标版本只能来自报告的 `fixed_versions`。
- 拒绝比 `current_version` 更旧的修复版本。
- `breaking_upgrade=false` 时必须存在同主版本修复。
- 报告当前版本必须与 manifest 中的直接声明精确匹配。
- 明确记录 `same_major_upgrade`、`major_version_change` 或 `declared_breaking_upgrade`。

### 直接与传递依赖

- 只自动修改 manifest 中确认的直接依赖。
- 如果组件只存在于 lockfile，则判定为传递依赖。
- 传递依赖不会被猜测式提升；必须补充父依赖或 override/resolution 策略证据。

### 锁文件

锁文件不得手工替换版本或伪造 checksum/integrity。只有下列离线包管理器操作可以生成候选：

- npm：`npm install --package-lock-only --ignore-scripts --offline`
- pnpm：`pnpm install --lockfile-only --offline --ignore-scripts`
- Yarn：`yarn install --offline --ignore-scripts --non-interactive`
- uv：`uv lock --offline`
- PDM：`pdm lock --offline`
- Pipenv：`PIP_NO_INDEX=1 pipenv lock`
- Cargo：`cargo update -p <component> --precise <version> --offline`
- Go：`GOPROXY=off GOSUMDB=off go mod tidy`

Poetry 不同版本缺少一致、可证明的离线锁定契约，因此默认阻断并要求接入可重复的 lockfile regenerator。

锁文件生成后必须同时满足：

1. 文件确实发生变化。
2. JSON/TOML 或文本结构仍有效。
3. 目标组件解析到修复版本。
4. Git 能生成 manifest 与 lockfile 的完整精确 diff。

任何命令缺失、离线缓存不足、解析版本不符或锁文件未变化都会进入 `blocked`。

## 验证策略

依赖升级 Profile 的 mandatory 层：

```text
exact apply / build
business regression
SCA rescan（检测到可执行扫描器时）
differential risk
```

扫描能力发现：

- OSV-Scanner
- pip-audit

扫描器只有在当前环境真实可执行时才进入 mandatory profile。不能用静态 “passed” 标签代替命令、退出码和日志。

## 分类失败回退

| 失败类别 | 回退节点 |
|---|---|
| security_not_fixed / scanner_still_reports | RootCauseAnalysisAgent |
| business_regression | RemediationPlanAgent |
| build / diff risk / patch policy / test harness | PatchGenerationAgent |
| tooling_gap | ValidationToolchain |
| unknown | Human review |

该映射由确定性策略执行并有 9 类参数化测试。

## 验收结果

| 指标 | 结果 |
|---|---:|
| 本项目测试 | 120/120 |
| 参数化子样本 | 58/58 |
| SCA 单元/E2E 测试 | 15/15 |
| 多生态直接依赖矩阵 | 15/15 |
| 锁文件成功重建路径 | 通过 |
| 锁文件不可重建阻断路径 | 通过 |
| 传递依赖阻断路径 | 通过 |
| 版本不一致阻断路径 | 通过 |
| 非破坏性跨主版本阻断路径 | 通过 |
| 分类失败回退矩阵 | 9/9 |
| blocked 误报 success | 0 |

完整测试命令：

```text
python -m pytest tests -q -p no:cacheprovider
```

## 设计边界

以下行为是阶段 2 的安全边界，不是未完成项：

- 没有父依赖证据时不自动修复传递依赖。
- 没有离线工具或缓存时不生成锁文件。
- 没有真实 build/business/scanner 证据时不标记 verified。
- 未接入专业执行器的漏洞家族不进入通用补丁生成。

阶段 3 未开始。本阶段没有引入或接入 PatchAgent。
