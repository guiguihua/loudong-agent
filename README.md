# 漏洞修复 Agent（Vulnerability Remediation Agent）

> 从漏洞报告 + 源码 → 全自动推理 → 精准补丁 + 验证报告

基于 **DeepSeek LLM** 的多 Agent 协作安全漏洞修复系统。5 个专业 Agent 通过 ReAct 推理循环和工具调用能力，自动完成漏洞分析、根因定位、修复方案制定、补丁生成和验证失败的诊断。

---

## 架构总览

```
漏洞 JSON + 源码
      │
      ▼ EvidenceCollector（确定性证据收集，不调用 LLM）
      │   ├── 目标文件指纹 (SHA256)
      │   ├── 有界代码切片 (上下文窗口切片)
      │   ├── 路由入口点 (FastAPI/Flask/Django/Express/Spring/Go)
      │   ├── Source / Sink 候选点 (正则匹配)
      │   ├── 依赖证据 (Manifest 扫描)
      │   ├── 测试与配置证据
      │   └── 验证能力检测 (pytest/maven/go test/semgrep)
      │
      ▼ ImpactAnalysisAgent（ReAct Agent + DeepSeek LLM）
      │   推理：受影响服务、API 入口点、调用路径、数据资产、回归目标
      │   快路径: Direct Structured → 升级路径: Evidence-driven Bounded ReAct
      │
      ▼ RootCauseAnalysisAgent（ReAct Agent + DeepSeek LLM）
      │   推理：Source → Sink 数据流、缺失/失效安全控制、安全不变量
      │   快路径: Direct Structured → 升级路径: Hypothesis–Test + ToT-lite
      │
      ▼ RemediationPlanAgent（ReAct Agent + DeepSeek LLM）
      │   推理：Plan-and-Solve + Generate-Rank-Select
      │   策略: code_change / dependency_upgrade / configuration_change
      │   路径门禁：确定性将 LLM 文本路径解析为唯一仓库文件
      │
      ▼ RepairTaskClassifier（确定性能力路由 + 证据资格门禁 + VerificationProfile）
      │
      ▼ PatchGenerationAgent / 专业 Repair Executor
      │   SQL/命令注入/路径穿越：AST ChangeSet → 隔离 Git 工作区
      │   → 结构化符号编辑 → 聚焦测试 → Git 生成 Unified Diff
      │   依赖漏洞：SCA ChangeSet → 精确修改 manifest → 版本/语法/锁文件门禁
      │   未接入专业执行器或证据不足：blocked，不进入通用补丁合成
      │
      ▼ ValidationToolchain（按漏洞类型选择 mandatory 验证层）
      │   Exact Apply / Build / Attack / Legitimate / Scanner / Diff Risk
      │
  ┌───┴───┐
  通过    失败
  │       ▼
  报告    FailureAnalysisAgent（ReAct Agent + DeepSeek LLM）
          Reflexion 诊断 → 重规划 → 重试（最多 3 次）
```

---

## 核心模块

### 1. Agent 框架 (`agent.py`)

**BaseAgent** — ReAct（Reasoning + Acting）风格 Agent 基类，实现：

| 特性 | 说明 |
|------|------|
| 多轮推理循环 | Observe → Think → Act → Observe，最多 N 轮 |
| 工具调用 | `read_file` / `search_code` / `list_dir` / `run_shell` |
| 结构化输出 | `submit_final_result` 工具，通过 JSON Schema 约束输出 |
| 工具预算 | 每个工具可限制调用次数，防止无限探索 |
| 路径门禁 | `allowed_paths` 限制 Agent 只能访问指定文件 |
| 多级回退 | Max turns → 强制输出 → 纯净上下文，3 级回退策略 |
| XML 工具调用适配 | 兼容思考模型将 function call 渲染为 XML 的场景 |

**内置工具集** (`create_default_tools`):

```python
# read_file   — 读取源文件（支持行范围，默认最多 500 行）
# search_code — 正则搜索代码（ripgrep + Python 回退）
# list_dir    — 浏览目录结构
# run_shell   — 执行 shell 命令（限 Patch/FailureAnalysis 使用）
```

### 2. 数据模型 (`models.py`)

完整的类型安全数据模型（60+ dataclass + 15+ Enum），覆盖流水线全阶段：

**枚举类型**:
- `Severity` — critical / high / medium / low / info / unknown
- `Confidence` — high / medium / low / unknown
- `AssessmentStatus` — confirmed / probable / possible / not_affected / unknown
- `RootCauseCategory` — 12 种根因分类（missing_input_validation, unsafe_api_usage, vulnerable_dependency 等）
- `RemediationStrategyType` — 7 种策略（code_change, dependency_upgrade, configuration_change 等）
- `PatchType` — code / dependency / configuration / test / virtual / documentation
- `FailureCategory` — build_failure / test_harness_failure / business_regression / security_not_fixed 等 9 种
- `ValidationLayer` — build / business_regression / security_regression / scanner_rescan / differential_risk

**核心数据结构**:
- `NormalizedVulnerability` — 标准化漏洞报告
- `EvidenceBundle` — 确定性证据集合（含切片、入口点、候选点、指纹）
- `ImpactAssessment` — 影响面评估
- `RootCauseAssessment` — 根因分析（含 Source/Sink/Propagation/SecurityInvariant）
- `RemediationPlan` — 修复方案（含策略排名、计划变更、回滚方案）
- `PatchCandidate` — 候选补丁（含 Unified Diff Artifacts）
- `PatchValidationResult` / `ValidationToolchainResult` — 验证结果
- `FailureAnalysisResult` — 失败诊断（含 Reflexion 和 do_not_repeat）
- `RemediationReport` — 完整修复报告（含 PR Markdown 和 Ticket 评论）
- `RepairLoopResult` — 修复循环最终结果

### 3. LLM 后端 (`llm.py`)

**LLMBackend** — 封装 DeepSeek API（兼容 OpenAI SDK），提供：

| 方法 | 用途 |
|------|------|
| `reason()` | 单次结构化推理（含 Schema 约束的 function calling） |
| `chat()` | 多轮对话（工具调用循环）返回 `ChatResponse{content, tool_calls, finish_reason}` |

**Schema 定义**（5 个 JSON Schema 约束各 Agent 输出）:
- `IMPACT_SCHEMA` — 影响面评估（17 个必需字段）
- `ROOT_CAUSE_SCHEMA` — 根因分析（含 hypotheses 假设-验证）
- `REMEDIATION_PLAN_SCHEMA` — 修复方案（含 candidate_rankings 多策略打分）
- `PATCH_SCHEMA` — 补丁生成
- `FAILURE_ANALYSIS_SCHEMA` — 失败诊断（含 reflection / do_not_repeat）

**智能容错**:
- 截断 JSON 自动修复（补全缺失括号）
- 从 ````json` 代码块或纯文本中提取 JSON
- Thinking 模型的 `reasoning_content` 回退解析

### 4. 5 个专业 Agent

#### ImpactAnalysisAgent (`impact.py`)
- 继承 BaseAgent，拥有 `read_file` / `search_code` / `list_dir` 工具
- 输入：漏洞报告 + EvidenceBundle + 静态上下文工具
- 输出：`ImpactAssessment`（受影响服务、API 入口、调用路径、数据分类等）
- 快路径：单次 Direct Structured 推理（temperature=0.1）
- 升级触发：置信度 < 0.4 / 高危无确认调用路径 / 入口点与证据冲突
- Deep 模式：Evidence-driven Bounded ReAct，连续两次无新证据停止
- 回退：确定性正则提取（从分析文本或漏洞报告中提取影响面信息）

#### RootCauseAnalysisAgent (`root_cause.py`)
- 继承 BaseAgent，追踪 Source → Propagation → Sink 完整数据流
- 快路径：单次 Direct Structured 推理
- Deep 模式：Hypothesis–Test + ToT-lite（提出 2-4 个竞争假设，按源码证据剪枝）
- 源码事实门禁：核对真实文件、符号和 API 契约，移除无法由 EvidenceBundle 支持的 source/sink/affected_code
- 降级策略：仅做保守的纯文本提取；不按 CVE 标签自动补全攻击链、API 或升级方案，证据不足时降置信度并转人工复核

#### RemediationPlanAgent (`remediation.py`)
- Plan-and-Solve + Generate-Rank-Select（生成 2-3 候选策略 → 多维度打分 → 选择最优）
- 打分维度：因果链切断 35% / 安全不变量 25% / 兼容性 15% / 可验证性 15% / 风险 10%
- 模板化回退：SQL 注入 → 参数化查询；依赖漏洞 → 升级声明
- **路径门禁** (`_reconcile_plan_paths`)：确定性将 LLM 输出的描述性路径解析为唯一仓库文件
- 失败反馈融合：根据上次 FailureAnalysis 的结果调整方案

#### PatchGenerationAgent (`patching.py`)
- 继承 BaseAgent，作为补丁执行入口和候选数据适配层
- SQL 注入、命令注入、路径穿越路由到 `SASTCodeRepairExecutor`
- `PythonSemanticContextBuilder` 使用 AST 获取完整目标函数、定义和直接引用，不截断目标符号
- 先创建隔离 Git 工作区并锁定文件哈希，再让 LLM 输出结构化符号编辑
- 编辑由工具按 AST 边界执行；LLM 不负责 unified diff hunk 行号
- 修改后立即执行语法检查、漏洞家族安全 Oracle 和聚焦测试
- 最终 Unified Diff 由 Git 生成，并再次使用 `git apply --check` 精确验证
- 依赖漏洞路由到 `SCADependencyRepairExecutor`，不再交给普通代码 PatchAgent
- SCA 执行器支持 requirements/pyproject/package.json/pom/go.mod/Cargo.toml，
  只选择报告给出的修复版本
- 只自动修改 manifest 中能够确认的直接依赖；仅存在于 lockfile 的传递依赖要求补充父依赖证据
- npm/pnpm/yarn/uv/PDM/Pipenv/Cargo/Go 锁文件只允许通过包管理器离线重建，
  并重新检查语法、目标解析版本和 Git diff；工具或离线缓存不足时直接阻断
- `breaking_upgrade=false` 时要求存在同主版本修复；跨主版本或明确破坏性升级必须通过
  mandatory build 与 consumer regression
- 未接入专业执行器的漏洞类型由 `RepairTaskClassifier` 标记为
  `automation_eligible=false`，不会再静默落入通用补丁生成
- 静态结构预检 (`PatchValidationAgent`)：
  - 验证 unified diff 头完整性（`---` / `+++` / `@@`）
  - 验证所有 planned_changes 都有对应 artifact
  - 验证安全回归测试是否生成
  - 验证补丁边界策略（allowed_files / diff 行数）

#### FailureAnalysisAgent (`failure_analysis.py`)
- 按验证层路由的 Hypothesis–Test + Reflexion 诊断
- 确定性分层路由：
  - Security/Scanner 失败 → `ROOT_CAUSE_AGENT`（重新做假设检验）
  - Business 回归 → `REMEDIATION_PLAN_AGENT`（重新排序）
  - Build/Diff 风险 → `PATCH_GENERATION_AGENT`（修复代码）
  - Tooling 缺口 → `VALIDATION_TOOLCHAIN` / `HUMAN_REVIEW`
- 输出 `reflection`（本轮经验）和 `do_not_repeat`（下轮禁止项）

### 5. 推理策略系统 (`reasoning.py`)

三级流水线模式，每阶段独立策略配置：

| 模式 | Impact | RootCause | Remediation | Patch | Failure |
|------|--------|-----------|-------------|-------|---------|
| **fast** | Direct Structured (4轮) | Direct Structured (4轮) | Plan-Select (1轮,不升级) | Patch Synthesis (4轮) | 不触发 |
| **balanced** | Direct Structured → Bounded ReAct (8轮) | Direct Structured → Hypothesis-Test (8轮) | Plan-Select → Bounded ReAct (4轮) | Patch Synthesis (6轮) | Reflexion (1轮) |
| **deep** | 始终 Deep (8轮) | 始终 Deep (10轮) | 始终 Deep (4轮) | Patch Synthesis (10轮) | Reflexion (1轮) |

每个 `StagePolicy` 控制：`max_turns`, `max_output_tokens`, `tool_budget`, `no_progress_limit`, `allow_escalation`

`StageExecution` 记录：使用的模式、是否升级、升级原因、LLM 调用数、工具调用详情、停止原因

### 6. 证据收集器 (`evidence.py`)

**EvidenceCollector** — 确定性无 LLM 的代码证据预处理：

- **语言检测**：识别 40+ 文件扩展名 → 语言映射
- **路由入口发现**：正则匹配 FastAPI/Flask/Django/Express/Spring/Go 路由装饰器
- **Sink 模式识别**：8 组危险函数签名（SQL/SSRF/Command/Deserialization/Path/XSS/Auth/Crypto）+ 密钥泄露检测
- **Source 模式识别**：请求对象访问点（request.args, req.query 等）+ JWT/认证参数
- **代码切片**：有界上下文窗口（默认 80 行半径）+ 字符预算（默认 50KB）
- **敏感信息脱敏**：密钥行 / Bearer Token / AWS AKIA 自动 `<redacted>`
- **测试/验证能力自动发现**：检测 pytest/maven/go/cargo/semgrep/OSV-Scanner/pip-audit 能力
- **缓存机制**：LRU 缓存（默认 64 条目），相同输入复用
- **格式化输出**：`format_evidence_bundle()` 限长输出适配 Agent prompt

### 7. 验证工具链 (`validation.py`)

**ValidationToolchain** — 按 `VerificationProfile` 选择 mandatory 层的隔离工作区验证：

```
静态预检 (PatchValidationAgent)
  ↓ 通过
隔离工作区补丁应用 + 真实验证命令执行
  ├── Build (git apply + python compileall / mvn compile)
  ├── Business Regression (pytest / npm test / go test)
  ├── Security Regression (安全回归测试)
  ├── Scanner Rescan (semgrep 复扫)
  └── Differential Risk (补丁范围策略检查)
```

**WorkspaceValidationExecutor** (`execution.py`)：
- 将候选 diff 应用到隔离的 `tempfile` 副本
- 执行用户配置的或自动发现的验证命令
- 记录命令、退出码、耗时和日志证据
- 候选补丁**绝不写入、提交或合并到原始仓库**

### 8. 报告生成 (`reporting.py`)

**RemediationReportAgent** — 生成双格式修复报告：

- **PR 描述** (`pr_description_markdown`)：完整 Markdown，含修改摘要、影响面、根因、补丁 diff、测试结果、验证结果、风险说明、回滚方案、人工审查重点
- **工单评论** (`ticket_comment_markdown`)：精简版，适合 Jira/GitHub Issue 评论
- 智能降级：根因分析不完整时，基于漏洞报告本身推断有意义的描述
- 阻断处理：补丁未生成或验证未通过时生成阻断报告

### 9. 流水线编排 (`orchestration.py`)

**PatchRepairLoopOrchestrator** — 确定性状态机编排：

```
RemediationPlan → PatchGeneration → Validation
                                      ↑      ↓
                          FailureAnalysis ←── 失败
                              ↓
                    重新 RootCause / Remediation（最多 3 次）
```

### 10. 漏洞标准化 (`normalization.py`)

**VulnerabilityNormalizer** — 确定性规则引擎：
- 严重性别名（中英文）：critical → 严重 → high → 高等
- 类型别名：sqli → SQL Injection, xss → Cross-Site Scripting 等
- SARIF 格式兼容（自动提取 `ruleId`, `physicalLocation`, `message.text`）
- 依赖信息提取（component, current_version, fixed_versions）
- 稳定 ID 生成（SHA256 哈希）
- LLM 辅助接口（预留给规则无法确认的字段）

### 11. Web UI (`api.py` + `web/`)

基于 FastAPI + Jinja2 的完整 Web 平台：

**页面路由**:
| 路径 | 功能 |
|------|------|
| `/` | 仪表盘（任务统计 + 最近任务） |
| `/new` | 新建修复任务（JSON / 表单 / 仓库绑定） |
| `/finding/{id}` | 漏洞详情/修复结果 |
| `/chat` | 实时 WebSocket 聊天（漏洞分析对话） |
| `/repo` | 仓库浏览器（Git 仓库克隆/绑定/浏览） |
| `/history` | 历史记录 |

**API 端点**:
| 方法 | 路径 | 功能 |
|------|------|------|
| `POST` | `/v1/findings/analyze` | 分析（标准化 + 影响面 + 根因） |
| `POST` | `/v1/findings/fix` | 同步修复流水线 |
| `POST` | `/api/tasks` | 创建异步修复任务 |
| `GET` | `/api/tasks/{id}` | 任务状态/进度（5 阶段） |
| `GET` | `/api/tasks/{id}/result` | 任务完整结果 |
| `GET` | `/api/history` | 历史记录列表 |
| `POST` | `/api/git/clone` | 克隆仓库 |
| `POST` | `/api/git/bind-local` | 绑定本地仓库 |
| `GET` | `/api/git/repos` | 仓库列表 |
| `GET` | `/api/git/{id}/tree` | 文件树 |
| `GET` | `/api/git/{id}/file` | 文件内容 |
| `GET` | `/api/git/{id}/commits` | 提交历史 |
| `GET` | `/api/examples` | 示例库列表 |
| `POST` | `/api/examples/load` | 加载示例漏洞数据+源码 |
| `WS` | `/ws/chat` | 实时聊天 |

**任务进度追踪**（5 阶段）:
1. 标准化 + 证据收集
2. 影响面分析
3. 根因分析
4. 修复方案 + 补丁生成
5. 报告生成

**智能报告解析** (`_prepare_raw_report`)：
- 自动识别 YAML/JSON 格式安全报告
- CVE/CWE 正则提取
- 漏洞类型关键词匹配（10+ 种常见类型）

### 12. CLI (`cli.py`)

完整命令行工具：

```bash
# 列出预置 demo
python -m vuln_agent list

# 运行预置 demo
python -m vuln_agent run code-sqli         # SQL 注入 (Flask)
python -m vuln_agent run django-alias      # Django ORM Alias 注入
python -m vuln_agent run struts-cve        # Struts2 CVE-2017-5638
python -m vuln_agent run log4j-cve         # Log4Shell CVE-2021-44228
python -m vuln_agent run spring-cve        # Spring4Shell CVE-2022-22965
python -m vuln_agent run commons-text-cve  # Commons Text CVE-2022-42889
python -m vuln_agent run vc-django         # Django 5.0.6 SQL 注入依赖升级

# 批量运行
python -m vuln_agent run --all             # 所有 demo
python -m vuln_agent run --all-deps        # 所有 CVE demo

# 从 JSON 文件运行
python -m vuln_agent run --file vulnerability.json
python -m vuln_agent run --file vuln.json --source-dir ./src
python -m vuln_agent run --file vuln.json --source-dir ./src --run-mode deep
python -m vuln_agent run --file vuln.json --analyze-only

# 启动 API
python -m vuln_agent serve --port 8000

# 交互式对话
python -m vuln_agent chat

# 评估测试
python -m vuln_agent evaluate
python -m vuln_agent evaluate --demo code-sqli django-alias
```

### 13. 预置 Demo (`demos.py`)

7 个预置漏洞场景（`DemoPreset`），每个封装完整的：

| Demo Key | 类型 | 漏洞 | 修复策略 |
|----------|------|------|----------|
| `code-sqli` | 代码修复 | Flask SQL 注入（字符串拼接） | 参数化查询 |
| `django-alias` | 代码修复 | Django ORM Alias 注入（set_values 缺少 check_alias） | 别名校验 |
| `struts-cve` | 依赖升级 | Apache Struts2 CVE-2017-5638 RCE | 升级 struts2-core |
| `log4j-cve` | 依赖升级 | Log4Shell CVE-2021-44228 JNDI 注入 | 升级 log4j-core |
| `commons-text-cve` | 依赖升级 | Commons Text CVE-2022-42889 不安全插值 | 升级 commons-text |
| `spring-cve` | 依赖升级 | Spring4Shell CVE-2022-22965 不安全数据绑定 | 升级 spring-webmvc |
| `vc-django` | 依赖升级 | Django 5.0.6 SQL 注入（validation-coverage fixture） | 升级到 5.0.8 |

每个 Demo 包含：上下文工厂函数、源码文件、验证摘要（含真实 payload 和断言）

### 14. 工具上下文 (`tools.py`)

静态适配器工具协议：

| 工具 | 收集内容 | 用途 |
|------|---------|------|
| `CodeContextTool` | 服务、调用路径、入口点、数据分类、上下游依赖 | Impact |
| `AssetInventoryTool` | 部署资产、受影响的构建制品 | Impact |
| `RuntimeEvidenceTool` | 运行时路由、调用路径 | Impact |
| `RootCauseEvidenceTool` | Source/Sink 线索、Guard/Failed Control、触发条件、依赖上下文 | RootCause |

`Static*` 实现为字典查找适配器，可替换为 AST/索引/调用图适配器。

### 15. 评估框架 (`evaluate.py`)

内置评估测试流程：

- **Schema 校验器**：验证每个 Agent 输出的必需字段完整性
- **补丁统计**：artifact 数量、修改文件数、diff 行数
- **对比报告**：LLM vs 确定性模式的成功率/耗时对比
- **输出格式**：Markdown + JSON 双格式报告
- **改进建议**：基于成功率、耗时和边界用例崩溃自动生成建议

### 16. 配置管理 (`config.py`)

- `.env` 文件自动加载 (`load_env_file`)
- 配置状态安全报告（密钥脱敏）
- LLM / GitHub / GitLab 连接状态检测

---

## 三种使用方式

### 方式 1：CLI 一行命令

```powershell
# 设置 API Key
$env:DEEPSEEK_API_KEY = "sk-..."

# 完整 LLM 模式
python -m vuln_agent run --file vulnerability.json --source-dir ./src

# 使用 deep 推理策略
python -m vuln_agent run --file vulnerability.json --source-dir ./src --run-mode deep

# 启动 Web 服务
python -m vuln_agent serve --port 8000
```

### 方式 2：Python API

```python
from vuln_agent.runner import run_dict

source_code = {"src/api/search.py": open("src/api/search.py").read()}

result = run_dict(
    {
        "finding_id": "F-001",
        "vulnerability_type": "SQL Injection",
        "severity": "high",
        "affected_file": "src/api/search.py",
        "affected_function": "search_users",
        "line": 42,
        "evidence": "user input concatenated into SQL",
        "scanner": "SAST",
    },
    source_files=source_code,
    language="Python",
    framework="Flask",
)

print(result["status"])           # succeeded / exhausted / blocked
print(result["patch_candidate"])  # 补丁（含 unified diff artifacts）
print(result["report_markdown"])  # PR 报告
```

### 方式 3：REST API

```bash
# 分析
curl -X POST http://localhost:8000/v1/findings/analyze \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"F-001","vulnerability_type":"SQL Injection",...}'

# 完整修复
curl -X POST http://localhost:8000/v1/findings/fix \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"F-001","vulnerability_type":"SQL Injection",...}'

# 异步任务
curl -X POST http://localhost:8000/api/tasks \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"F-001","vulnerability_type":"SQL Injection",...}'
```

---

## 漏洞报告 JSON 字段参考

```jsonc
{
  // ── 必需字段 ──
  "finding_id": "F-XXX-001",
  "vulnerability_type": "SQL Injection | Cross-Site Scripting | Path Traversal | dependency | ...",
  "severity": "critical | high | medium | low",
  "scanner": "SAST | SCA | 手动",

  // ── 代码漏洞 ──
  "affected_file": "src/api/search.py",
  "affected_function": "search_users",
  "line": 42,
  "evidence": "描述漏洞的具体证据",
  "recommendation": "修复建议（可选）",

  // ── 依赖漏洞 ──
  "component": "org.apache.struts:struts2-core",
  "current_version": "2.3.31",
  "fixed_versions": ["2.3.32", "2.5.10.1"],
  "breaking_upgrade": false,

  // ── 可选 ──
  "cve": "CVE-2017-5638",
  "cwe": "CWE-89",
  "repository": "https://github.com/org/repo",
  "confidence": "high | medium | low",

  // ── 可审计验证 ──
  "validation_commands": {
    "build": "python -m compileall -q .",
    "business_regression": "python -m pytest tests -q",
    "security_regression": "python -m pytest tests/test_cve_xxx.py -q",
    "scanner_rescan": "semgrep scan --config auto ."
  },
  "validation_timeout": 300
}
```

---

## 安装

```bash
# 基础安装
pip install -e .

# 含 LLM 支持
pip install -e ".[llm]"

# 含测试工具
pip install -e ".[dev]"

# 全部
pip install -e ".[llm,dev]"
```

依赖：
- Python ≥ 3.11
- FastAPI + Uvicorn（Web API）
- Jinja2（模板渲染）
- GitPython（仓库管理）
- OpenAI SDK（DeepSeek LLM，可选）

---

## 配置 DeepSeek

```powershell
$env:DEEPSEEK_API_KEY = "sk-..."                            # 必需
$env:DEEPSEEK_MODEL = "deepseek-v4-pro"                     # 可选，默认 deepseek-chat
$env:DEEPSEEK_BASE_URL = "https://api.deepseek.com"         # 可选
```

或创建 `.env` 文件：

```env
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=deepseek-chat
```

---

## 运行测试

```bash
python -m pytest tests -q -p no:cacheprovider  # 仅运行本项目测试；排除 validation-coverage 上游快照
python -m vuln_agent evaluate              # Agent 评估流程
```

---

## 项目结构

```
loudong-agent/
├── src/vuln_agent/
│   ├── __init__.py          # 包导出
│   ├── agent.py             # BaseAgent ReAct 框架 + 工具集
│   ├── api.py               # FastAPI 应用 + REST API + WebSocket
│   ├── cli.py               # CLI 入口 (list/run/serve/chat/evaluate)
│   ├── config.py            # .env 加载 + 配置状态
│   ├── demos.py             # 7 个预置 Demo 注册表
│   ├── evaluate.py          # 评估框架 (Schema 校验 + 指标收集 + 对比报告)
│   ├── evidence.py          # EvidenceCollector 确定性证据收集
│   ├── execution.py         # WorkspaceValidationExecutor 隔离验证
│   ├── failure_analysis.py  # FailureAnalysisAgent (Reflexion 诊断)
│   ├── impact.py            # ImpactAnalysisAgent (影响面分析)
│   ├── llm.py               # LLMBackend (DeepSeek API) + 5 个 JSON Schema
│   ├── models.py            # 60+ dataclass + 15+ Enum 数据模型
│   ├── normalization.py     # VulnerabilityNormalizer 标准化
│   ├── orchestration.py     # PatchRepairLoopOrchestrator 流水线编排
│   ├── patching.py          # PatchGenerationAgent + PatchValidationAgent
│   ├── semantic.py          # Python AST 语义上下文 + ChangeSet
│   ├── sast_executor.py     # SQL/命令注入/路径穿越隔离工作区执行器
│   ├── sca_executor.py      # 多生态依赖声明升级与锁文件一致性门禁
│   ├── routing.py           # 漏洞家族、执行器和 VerificationProfile 路由
│   ├── quality.py           # 单任务补丁质量门禁
│   ├── baseline.py          # Verified Patch Rate 与发布门禁
│   ├── reasoning.py         # PipelineMode / ReasoningMode / StagePolicy
│   ├── remediation.py       # RemediationPlanAgent (Plan-and-Solve + Ranking)
│   ├── reporting.py         # RemediationReportAgent (双格式报告)
│   ├── root_cause.py        # RootCauseAnalysisAgent (CVE 知识注入)
│   ├── runner.py            # run_dict / run_file 公共 API
│   ├── service.py           # IntakeImpactService 分析服务
│   ├── tools.py             # 静态适配器工具 (CodeContext / AssetInventory / RootCauseEvidence)
│   ├── validation.py        # ValidationToolchain (5 层验证)
│   ├── web/                 # Web 模块
│   │   ├── chat.py          # WebSocket 聊天管理器
│   │   ├── git_handler.py   # Git 仓库管理
│   │   ├── routes.py        # 页面路由
│   │   └── tasks.py         # 异步任务管理器
│   ├── templates/           # Jinja2 模板 (7 个页面)
│   └── static/              # 静态资源
├── examples/                # 5 个漏洞 JSON 示例
├── validation-coverage/     # Django 5.0.6 本地验证 fixture
├── tests/                   # 4 个测试模块
├── outputs/                 # 运行输出目录
├── .data/                   # 服务器运行数据
├── pyproject.toml           # 项目配置
├── CLAUDE.md                # Claude Code 指令
└── README.md                # 本文件
```

---

## 设计原则

1. **标准化是确定性数据管道**：漏洞归一化由规则引擎完成，不由 Agent 自由推理
2. **LLM 只补全规则无法确认的字段**：输出必须通过 Schema 校验
3. **影响面结论必须引用证据**：显式列出未知项，不能从漏洞类型直接推断
4. **根因由数据流/依赖/配置证据支撑**：不得仅凭漏洞类型名称推导
5. **候选补丁不写入原始仓库**：真实验证在隔离工作区执行
6. **分层升级策略**：fast/balanced 默认走单次结构化快路径，只有证据门槛不满足时才升级到 deep
7. **修复只使用当前仓库证据**：官方补丁或参考答案不进入 Agent 上下文
8. **缺少关键证据时输出 `needs_human_review`**：不得继续自动修复
