# 漏洞修复 Agent

从漏洞报告 + 源码 → 全自动推理 → 精准补丁 + 验证报告。

**5 个 Agent 全部 LLM 化**：Impact → RootCause → Remediation → **Patch** → FailureAnalysis。
LLM 模式使用 DeepSeek API（兼容 OpenAI SDK）。

---

## 三种使用方式

### 方式 1：CLI 一行命令（最简）

```bash
# 确定性模式
python -m vuln_agent run --file vulnerability.json

# LLM 推理 + 自动加载源码
$env:DEEPSEEK_API_KEY = "sk-..."
python -m vuln_agent run --file vulnerability.json --source-dir ./src --llm

# 完整示例（使用内置 demo）
cd example_usage
python -m vuln_agent run --file vulnerability.json --source-dir . --llm
```

`--source-dir` 会自动递归加载目录下所有代码文件（`.py` `.java` `.go` `.js` `.ts` 等 40+ 种），自动跳过 `node_modules` `.git` `__pycache__` 等。

### 方式 2：Python API（集成到你的系统）

```python
from vuln_agent.runner import run_dict

# 读源码
source_code = open("src/api/search.py").read()

result = run_dict(
    # ── 漏洞报告（最简字段）──
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
    use_llm=True,
    source_files={"src/api/search.py": source_code},
    language="Python",
    framework="Flask",
)

# 取结果
print(result["status"])              # succeeded / exhausted
print(result["patch_candidate"])     # 补丁（含 unified diff）
print(result["report_markdown"])     # PR 报告
```

### 方式 3：REST API

```bash
# 启动服务
python -m vuln_agent serve --port 8000

# 仅分析
curl -X POST http://localhost:8000/v1/findings/analyze \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"F-001","vulnerability_type":"SQL Injection",...}'

# 完整修复流水线（含源码）
curl -X POST http://localhost:8000/v1/findings/fix \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "F-001",
    "vulnerability_type": "SQL Injection",
    "severity": "high",
    "affected_file": "src/api/search.py",
    "evidence": "...",
    "scanner": "SAST",
    "source_files": {
        "src/api/search.py": "def search_users(q): ..."
    },
    "language": "Python",
    "use_llm": true
  }'
```

---

## 架构

```
漏洞JSON + 源码
      │
      ▼ Normalizer（规则引擎）
      │
      ▼ ImpactAnalysisAgent（DeepSeek LLM ✓）
      │   推理：受影响服务、API入口、调用路径
      │
      ▼ RootCauseAnalysisAgent（DeepSeek LLM ✓）
      │   推理：source→sink 数据流、缺失安全控制
      │
      ▼ RemediationPlanAgent（DeepSeek LLM ✓）
      │   推理：code_change / dependency_upgrade / configuration_change
      │
      ▼ PatchGenerationAgent（DeepSeek LLM ✓）
      │   推理：读懂源码 → 生成 unified diff 补丁
      │
      ▼ ValidationToolchain（规则，5层）
      │   build → business_regression → security_regression → scanner_rescan → diff_risk
      │
  ┌───┴───┐
  通过    失败
  │       ▼
  报告    FailureAnalysisAgent（DeepSeek LLM ✓）
          诊断失败根因 → 重规划 → 重试（最多3次）
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
  "confidence": "high | medium | low"
}
```

---

## 安装

```bash
pip install -e ".[llm]"     # 含 LLM 支持
pip install -e ".[dev]"     # 含测试工具
pip install -e ".[llm,dev]" # 全部
```

## 配置 DeepSeek

```bash
$env:DEEPSEEK_API_KEY = "sk-..."                            # 必需
$env:DEEPSEEK_MODEL = "deepseek-v4-pro"                     # 可选，默认 deepseek-chat
$env:DEEPSEEK_BASE_URL = "https://api.deepseek.com"         # 可选
```

## CLI 速查

```bash
python -m vuln_agent list                                   # 列出预置 demo
python -m vuln_agent run --file <path>.json                 # 确定性模式
python -m vuln_agent run --file <path>.json --source-dir ./src --llm  # 完整 LLM 模式
python -m vuln_agent run --all-deps                         # 批量 CVE demo
python -m vuln_agent serve                                  # 启动 API
python -m vuln_agent chat                                   # 交互式对话
python -m unittest discover -s tests -v                     # 运行测试（28个）
```
