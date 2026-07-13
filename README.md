# Vulnerability Intake & Impact Analysis

补丁生成与验证 Agent 的第一阶段实现，覆盖：

1. 漏洞输入与规则优先的标准化；
2. 代码、API、资产、SBOM、运行时和测试上下文采集；
3. 基于工具证据的影响面分析；
4. 基于 Source/Guard/Sink、依赖和配置证据的根因定位；
5. 对低置信度字段预留 LLM 辅助接口；
6. 输出结构化证据、未知项和自动化决策建议。

## 快速运行

```powershell
python -m unittest discover -s tests -v
python -m pip install -e .
uvicorn vuln_agent.api:app --reload
```

## 可审计的完整验证

调用 `run_dict`、`run_file` 或 REST API 时可提供 `validation_commands`。系统会把候选
unified diff 应用到隔离的临时工作区，再执行真实命令；报告会记录命令、退出码、耗时和
截取日志。候选补丁不会写入、提交或合并到原始仓库，只作为人工审查参考。缺少任一必需
层或只有 `passed` 标签而没有执行证据时，报告会被阻断。

修复 Agent 只使用漏洞报告和当前仓库中的源码、配置、依赖及测试证据制定方案。官方补丁
或参考答案不进入 Agent 上下文；如验证集包含参考修复，它只能在 Agent 完成后用于离线评分。

```json
{
  "validation_commands": {
    "build": "python -m compileall -q .",
    "business_regression": "python -m pytest tests -q",
    "security_regression": "python -m pytest tests/test_cve_2024_47081.py -q",
    "scanner_rescan": "semgrep scan --config auto ."
  },
  "validation_timeout": 300
}
```

`differential_risk` 由补丁边界检查自动生成真实证据；其余四层必须配置可执行命令。

提交示例见 `examples/sast_sql_injection.json`。

## 设计原则

- 标准化是确定性数据管道，不由 Agent 自由推理。
- LLM 只能补全规则无法确认的字段，输出必须通过 Schema 校验。
- 影响面结论必须引用证据，并显式列出未知项。
- 根因必须由数据流、依赖或有效配置证据支持，不能由漏洞类型直接推断。
- 缺少关键证据时输出 `needs_human_review`，不得继续自动修复。
