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

提交示例见 `examples/sast_sql_injection.json`。

## 设计原则

- 标准化是确定性数据管道，不由 Agent 自由推理。
- LLM 只能补全规则无法确认的字段，输出必须通过 Schema 校验。
- 影响面结论必须引用证据，并显式列出未知项。
- 根因必须由数据流、依赖或有效配置证据支持，不能由漏洞类型直接推断。
- 缺少关键证据时输出 `needs_human_review`，不得继续自动修复。
