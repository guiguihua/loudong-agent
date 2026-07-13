"""RootCauseAnalysisAgent — 分析漏洞根因。

继承 BaseAgent，拥有 read_file / search_code 工具，
能自己读代码追踪 source-to-sink 数据流，识别缺失的安全控制。
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .agent import BaseAgent, create_default_tools
from .models import (
    AffectedCode,
    AlternativeHypothesis,
    AssessmentStatus,
    CodePoint,
    Confidence,
    Evidence,
    EvidenceBundle,
    FailedControl,
    ImpactAssessment,
    NormalizedVulnerability,
    PropagationStep,
    RootCause,
    RootCauseAssessment,
    RootCauseCategory,
)
from .tools import DependencyRootCauseContext, RootCauseCodeContext, RootCauseEvidenceTool

if TYPE_CHECKING:
    from .llm import LLMBackend

ROOT_CAUSE_AGENT_PROMPT = """你是一位资深安全研究员，负责分析漏洞的完整根因。

## 你的任务
追踪不可信数据的完整数据流：
1. Source: 不可信输入从哪里进入系统？
2. Propagation: 经过哪些步骤传播？
3. Sink: 最终到达哪个危险操作（SQL执行、命令执行、文件读写等）？
4. Missing Control: 缺失了什么安全控制？

## 可用工具
- read_file: 读取源码文件的具体行范围
- search_code: 搜索代码中的危险函数调用（execute、eval、open、render 等）

## 工作方式
1. 先读漏洞报告中指出的文件
2. 搜索代码中相关的危险函数
3. 追踪变量从入口到危险操作的数据流
4. 识别路径上缺失或失效的安全控制
5. 给出安全不变量和修复约束

确认分析完成后，调用 submit_final_result 工具提交最终结果。"""


class RootCauseAnalysisAgent(BaseAgent):
    """分析漏洞根因 — 自己读代码追踪数据流。"""

    def __init__(
        self,
        evidence_tool: RootCauseEvidenceTool,
        llm: LLMBackend | None = None,
        workspace: Path | None = None,
    ):
        ws = workspace or Path.cwd()
        super().__init__(
            name="RootCauseAnalysis",
            system_prompt=ROOT_CAUSE_AGENT_PROMPT,
            tools=create_default_tools(ws),
            llm=llm,
            max_turns=10,
            workspace=ws,
        )
        self.evidence_tool = evidence_tool

    def analyze(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> RootCauseAssessment:
        """运行 Root Cause Analysis Agent。"""
        from .llm import ROOT_CAUSE_SCHEMA
        self.output_schema = ROOT_CAUSE_SCHEMA

        task = self._build_task(finding, impact, evidence_bundle)
        raw = self.run(task)

        if "_raw_output" in raw:
            extracted = self._extract_structured_from_raw(
                raw_text=raw["_raw_output"],
                finding=finding,
                impact=impact,
            )
            return self._dict_to_root_cause(finding, extracted)
        return self._dict_to_root_cause(finding, raw)

    def _extract_structured_from_raw(
        self,
        raw_text: str,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
    ) -> dict:
        """从非结构化的 LLM 输出中二次提取结构化根因分析字段。"""
        if not self.llm:
            return self._fallback_raw_extraction(raw_text, finding)

        from .llm import ROOT_CAUSE_SCHEMA

        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
        extraction_prompt = f"""以下是一段漏洞根因分析的原始文本。请从中提取关键信息，填入指定 JSON 结构。

## 漏洞基本信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 函数: {finding.locations[0].function if finding.locations and finding.locations[0].function else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}

## 原始分析文本
{raw_text[:8000]}

## 要求
请仔细阅读上面的分析文本，尽量提取所有你能找到的结构化信息。
如果某个字段在文本中找不到对应信息，使用合理的默认值（空字符串/空数组/unknown），不要编造。"""

        try:
            structured = self.llm.reason(
                user_prompt=extraction_prompt,
                system_prompt="你是一个结构化数据提取器。从安全分析文本中提取关键信息并填入 JSON 结构。只输出 JSON。",
                output_schema={
                    "type": "object",
                    "description": "从原始分析文本中提取的结构化根因分析",
                    "properties": {
                        k: v for k, v in ROOT_CAUSE_SCHEMA.get("properties", {}).items()
                        if k not in ("reasoning",)
                    },
                    "required": ["status", "root_cause_category", "summary", "missing_control", "causal_chain", "confidence_score", "needs_human_review"],
                },
                temperature=0.1,
            )
            if isinstance(structured, dict) and structured.get("summary"):
                structured["_extracted_from_raw"] = True
                return structured
        except Exception:
            pass

        return self._fallback_raw_extraction(raw_text, finding)

    @staticmethod
    def _fallback_raw_extraction(raw_text: str, finding: NormalizedVulnerability) -> dict:
        """LLM 不可用时的纯文本回退提取 — 尽可能从分析文本中抓取有用信息。"""
        import re

        result: dict = {
            "status": "possible",
            "root_cause_category": "unknown",
            "summary": "",
            "source": {},
            "propagation": [],
            "sink": {},
            "missing_control": "",
            "causal_chain": [],
            "broken_mechanism": [],
            "security_invariant": "",
            "guardrail": "",
            "exploitability_note": "",
            "recommended_fix_constraints": [],
            "confidence_score": 0.3,
            "unknowns": ["结构化提取失败，以下内容从非结构化文本中尽力提取"],
            "needs_human_review": True,
            "contributing_factors": [],
            "affected_code": [],
            "alternative_hypotheses": [],
            "trigger_conditions": [],
        }

        # 1. 尝试找到 JSON 块
        json_match = re.search(r'\{[^{}]*"summary"[^{}]*\}', raw_text, re.DOTALL)
        if not json_match:
            json_match = re.search(r'\{[^{}]*"root_cause"[^{}]*\}', raw_text, re.DOTALL)
        if json_match:
            import json as _json
            try:
                parsed = _json.loads(json_match.group(0))
                if isinstance(parsed, dict):
                    for k, v in parsed.items():
                        if k in result and v:
                            result[k] = v
            except (_json.JSONDecodeError, ValueError):
                pass

        # 2. 按段落提取关键摘要
        text_clean = re.sub(r'```[^`]*```', '', raw_text)
        text_clean = re.sub(r'#{1,6}\s+', '', text_clean)
        paragraphs = [p.strip() for p in text_clean.split('\n\n') if len(p.strip()) > 30]
        if not result.get("summary") and paragraphs:
            result["summary"] = paragraphs[0][:500]

        # 3. 从文本中匹配常见模式提取 missing_control
        missing_patterns = [
            (r'(?:缺失|缺少|缺少的?|missing)\s*(?:的\s*)?(?:安全)?(?:控制|防护|检查|校验)[：:\s]\s*(.+?)(?:\n|$)', 1),
            (r'(?:missing[_\s]control|Missing\s*Control)[：:\s]\s*(.+?)(?:\n|$)', 1),
            (r'(?:应|应该|需要|必须)\s*(?:使用|增加|添加|实现|执行)\s*(.+?)(?:\，|\,|。|\.|\n|$)', 1),
            (r'(?:漏洞|问题)\s*(?:根因|原因|在于)[：:\s]\s*(.+?)(?:\n|$)', 1),
        ]
        for pattern, group in missing_patterns:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                extracted = match.group(group).strip()[:200]
                if not result.get("missing_control") and extracted:
                    result["missing_control"] = extracted
                if not result.get("summary") and extracted:
                    result["summary"] = extracted
                break

        # 4. 提取因果链
        chain_patterns = [
            r'(?:因果链|causal.chain|攻击链|利用链|数据流)[：:]\s*(.+?)(?:\n\n|\n(?!\d)|$)',
            r'(?:\d+[\.\)、]\s*)(.+?(?:→|->|→).+?)(?:\n|$)',
        ]
        for pattern in chain_patterns:
            matches = re.findall(pattern, raw_text, re.IGNORECASE | re.MULTILINE)
            if matches and not result.get("causal_chain"):
                result["causal_chain"] = [m.strip()[:300] for m in matches[:10]]
                break

        # 5. 提取 security_invariant
        inv_patterns = [
            r'(?:安全不变量|security.invariant|安全属性)[：:]\s*(.+?)(?:\n|$)',
            r'(?:预期行为|正常行为|正确行为)[：:]\s*(.+?)(?:\n|$)',
        ]
        for pattern in inv_patterns:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match and not result.get("security_invariant"):
                result["security_invariant"] = match.group(1).strip()[:300]
                break

        # 6. 提取 affected_code
        file_pattern = re.findall(r'(?:文件|受影响|affected.file|修改)[：:\s]*`?([a-zA-Z0-9_/\.\-]+\.(?:py|java|go|js|ts|cpp|c|h))`?', raw_text)
        if file_pattern:
            result["affected_code"] = [
                {"file": f, "function": None, "lines": [], "role": "primary_cause"}
                for f in list(dict.fromkeys(file_pattern))[:5]
            ]

        # 7. CVE/CWE 类型专属知识
        result = RootCauseAnalysisAgent._apply_cve_knowledge(result, finding, raw_text)

        # 最终降级：从漏洞报告中生成有意义的降级内容
        if not result.get("summary"):
            evidence_text = "; ".join(e for e in (finding.evidence or []) if e.strip())
            locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]
            loc_str = locs[0] if locs else "unknown"
            result["summary"] = (
                f"{finding.finding_id}: {finding.vulnerability_type} — "
                f"受影响位置 {loc_str}."
                f"{' 证据: ' + evidence_text if evidence_text else ''}"
                f"{' 修复建议: ' + finding.recommendation if finding.recommendation else ''}"
            )
        if not result.get("missing_control") or str(result.get("missing_control", "")).strip() in (
            "missing_control", "missing_security_control", "missing control", "",
        ):
            result["missing_control"] = (
                f"针对 {finding.vulnerability_type} 的安全控制（"
                f"具体控制需人工审查确认。"
                f"{' 参考修复建议: ' + finding.recommendation if finding.recommendation else ''}"
                "）"
            )

        return result

    @staticmethod
    def _apply_cve_knowledge(result: dict, finding: NormalizedVulnerability, raw_text: str) -> dict:
        """对已知 CVE/CWE 漏洞模式注入专属的攻击机制知识。"""
        import re

        vuln_lower = (finding.vulnerability_type or "").lower()
        cwe = (finding.cwe or "").lower()
        evidence_text = " ".join(e for e in (finding.evidence or []) if e.strip()).lower()
        combined = f"{vuln_lower} {cwe} {evidence_text} {raw_text[:2000]}".lower()

        # ── JWT 算法混淆 ──
        is_jwt_alg_confusion = any(kw in combined for kw in [
            "jwt", "jose", "algorithm confusion", "算法混淆", "alg:none",
            "hmac", "非对称", "rs256", "hs256", "authlib", "pyjwt",
            "cve-2022-29217", "cve-2024-37568", "cve-2024-33663",
        ])

        if is_jwt_alg_confusion:
            if not result.get("security_invariant"):
                result["security_invariant"] = (
                    "JWT 的签名验证算法必须与 Token Header 中声明的 alg 字段严格一致，"
                    "且应用层必须显式指定允许的算法白名单。"
                    "不得允许 Token 自身声明验证算法（如 alg:none），"
                    "也不得将非对称密钥（RSA/EC）用于 HMAC 对称验证。"
                )
            if not result.get("guardrail"):
                result["guardrail"] = (
                    "JWT 解码入口必须显式校验 algorithms 参数："
                    "1) 禁止空 algorithms 或默认推导；"
                    "2) 禁止 alg:none；"
                    "3) 非对称密钥类型不得参与 HMAC 验证路径。"
                )
            if not result.get("broken_mechanism") or len(result.get("broken_mechanism", [])) < 3:
                loc_str = ", ".join(
                    f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line
                ) or "JWT 解码入口"
                result["broken_mechanism"] = [
                    f"[入口] 应用调用 jwt.decode(token, key) 或 jwt.decode(token, key, algorithms=None) "
                    f"— 未显式指定 algorithms 参数",
                    f"[缺失验证] 解码函数信任 Token Header 中的 alg 字段，"
                    f"未校验其是否在应用预期的算法白名单中",
                    f"[密钥混淆] 攻击者获取公开的非对称公钥（RSA/EC public key），"
                    f"将其作为 HMAC 对称密钥使用，因为 HMAC 密钥可以是任意字节串",
                    f"[签名伪造] 攻击者用公钥作为 HMAC 密钥对恶意 payload 签名，"
                    f"设置 alg:HS256，服务器用同一公钥验证 HMAC 签名 → 验证通过",
                    f"[权限提升] 伪造的 Token 被服务器接受，攻击者获得任意用户身份/权限",
                    f"[受影响代码] {loc_str} — 缺少 algorithms 参数显式校验",
                ]
            if not result.get("causal_chain"):
                result["causal_chain"] = [
                    "攻击者获取应用公钥（通常从 /.well-known/jwks.json 公开端点） → "
                    "构造恶意 JWT Token，Header 声明 alg:HS256 → "
                    "用公钥作为 HMAC 密钥对 payload 签名 → "
                    "发送 Token 到应用 → "
                    "jwt.decode() 未校验 algorithms 参数 → "
                    "信任 Token 声明的 HS256 算法 → "
                    "使用公钥作为 HMAC 密钥验证签名 → "
                    "签名验证通过 → 攻击者获得伪造身份",
                ]
            if not result.get("exploitability_note"):
                result["exploitability_note"] = (
                    "利用条件：攻击者需要获取应用的 JWT 验证公钥。"
                    "公钥通常通过标准端点公开（如 /.well-known/jwks.json），"
                    "或硬编码在客户端代码/配置文件/SPA 中。"
                    "无需任何身份认证即可发起攻击。"
                    "影响范围包括所有依赖该 JWT 进行身份认证和授权的 API 端点。"
                )
            if not result.get("recommended_fix_constraints"):
                result["recommended_fix_constraints"] = [
                    "jwt.decode() 调用必须显式指定 algorithms 参数，禁止传空或 None",
                    "禁止 alg:none，必须在算法白名单中排除",
                    "非对称密钥不得用于 HMAC 验证路径",
                    "升级到 Authlib >= 1.3.1 或 PyJWT >= 2.4.0 等已修复版本",
                    "对所有现有 jwt.decode() 调用点做全量排查和回归测试",
                ]

        # ── SQL 注入 ──
        is_sqli = any(kw in combined for kw in ["sql injection", "sqli", "cwe-89"])
        if is_sqli and not result.get("broken_mechanism"):
            loc_str = ", ".join(
                f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line
            ) or "SQL 执行点"
            result["broken_mechanism"] = [
                f"[入口] 不可信输入进入应用（HTTP 参数/Header/Body）",
                f"[传播] 输入未经参数化直接拼接到 SQL 语句字符串中",
                f"[汇点] 拼接后的字符串传递给数据库执行器（execute/cursor.execute）",
                f"[触发] 攻击者注入 SQL 元字符改变查询语义",
                f"[受影响代码] {loc_str}",
            ]
            if not result.get("security_invariant"):
                result["security_invariant"] = (
                    "SQL 查询结构必须在编译时确定，用户输入只能作为数据参数绑定，"
                    "不得参与 SQL 语句文本的拼接或插值。"
                )
            if not result.get("guardrail"):
                result["guardrail"] = "所有用户输入必须通过参数化查询（? 占位符或命名参数）传递给数据库驱动器。"

        return result

    def _build_task(
        self,
        finding: NormalizedVulnerability,
        impact: ImpactAssessment,
        evidence_bundle: EvidenceBundle | None = None,
    ) -> str:
        """构建根因分析任务。"""
        from .evidence import format_evidence_bundle

        code = self.evidence_tool.collect_code_evidence(finding)
        locs = [f"{loc.file}:{loc.line}" for loc in finding.locations if loc.line]

        return f"""分析以下漏洞的根因：

## 漏洞信息
- ID: {finding.finding_id}
- 类型: {finding.vulnerability_type}
- 严重性: {finding.severity.value}
- 文件: {', '.join(locs) if locs else 'unknown'}
- 函数: {finding.locations[0].function if finding.locations and finding.locations[0].function else 'unknown'}
- 证据: {'; '.join(finding.evidence) if finding.evidence else '无'}
- 建议: {finding.recommendation or '未提供'}

## 影响面
- 服务: {impact.affected_services}
- 入口点: {[(e.route, e.method) for e in impact.entry_points]}
- 调用路径: {impact.call_paths}

## 代码线索
- Source: {code.source.symbol + ' @ ' + code.source.file if code.source else 'unknown'}
- Sink: {code.sink.symbol + ' @ ' + code.sink.file if code.sink else 'unknown'}
- 传播步骤: {[(s.symbol, s.operation) for s in code.propagation] if code.propagation else 'unknown'}
- 已有守卫: {code.guards or 'none'}
- 失效控制: {[(c.control, c.reason) for c in code.failed_controls] if code.failed_controls else 'none'}
- 触发条件: {code.trigger_conditions or 'unknown'}
- 语言: {code.language or 'unknown'}
- 框架: {code.framework or 'unknown'}

## 确定性 EvidenceBundle（优先使用）
{format_evidence_bundle(evidence_bundle)}

## 要求
先复用 EvidenceBundle 的 source/sink 候选和有界代码切片；仅在关键链路缺失或证据冲突时使用工具补充读取。追踪完整的 source-to-sink 数据流。
识别缺失的安全控制，给出安全不变量和修复约束。"""

    @staticmethod
    def _dict_to_root_cause(finding: NormalizedVulnerability, raw: dict) -> RootCauseAssessment:
        """将 LLM 输出转为 RootCauseAssessment。"""
        source_raw = raw.get("source", {}) or {}
        sink_raw = raw.get("sink", {}) or {}
        evidence = [
            Evidence("llm-root-cause", "agent_reasoning", "Agent 探索代码后推理的根因分析",
                     raw.get("reasoning", ""), Confidence.MEDIUM)
        ]
        return RootCauseAssessment(
            finding_id=finding.finding_id,
            status=AssessmentStatus(raw.get("status", "probable")),
            root_cause_category=RootCauseCategory(raw.get("root_cause_category", "unknown")),
            root_cause=RootCause(
                summary=raw.get("summary", ""),
                source=CodePoint(source_raw.get("symbol", ""), source_raw.get("file"), source_raw.get("line"))
                if source_raw else None,
                propagation=[PropagationStep(p["symbol"], p["operation"]) for p in raw.get("propagation", [])],
                sink=CodePoint(sink_raw.get("symbol", ""), sink_raw.get("file"), sink_raw.get("line"))
                if sink_raw else None,
                missing_control=raw.get("missing_control"),
                failed_existing_controls=[
                    FailedControl(fc["control"], fc["reason"])
                    for fc in raw.get("failed_existing_controls", [])
                ],
                trigger_conditions=raw.get("trigger_conditions", []),
            ),
            contributing_factors=raw.get("contributing_factors", []),
            causal_chain=raw.get("causal_chain", []),
            affected_code=[
                AffectedCode(ac["file"], ac.get("function"), ac.get("lines", []), ac.get("role", "primary_cause"))
                for ac in raw.get("affected_code", [])
            ],
            evidence=evidence,
            alternative_hypotheses=[
                AlternativeHypothesis(ah["hypothesis"], ah["result"], ah["reason"])
                for ah in raw.get("alternative_hypotheses", [])
            ],
            confidence_score=float(raw.get("confidence_score", 0.5)),
            unknowns=raw.get("unknowns", []),
            needs_human_review=bool(raw.get("needs_human_review", True)),
            recommended_fix_constraints=raw.get("recommended_fix_constraints", []),
            security_invariant=raw.get("security_invariant"),
            guardrail=raw.get("guardrail"),
            broken_mechanism=raw.get("broken_mechanism", []),
            exploitability_note=raw.get("exploitability_note"),
        )
