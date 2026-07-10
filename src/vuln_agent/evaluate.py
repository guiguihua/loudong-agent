"""漏洞修复 Agent 评估框架。

运行全部内置 demo + 边界用例，收集正确性、完整性、性能和鲁棒性指标，
生成 Markdown + JSON 双格式评估报告。

用法:
    python -m vuln_agent evaluate                        # 完整评估（确定性 + LLM）
    python -m vuln_agent evaluate --mode deterministic   # 仅确定性模式
    python -m vuln_agent evaluate --mode llm             # 仅 LLM 模式
    python -m vuln_agent evaluate --output-dir ./results # 指定输出目录
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .eval_cases import EvalCase, generate_cases

ROOT = Path(__file__).resolve().parents[2]

# ── Schema 定义：各 Agent 输出必需字段 ─────────────────────────────────


# 每个 Agent 输出的关键字段（用于完整性校验）
REQUIRED_FIELDS: dict[str, list[str]] = {
    "finding": [
        "finding_id", "vulnerability_type", "severity", "scanner",
        "locations", "evidence", "cwe",
    ],
    "impact": [
        "status", "affected_services", "entry_points", "call_paths",
        "affected_assets", "affected_artifacts", "data_classification",
        "upstream_dependencies", "downstream_dependencies",
        "regression_targets", "suggested_tests", "evidence",
        "unknowns", "confidence_score", "needs_human_review",
    ],
    "root_cause": [
        "status", "root_cause_category",
        "root_cause",  # nested: summary, source, propagation, sink, missing_control, etc.
        "contributing_factors", "causal_chain", "affected_code",
        "evidence", "alternative_hypotheses", "confidence_score",
        "unknowns", "needs_human_review", "recommended_fix_constraints",
        "security_invariant", "guardrail", "broken_mechanism",
    ],
    "report": [
        "report_id", "finding_id", "patch_id", "status", "title",
        "executive_summary", "root_cause_summary", "remediation_summary",
        "changed_files", "test_results", "security_validation_results",
        "validation_summary", "risk_summary", "rollback_summary",
        "human_review_focus", "pr_description_markdown",
        "ticket_comment_markdown", "sections", "needs_human_review",
    ],
    "patch_candidate": [
        "patch_id", "finding_id", "status", "summary", "artifacts",
        "changed_files", "test_changes", "security_notes",
        "assumptions", "risks", "validation_plan", "policy_check",
        "blocked_reason", "needs_human_review",
    ],
    "patch_validation": [
        "patch_id", "finding_id", "status", "layers", "failures",
        "next_action", "feedback_for_failure_analysis",
        "report_ready", "needs_human_review",
    ],
    "failure_analysis": [
        "patch_id", "finding_id", "primary_category", "summary",
        "findings", "route_to", "remediation_feedback",
        "patch_generation_feedback", "validation_feedback",
        "requires_root_cause_recheck", "needs_human_review",
    ],
}


# ── 指标数据类 ──────────────────────────────────────────────────────────


@dataclass(slots=True)
class CaseMetrics:
    """单个用例的运行指标。"""
    case_id: str
    category: str               # "demo" | "edge"
    mode: str                   # "deterministic" | "llm"
    description: str
    status: str                 # "succeeded" | "exhausted" | "error"
    total_time_ms: float = 0
    error_message: str | None = None
    # 输出完整性：每部分 (present_fields / required_fields)
    field_completeness: dict[str, str] = field(default_factory=dict)
    # 补丁统计
    patch_artifact_count: int = 0
    patch_changed_files_count: int = 0
    patch_diff_lines: int = 0
    # 重试
    attempt_count: int = 1
    # LLM 特有
    llm_fallback_count: int = 0  # LLM 解析失败回退到确定性模式的次数


@dataclass(slots=True)
class EvalReport:
    """完整评估报告。"""
    timestamp: str
    total_cases: int
    modes: list[str]
    summary: dict[str, Any]       # 按 mode 汇总
    cases: list[dict[str, Any]]   # 每个用例的详细指标
    edge_cases: list[dict[str, Any]]
    comparison: dict[str, Any]    # LLM vs 确定性 对比


# ── Schema 校验器 ───────────────────────────────────────────────────────


class SchemaValidator:
    """校验 Agent 输出字典的结构完整性。"""

    @staticmethod
    def validate(output: dict[str, Any]) -> dict[str, str]:
        """返回各部分的字段覆盖率字符串，如 "15/17"。"""
        results: dict[str, str] = {}
        for section, required in REQUIRED_FIELDS.items():
            if section not in output or output[section] is None:
                results[section] = f"0/{len(required)} (missing section)"
                continue
            data = output[section]
            if not isinstance(data, dict):
                results[section] = f"0/{len(required)} (not a dict)"
                continue
            present = sum(1 for f in required if f in data and data[f] is not None)
            results[section] = f"{present}/{len(required)}"
        return results

    @staticmethod
    def patch_stats(output: dict[str, Any]) -> dict[str, int]:
        """提取补丁统计指标。"""
        pc = output.get("patch_candidate", {}) or {}
        artifacts = pc.get("artifacts", []) or []
        changed_files = pc.get("changed_files", []) or []
        diff_lines = 0
        for a in artifacts:
            content = a.get("content", "") or ""
            diff_lines += sum(
                1 for line in content.splitlines()
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
            )
        return {
            "artifact_count": len(artifacts),
            "changed_files_count": len(changed_files),
            "diff_lines": diff_lines,
        }


# ── 评估执行器 ──────────────────────────────────────────────────────────


class EvaluationRunner:
    """运行单个用例并收集所有指标。"""

    def __init__(self, use_llm: bool = False):
        self.use_llm = use_llm

    def run_case(self, case: EvalCase) -> CaseMetrics:
        """运行单个评估用例，返回指标。"""
        from .runner import run_dict

        mode = "llm" if self.use_llm else "deterministic"
        metrics = CaseMetrics(
            case_id=case.case_id,
            category=case.category,
            mode=mode,
            description=case.description,
            status="error",
        )

        start = time.perf_counter()
        try:
            result = run_dict(
                case.raw_input,
                use_llm=self.use_llm,
                source_files=case.source_files,
                language=case.raw_input.get("language"),
                framework=case.raw_input.get("framework"),
                repository=case.raw_input.get("repository"),
            )
            elapsed = (time.perf_counter() - start) * 1000
            metrics.total_time_ms = round(elapsed, 1)
            metrics.status = result.get("status", "error")

            # 字段完整性
            metrics.field_completeness = SchemaValidator.validate(result)

            # 补丁统计
            stats = SchemaValidator.patch_stats(result)
            metrics.patch_artifact_count = stats["artifact_count"]
            metrics.patch_changed_files_count = stats["changed_files_count"]
            metrics.patch_diff_lines = stats["diff_lines"]

            # 尝试次数（从 patch_id 推断）
            pc = result.get("patch_candidate", {}) or {}
            pid = pc.get("patch_id", "")
            if "-0" in pid:
                try:
                    metrics.attempt_count = int(pid.split("-")[-1])
                except ValueError:
                    pass

        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            metrics.total_time_ms = round(elapsed, 1)
            metrics.status = "error"
            metrics.error_message = traceback.format_exc()

        return metrics

    def run_all(self, cases: list[EvalCase]) -> list[CaseMetrics]:
        """批量运行用例。"""
        # 只运行与当前模式匹配的用例
        mode = "llm" if self.use_llm else "deterministic"
        matching = [c for c in cases if c.mode == mode]
        results: list[CaseMetrics] = []
        total = len(matching)
        for i, case in enumerate(matching):
            print(f"  [{i+1}/{total}] {case.case_id} ... ", end="", flush=True)
            m = self.run_case(case)
            symbol = "✓" if m.status == "succeeded" else ("✗" if m.status == "error" else "⚠")
            print(f"{symbol} ({m.total_time_ms:.0f}ms)")
            results.append(m)
        return results


# ── 对比报告生成器 ──────────────────────────────────────────────────────


class ComparisonReporter:
    """对比 LLM 与确定性模式的结果差异。"""

    @staticmethod
    def compare(
        det_results: list[CaseMetrics],
        llm_results: list[CaseMetrics],
    ) -> dict[str, Any]:
        """生成 LLM vs 确定性模式对比。"""
        det_map = {m.case_id.replace("-deterministic", ""): m for m in det_results}
        llm_map = {m.case_id.replace("-llm", ""): m for m in llm_results}

        comparison = {
            "pairs": [],
            "summary": {
                "det_success_rate": ComparisonReporter._success_rate(det_results),
                "llm_success_rate": ComparisonReporter._success_rate(llm_results),
                "det_avg_time_ms": ComparisonReporter._avg_time(det_results),
                "llm_avg_time_ms": ComparisonReporter._avg_time(llm_results),
                "time_ratio": 0,
            },
        }

        # 计算时间比
        det_avg = comparison["summary"]["det_avg_time_ms"]
        llm_avg = comparison["summary"]["llm_avg_time_ms"]
        if det_avg > 0:
            comparison["summary"]["time_ratio"] = round(llm_avg / det_avg, 1)

        # 逐一对比
        common_keys = set(det_map.keys()) & set(llm_map.keys())
        for key in sorted(common_keys):
            d = det_map[key]
            l = llm_map[key]
            comparison["pairs"].append({
                "case": key,
                "det_status": d.status,
                "llm_status": l.status,
                "det_time_ms": d.total_time_ms,
                "llm_time_ms": l.total_time_ms,
                "det_diff_lines": d.patch_diff_lines,
                "llm_diff_lines": l.patch_diff_lines,
                "det_artifact_count": d.patch_artifact_count,
                "llm_artifact_count": l.patch_artifact_count,
            })

        return comparison

    @staticmethod
    def _success_rate(results: list[CaseMetrics]) -> float:
        if not results:
            return 0.0
        succeeded = sum(1 for r in results if r.status == "succeeded")
        return round(succeeded / len(results) * 100, 1)

    @staticmethod
    def _avg_time(results: list[CaseMetrics]) -> float:
        if not results:
            return 0.0
        return round(sum(r.total_time_ms for r in results) / len(results), 1)


# ── 报告渲染 ────────────────────────────────────────────────────────────


def _render_markdown(report: EvalReport) -> str:
    """将评估报告渲染为 Markdown。"""
    lines = [
        "# 漏洞修复 Agent 评估报告",
        "",
        f"**评估时间**：{report.timestamp}",
        f"**用例总数**：{report.total_cases}",
        f"**运行模式**：{', '.join(report.modes)}",
        "",
        "---",
        "",
        "## 总体摘要",
        "",
    ]

    # 总体摘要表
    for mode, summary in report.summary.items():
        lines.append(f"### {mode.upper()} 模式")
        lines.append("")
        lines.append(f"| 指标 | 值 |")
        lines.append(f"|------|-----|")
        lines.append(f"| 成功率 | {summary['success_rate']}% ({summary['succeeded']}/{summary['total']}) |")
        lines.append(f"| 平均耗时 | {summary['avg_time_ms']:.0f} ms |")
        lines.append(f"| 最快 | {summary['min_time_ms']:.0f} ms |")
        lines.append(f"| 最慢 | {summary['max_time_ms']:.0f} ms |")
        lines.append(f"| 错误数 | {summary['errors']} |")
        lines.append("")

    # LLM vs 确定性对比
    if report.comparison.get("pairs"):
        lines.extend([
            "---",
            "",
            "## LLM vs 确定性模式对比",
            "",
        ])
        comp = report.comparison["summary"]
        lines.append(f"| 指标 | 确定性 | LLM |")
        lines.append(f"|------|--------|-----|")
        lines.append(f"| 成功率 | {comp['det_success_rate']}% | {comp['llm_success_rate']}% |")
        lines.append(f"| 平均耗时 | {comp['det_avg_time_ms']:.0f} ms | {comp['llm_avg_time_ms']:.0f} ms |")
        lines.append(f"| 耗时比 | 1x | {comp['time_ratio']}x |")
        lines.append("")

        lines.append("### 详细对比")
        lines.append("")
        lines.append("| 用例 | 确定性 | LLM | 耗时比 |")
        lines.append("|------|--------|-----|--------|")
        for pair in report.comparison["pairs"]:
            det_s = "✅" if pair["det_status"] == "succeeded" else "❌"
            llm_s = "✅" if pair["llm_status"] == "succeeded" else "❌"
            ratio = f"{pair['llm_time_ms'] / max(pair['det_time_ms'], 1):.1f}x"
            lines.append(f"| {pair['case']} | {det_s} ({pair['det_time_ms']:.0f}ms) | {llm_s} ({pair['llm_time_ms']:.0f}ms) | {ratio} |")
        lines.append("")

    # 详细结果表
    lines.extend([
        "---",
        "",
        "## 用例详细结果",
        "",
        "| 用例 | 模式 | 状态 | 耗时 | 补丁文件 | Diff行 | 字段完整性 |",
        "|------|------|------|------|----------|--------|-----------|",
    ])

    for case in report.cases:
        status_icon = "✅" if case["status"] == "succeeded" else ("❌" if case["status"] == "error" else "⚠️")
        # 取最差的字段覆盖率
        field_strs = [v for v in case["field_completeness"].values() if v is not None]
        worst_field = _worst_field(field_strs) if field_strs else "N/A"
        lines.append(
            f"| {case['case_id']} | {case['mode']} | {status_icon} {case['status']} | "
            f"{case['total_time_ms']:.0f}ms | {case['patch_changed_files_count']} | "
            f"{case['patch_diff_lines']} | {worst_field} |"
        )

    # 错误详情
    error_cases = [c for c in report.cases if c["status"] == "error"]
    if error_cases:
        lines.extend([
            "",
            "---",
            "",
            "## 错误详情",
            "",
        ])
        for c in error_cases:
            lines.append(f"### {c['case_id']}")
            lines.append(f"```")
            lines.append(c.get("error_message", "unknown error"))
            lines.append(f"```")
            lines.append("")

    # 边界用例
    if report.edge_cases:
        lines.extend([
            "---",
            "",
            "## 边界用例（鲁棒性）",
            "",
            "| 用例 | 状态 | 耗时 | 说明 |",
            "|------|------|------|------|",
        ])
        for c in report.edge_cases:
            status_icon = "✅" if c["status"] != "error" else "❌"
            lines.append(
                f"| {c['case_id']} | {status_icon} {c['status']} | "
                f"{c['total_time_ms']:.0f}ms | {c['description']} |"
            )

    # 改进建议
    lines.extend([
        "",
        "---",
        "",
        "## 改进建议",
        "",
        *_generate_recommendations(report),
        "",
    ])

    return "\n".join(lines)


def _worst_field(field_strs: list[str]) -> str:
    """找出最差的字段覆盖率字符串。"""
    worst_ratio = 1.0
    worst_str = "N/A"
    for s in field_strs:
        if "/" in s:
            try:
                present, total = s.split("/")
                ratio = int(present) / int(total) if int(total) > 0 else 0
                if ratio < worst_ratio:
                    worst_ratio = ratio
                    worst_str = s
            except (ValueError, ZeroDivisionError):
                pass
        elif "missing" in s:
            return s
    return worst_str


def _generate_recommendations(report: EvalReport) -> list[str]:
    """基于评估结果生成改进建议。"""
    recs: list[str] = []

    for mode, summary in report.summary.items():
        success_rate = summary.get("success_rate", 0)
        if success_rate < 100:
            failed_count = summary["total"] - summary["succeeded"] - summary["errors"]
            recs.append(
                f"- **{mode} 模式成功率 {success_rate}%**："
                f"有 {summary['errors']} 个错误、{failed_count} 个未通过验证，"
                f"建议检查失败用例的详细输出定位问题。"
            )
        if summary.get("avg_time_ms", 0) > 60000:
            recs.append(
                f"- **{mode} 模式平均耗时 {summary['avg_time_ms']:.0f}ms**："
                f"超过 60s，建议优化 LLM prompt 大小或使用更快的 API。"
            )

    # 边界用例
    edge_errors = [c for c in report.edge_cases if c["status"] == "error"]
    if edge_errors:
        recs.append(
            f"- **{len(edge_errors)} 个边界用例崩溃**："
            f"需要增强 Agent 的异常处理，确保缺失字段等异常输入不导致崩溃。"
        )

    if not recs:
        recs.append("- 所有用例通过，Agent 表现良好。可以考虑增加更多 CVE 真实用例。")
    return recs


# ── 主入口 ──────────────────────────────────────────────────────────────


def evaluate_all(
    output_dir: Path | None = None,
    demo_filter: list[str] | None = None,
) -> EvalReport:
    """运行 Agent 评估流程（纯 LLM 模式）。

    Args:
        output_dir: 报告输出目录，默认 outputs/evaluations/
        demo_filter: 指定要评估的 demo key 列表，默认全部

    Returns:
        EvalReport 包含所有指标数据。
    """
    # 自动加载 .env
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except ImportError:
        pass

    modes = ["llm"]

    out_dir = output_dir or (ROOT / "outputs" / "evaluations")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  漏洞修复 Agent 评估")
    print(f"  模式: {', '.join(modes)}")
    print(f"  输出: {out_dir}")
    print(f"{'='*60}\n")

    all_metrics: list[CaseMetrics] = []
    edge_results: list[CaseMetrics] = []

    print(f"\n{'─'*60}")
    print(f"  [Agent] 模式 — 每个 Agent 拥有工具，多轮推理")
    print(f"{'─'*60}")

    runner = EvaluationRunner(use_llm=True)
    cases = generate_cases(demo_filter=demo_filter)
    metrics = runner.run_all(cases)

    # 分离 demo 和 edge 结果
    for m in metrics:
        if m.category == "edge":
            edge_results.append(m)
        else:
            all_metrics.append(m)

    # 构建汇总
    summary: dict[str, Any] = {}
    times = [m.total_time_ms for m in all_metrics]
    succeeded = sum(1 for m in all_metrics if m.status == "succeeded")
    errors = sum(1 for m in all_metrics if m.status == "error")
    summary["llm"] = {
        "total": len(all_metrics),
        "succeeded": succeeded,
        "exhausted": sum(1 for m in all_metrics if m.status == "exhausted"),
        "errors": errors,
        "success_rate": round(succeeded / len(all_metrics) * 100, 1) if all_metrics else 0,
        "avg_time_ms": round(sum(times) / len(times), 1) if times else 0,
        "min_time_ms": round(min(times), 1) if times else 0,
        "max_time_ms": round(max(times), 1) if times else 0,
    }

    # 构建报告
    report = EvalReport(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        total_cases=len(all_metrics) + len(edge_results),
        modes=modes,
        summary=summary,
        cases=[_metrics_to_dict(m) for m in all_metrics],
        edge_cases=[_metrics_to_dict(m) for m in edge_results],
        comparison={},
    )

    # 写报告
    _write_reports(report, out_dir)

    # 打印终端摘要
    _print_terminal_summary(report)

    return report


def _metrics_to_dict(m: CaseMetrics) -> dict[str, Any]:
    """将 CaseMetrics 转为可序列化的 dict。"""
    return {
        "case_id": m.case_id,
        "category": m.category,
        "mode": m.mode,
        "description": m.description,
        "status": m.status,
        "total_time_ms": m.total_time_ms,
        "error_message": m.error_message,
        "field_completeness": m.field_completeness,
        "patch_artifact_count": m.patch_artifact_count,
        "patch_changed_files_count": m.patch_changed_files_count,
        "patch_diff_lines": m.patch_diff_lines,
        "attempt_count": m.attempt_count,
        "llm_fallback_count": m.llm_fallback_count,
    }


def _write_reports(report: EvalReport, out_dir: Path) -> None:
    """写出 Markdown 和 JSON 报告。"""
    # Markdown
    md_path = out_dir / "evaluation-report.md"
    md_path.write_text(_render_markdown(report), encoding="utf-8")
    print(f"\n  Markdown 报告: {md_path}")

    # JSON
    json_path = out_dir / "evaluation-metrics.json"
    json_data = {
        "timestamp": report.timestamp,
        "total_cases": report.total_cases,
        "modes": report.modes,
        "summary": report.summary,
        "cases": report.cases,
        "edge_cases": report.edge_cases,
        "comparison": report.comparison,
    }
    json_path.write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  JSON 指标: {json_path}")


def _print_terminal_summary(report: EvalReport) -> None:
    """终端友好摘要。"""
    print(f"\n{'='*60}")
    print(f"  评估完成")
    print(f"{'='*60}")
    for mode, summary in report.summary.items():
        sr = summary["success_rate"]
        bar = _progress_bar(sr / 100)
        print(f"  {mode:16s}  成功率: {bar} {sr}%  "
              f"({summary['succeeded']}/{summary['total']})  "
              f"平均: {summary['avg_time_ms']:.0f}ms")
    edge_ok = sum(1 for c in report.edge_cases if c["status"] != "error")
    edge_total = len(report.edge_cases)
    print(f"  {'边界用例':16s}  鲁棒性: {edge_ok}/{edge_total} 未崩溃")
    print(f"{'='*60}")


def _progress_bar(ratio: float, width: int = 20) -> str:
    filled = int(ratio * width)
    if ratio >= 1.0:
        return "█" * width
    if ratio >= 0.8:
        return "█" * filled + "░" * (width - filled)
    return "█" * filled + " " * (width - filled)
