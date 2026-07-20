"""评估用测试用例生成器 — 内置 demo + 边界用例变体。

为 7 个内置 demo 生成正常用例和边界变体，覆盖：
  - 空 source_files
  - 缺少 affected_file 字段
  - 未知 vulnerability_type
  - 缺少 severity 字段
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .demos import DEMOS, DemoPreset


@dataclass(slots=True)
class EvalCase:
    """单个评估用例。"""
    case_id: str
    category: str               # "demo" | "edge"
    demo_key: str | None         # 来源 demo（edge case 也标记）
    mode: str                    # "deterministic" | "llm"
    raw_input: dict[str, Any]
    source_files: dict[str, str]
    description: str


# ── 边界用例生成 ────────────────────────────────────────────────────────


def _get_demo_raw(demo: DemoPreset) -> dict[str, Any]:
    """从 DemoPreset 提取 raw_input dict。"""
    raw = demo.raw_input
    if callable(raw):
        return raw()
    if isinstance(raw, str):
        import json
        from pathlib import Path
        return json.loads((Path(__file__).resolve().parents[2] / "examples" / raw).read_text(encoding="utf-8"))
    return copy.deepcopy(raw)


def _get_demo_sources(demo: DemoPreset) -> dict[str, str]:
    """从 DemoPreset 提取源文件。"""
    sources = {}
    for sf in demo.source_files():
        sources[sf.path] = sf.content
    return sources


def _make_empty_sources(demo: DemoPreset) -> EvalCase:
    """边界：空源文件。"""
    raw = _get_demo_raw(demo)
    return EvalCase(
        case_id=f"edge-empty-sources-{demo.key}",
        category="edge",
        demo_key=demo.key,
        mode="deterministic",
        raw_input=raw,
        source_files={},
        description=f"空 source_files — 验证 Agent 在无源码时不崩溃",
    )


def _make_no_affected_file(demo: DemoPreset) -> EvalCase:
    """边界：缺少 affected_file。"""
    raw = _get_demo_raw(demo)
    raw = copy.deepcopy(raw)
    raw.pop("affected_file", None)
    raw.pop("locations", None)
    return EvalCase(
        case_id=f"edge-no-affected-file-{demo.key}",
        category="edge",
        demo_key=demo.key,
        mode="deterministic",
        raw_input=raw,
        source_files=_get_demo_sources(demo),
        description="缺少 affected_file — 验证 Agent 能推断或优雅降级",
    )


def _make_unknown_vuln_type(demo: DemoPreset) -> EvalCase:
    """边界：未知漏洞类型。"""
    raw = _get_demo_raw(demo)
    raw = copy.deepcopy(raw)
    raw["vulnerability_type"] = "unknown_vulnerability_type_xyz"
    return EvalCase(
        case_id=f"edge-unknown-type-{demo.key}",
        category="edge",
        demo_key=demo.key,
        mode="deterministic",
        raw_input=raw,
        source_files=_get_demo_sources(demo),
        description="未知 vulnerability_type — 验证 Agent 回退到通用逻辑",
    )


def _make_no_severity(demo: DemoPreset) -> EvalCase:
    """边界：缺少 severity。"""
    raw = _get_demo_raw(demo)
    raw = copy.deepcopy(raw)
    raw.pop("severity", None)
    return EvalCase(
        case_id=f"edge-no-severity-{demo.key}",
        category="edge",
        demo_key=demo.key,
        mode="deterministic",
        raw_input=raw,
        source_files=_get_demo_sources(demo),
        description="缺少 severity — 验证 Normalizer 使用默认值",
    )


def _make_large_single_file(demo: DemoPreset) -> EvalCase:
    """边界：大文件单文件输入（模拟超大源文件）。"""
    raw = _get_demo_raw(demo)
    # 生成一个 2000 行的伪代码文件
    large_content = "\n".join(
        f"def function_{i}(arg_{i}):\n    # Auto-generated test code line {i}\n    return arg_{i}"
        for i in range(2000)
    )
    sources = _get_demo_sources(demo)
    # 把第一个文件替换为大文件
    if sources:
        first_key = next(iter(sources))
        sources[first_key] = large_content
    else:
        sources["large_file.py"] = large_content
    return EvalCase(
        case_id=f"edge-large-file-{demo.key}",
        category="edge",
        demo_key=demo.key,
        mode="deterministic",
        raw_input=raw,
        source_files=sources,
        description="超大单文件 (~2K 行) — 验证 Agent 处理大文件不超时",
    )


# ── 边缘用例工厂 ────────────────────────────────────────────────────────

EDGE_FACTORIES = [
    _make_empty_sources,
    _make_no_affected_file,
    _make_unknown_vuln_type,
    _make_no_severity,
    _make_large_single_file,
]


def generate_cases(demo_filter: list[str] | None = None) -> list[EvalCase]:
    """生成全部评估用例（纯 LLM Agent 模式）。

    Args:
        demo_filter: 指定 demo key 列表，默认全部

    Returns:
        按 [demo_normal_cases..., edge_cases...] 排序的用例列表
    """
    # 按 filter 筛选 demo
    demos = DEMOS
    if demo_filter:
        demos = [d for d in DEMOS if d.key in demo_filter]
        if not demos:
            raise ValueError(f"未找到匹配的 demo: {demo_filter}，可用: {[d.key for d in DEMOS]}")

    cases: list[EvalCase] = []

    for demo in demos:
        raw = _get_demo_raw(demo)
        sources = _get_demo_sources(demo)
        cases.append(EvalCase(
            case_id=f"demo-{demo.key}-llm",
            category="demo",
            demo_key=demo.key,
            mode="llm",
            raw_input=raw,
            source_files=sources,
            description=f"{demo.title} [Agent]",
        ))

    # 边界用例只在确定性模式下运行（快速验证鲁棒性）
    for demo in demos:
        for factory in EDGE_FACTORIES:
            cases.append(factory(demo))

    return cases
