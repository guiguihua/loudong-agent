"""LLM 推理后端 — 为 Agent 注入真正的推理能力。

使用 DeepSeek API（兼容 OpenAI SDK）进行结构化推理。
当 LLM 可用时，Agent 用 LLM 推理；否则回退到确定性规则。

环境变量:
    DEEPSEEK_API_KEY  — DeepSeek API Key（必需）
    DEEPSEEK_BASE_URL — 自定义 API 地址（可选，默认 https://api.deepseek.com）
    LLM_MODEL         — 默认模型名（可选，优先于 DEEPSEEK_MODEL）
    DEEPSEEK_MODEL    — [向后兼容] 默认模型名
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .config import load_env_file

load_env_file()


# ── JSON Schema 构建辅助 ──────────────────────────────────────────────


def _validate_schema_required(result: dict[str, Any], schema: dict[str, Any] | None) -> list[str]:
    """Check that result has all fields required by schema. Returns list of missing paths."""
    if not schema or not isinstance(result, dict):
        return []
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    missing: list[str] = []
    for field in required:
        if field not in result or result[field] is None:
            missing.append(field)
            continue
        field_schema = properties.get(field, {})
        if isinstance(field_schema, dict):
            nested_required = field_schema.get("required", [])
            if isinstance(nested_required, list):
                nested_value = result[field]
                if isinstance(nested_value, dict):
                    for nf in nested_required:
                        if nf not in nested_value or nested_value[nf] is None:
                            missing.append(f"{field}.{nf}")
    return missing


def _model_schema(model_class: type, description: str, required_fields: list[str] | None = None) -> dict[str, Any]:
    """从 dataclass 的 type hints 推断 JSON Schema。"""
    return {"type": "object", "description": description, "properties": {}, "required": required_fields or []}


# ── ImpactAssessment schema ───────────────────────────────────────────

IMPACT_SCHEMA = {
    "type": "object",
    "description": "漏洞影响面评估。基于漏洞信息和代码上下文，推理受影响的服务、入口点、调用路径、资产和风险评估。",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["confirmed", "probable", "possible", "not_affected", "unknown"],
            "description": "影响面确认状态。confirmed=三要素齐全(代码路径+资产+运行时), probable=有代码路径+资产, possible=至少有一项, unknown=无证据",
        },
        "affected_services": {
            "type": "array", "items": {"type": "string"},
            "description": "受影响的服务/组件名称列表",
        },
        "entry_points": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "route": {"type": "string"},
                    "method": {"type": "string", "default": "ANY"},
                    "authentication": {"type": "string", "default": "unknown"},
                    "internet_exposed": {"type": ["boolean", "null"]},
                },
                "required": ["route"],
            },
            "description": "可触发漏洞的 API 入口点",
        },
        "call_paths": {
            "type": "array", "items": {"type": "array", "items": {"type": "string"}},
            "description": "从入口到危险操作的调用路径",
        },
        "affected_assets": {
            "type": "array", "items": {"type": "string"},
            "description": "受影响的部署资产",
        },
        "affected_artifacts": {
            "type": "array", "items": {"type": "string"},
            "description": "受影响的构建制品/文件",
        },
        "data_classification": {
            "type": "array", "items": {"type": "string"},
            "description": "受影响的数据分类（如 user profile data, financial records）",
        },
        "upstream_dependencies": {
            "type": "array", "items": {"type": "string"},
            "description": "上游依赖",
        },
        "downstream_dependencies": {
            "type": "array", "items": {"type": "string"},
            "description": "下游依赖",
        },
        "regression_targets": {
            "type": "array", "items": {"type": "string"},
            "description": "应运行的回归测试目标",
        },
        "suggested_tests": {
            "type": "array", "items": {"type": "string"},
            "description": "建议新增的安全测试",
        },
        "unknowns": {
            "type": "array", "items": {"type": "string"},
            "description": "尚不确定的信息项",
        },
        "confidence_score": {
            "type": "number", "minimum": 0, "maximum": 1,
            "description": "影响面评估置信度 (0-1)",
        },
        "needs_human_review": {
            "type": "boolean",
            "description": "是否需要人工审查",
        },
        "reasoning": {
            "type": "string",
            "description": "推理过程简述，说明做出上述判断的依据",
        },
    },
    "required": ["status", "affected_services", "entry_points", "call_paths", "unknowns", "confidence_score", "needs_human_review"],
}


# ── RootCauseAssessment schema ────────────────────────────────────────

ROOT_CAUSE_SCHEMA = {
    "type": "object",
    "description": "漏洞根因分析。推理不可信数据的完整数据流：从哪里进入(source)、经过哪些传播步骤(propagation)、最终到达哪个危险操作(sink)、缺失了什么安全控制。",
    "properties": {
        "status": {
            "type": "string",
            "enum": ["confirmed", "probable", "possible", "unknown"],
            "description": "根因确认状态",
        },
        "root_cause_category": {
            "type": "string",
            "enum": [
                "missing_input_validation", "missing_output_encoding", "missing_authorization",
                "incorrect_authorization_scope", "unsafe_api_usage", "missing_security_control",
                "insecure_configuration", "vulnerable_dependency", "authentication_bypass",
                "unsafe_deserialization", "path_boundary_violation", "unknown",
            ],
            "description": "根因分类",
        },
        "summary": {"type": "string", "description": "根因一句话摘要"},
        "source": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "不可信数据来源符号（函数名/变量名）"},
                "file": {"type": "string"},
                "line": {"type": ["integer", "null"]},
            },
            "description": "不可信数据的入口点",
        },
        "propagation": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"},
                    "operation": {"type": "string", "description": "传播操作描述"},
                },
            },
            "description": "数据传播步骤",
        },
        "sink": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "危险操作符号"},
                "file": {"type": "string"},
                "line": {"type": ["integer", "null"]},
            },
            "description": "危险操作的汇点",
        },
        "missing_control": {
            "type": "string",
            "description": "缺失的安全控制。如 parameterized_query, output_encoding, path_sanitization, check_alias_validation",
        },
        "failed_existing_controls": {
            "type": "array", "items": {
                "type": "object",
                "properties": {"control": {"type": "string"}, "reason": {"type": "string"}},
            },
            "description": "存在但失效的安全控制",
        },
        "guards_present": {
            "type": "array", "items": {"type": "string"},
            "description": "路径上已有的安全守卫",
        },
        "trigger_conditions": {
            "type": "array", "items": {"type": "string"},
            "description": "触发漏洞的条件",
        },
        "causal_chain": {
            "type": "array", "items": {"type": "string"},
            "description": "完整的因果链描述",
        },
        "affected_code": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "function": {"type": ["string", "null"]},
                    "lines": {"type": "array", "items": {"type": "integer"}},
                    "role": {"type": "string"},
                },
            },
            "description": "受影响的代码位置",
        },
        "contributing_factors": {
            "type": "array", "items": {"type": "string"},
            "description": "contributing factors",
        },
        "alternative_hypotheses": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "hypothesis": {"type": "string"},
                    "result": {"type": "string", "enum": ["confirmed", "rejected", "unresolved"]},
                    "reason": {"type": "string"},
                },
            },
            "description": "已排除或待验证的替代假设",
        },
        "security_invariant": {
            "type": "string",
            "description": "本漏洞对应的安全不变量（正常状态下必须成立的属性）",
        },
        "guardrail": {
            "type": "string",
            "description": "本路径必须执行的安全守卫",
        },
        "broken_mechanism": {
            "type": "array", "items": {"type": "string"},
            "description": "破坏机制的逐步描述（入口→传播→缺失安检→汇点→触发条件）",
        },
        "exploitability_note": {
            "type": "string",
            "description": "可利用性说明",
        },
        "recommended_fix_constraints": {
            "type": "array", "items": {"type": "string"},
            "description": "修复必须满足的约束条件",
        },
        "confidence_score": {
            "type": "number", "minimum": 0, "maximum": 1,
            "description": "根因分析置信度",
        },
        "unknowns": {
            "type": "array", "items": {"type": "string"},
            "description": "仍然未知的信息",
        },
        "needs_human_review": {"type": "boolean"},
        "reasoning": {"type": "string", "description": "推理过程"},
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "hypothesis": {"type": "string"},
                    "required_evidence": {"type": "array", "items": {"type": "string"}},
                    "support": {"type": "array", "items": {"type": "string"}},
                    "counter_evidence": {"type": "array", "items": {"type": "string"}},
                    "verdict": {"type": "string", "enum": ["confirmed", "rejected", "unknown"]},
                },
            },
        },
    },
    "required": ["status", "root_cause_category", "summary", "missing_control", "causal_chain", "confidence_score", "needs_human_review"],
}


# ── PatchCandidate schema (关键字段) ──────────────────────────────────

PATCH_SCHEMA = {
    "type": "object",
    "description": "补丁生成结果。推理并生成修复代码变更。",
    "properties": {
        "summary": {"type": "string", "description": "补丁摘要"},
        "artifacts": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "patch_type": {"type": "string", "enum": ["code", "dependency", "configuration", "test", "virtual", "documentation"]},
                    "target": {"type": "string", "description": "目标文件路径"},
                    "content": {"type": "string", "description": "补丁内容 (unified diff 格式)"},
                    "description": {"type": "string"},
                },
                "required": ["patch_type", "target", "content", "description"],
            },
        },
        "changed_files": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "change_type": {"type": "string", "enum": ["code", "dependency", "configuration", "test", "virtual", "documentation"]},
                    "reason": {"type": "string"},
                },
            },
        },
        "security_notes": {"type": "array", "items": {"type": "string"}},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "risks": {"type": "array", "items": {"type": "string"}},
        "needs_human_review": {"type": "boolean"},
        "blocked_reason": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
    },
    "required": ["summary", "artifacts", "changed_files", "needs_human_review"],
}


# ── FailureAnalysis schema ────────────────────────────────────────────

FAILURE_ANALYSIS_SCHEMA = {
    "type": "object",
    "description": "补丁验证失败分析。诊断为什么验证失败，并给出修复建议。",
    "properties": {
        "primary_category": {
            "type": "string",
            "enum": ["build_failure", "test_harness_failure", "business_regression", "security_not_fixed", "scanner_still_reports", "differential_risk", "patch_policy_violation", "tooling_gap", "unknown"],
        },
        "summary": {"type": "string", "description": "失败原因一句话摘要"},
        "findings": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "category": {"type": "string"},
                    "severity": {"type": "string", "enum": ["blocker", "high", "medium", "low"]},
                    "failed_layer": {"type": ["string", "null"]},
                    "summary": {"type": "string"},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "suspected_reason": {"type": "string"},
                    "suggested_adjustment": {"type": "string"},
                },
                "required": ["category", "severity", "summary", "suspected_reason", "suggested_adjustment"],
            },
        },
        "remediation_feedback": {"type": "array", "items": {"type": "string"}, "description": "给修复方案 Agent 的反馈"},
        "patch_generation_feedback": {"type": "array", "items": {"type": "string"}, "description": "给补丁生成 Agent 的反馈"},
        "validation_feedback": {"type": "array", "items": {"type": "string"}, "description": "给验证工具链的反馈"},
        "route_to": {
            "type": "string",
            "enum": ["remediation_plan_agent", "root_cause_agent", "patch_generation_agent", "validation_toolchain", "human_review"],
        },
        "diagnostic_hypotheses": {"type": "array", "items": {"type": "string"}},
        "reflection": {"type": "array", "items": {"type": "string"}},
        "do_not_repeat": {"type": "array", "items": {"type": "string"}},
        "requires_root_cause_recheck": {"type": "boolean", "description": "是否需要重新检查根因"},
        "needs_human_review": {"type": "boolean"},
        "reasoning": {"type": "string"},
    },
    "required": ["primary_category", "summary", "findings", "remediation_feedback", "patch_generation_feedback", "needs_human_review"],
}


# ── RemediationPlan schema ────────────────────────────────────────────

REMEDIATION_PLAN_SCHEMA = {
    "type": "object",
    "description": "修复方案。推理出最优的修复策略和具体步骤。",
    "properties": {
        "status": {"type": "string", "enum": ["ready", "needs_context", "needs_human_review", "blocked"]},
        "remediation_goal": {"type": "string", "description": "修复目标"},
        "strategies": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "strategy_type": {"type": "string", "enum": ["code_change", "dependency_upgrade", "configuration_change", "virtual_patch", "test_only", "manual_remediation", "investigation_required"]},
                    "summary": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                    "preferred": {"type": "boolean", "default": True},
                },
                "required": ["strategy_type", "summary", "steps"],
            },
        },
        "planned_changes": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "change_type": {"type": "string"},
                    "description": {"type": "string"},
                    "reason": {"type": "string"},
                    "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "causally_required": {"type": "boolean", "description": "此文件是否被根因因果链直接命中，遗漏会导致漏洞仍然可达。source→sink 路径上的文件必须设为 true。"},
                },
                "required": ["file", "change_type", "description", "reason"],
            },
        },
        "risk_points": {"type": "array", "items": {"type": "string"}},
        "required_tests": {
            "type": "array", "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "test_type": {"type": "string"},
                    "target": {"type": "string"},
                    "assertion": {"type": "string"},
                },
                "required": ["name", "test_type", "target", "assertion"],
            },
        },
        "rejected_alternatives": {
            "type": "array", "items": {
                "type": "object",
                "properties": {"alternative": {"type": "string"}, "reason": {"type": "string"}},
            },
        },
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
        "needs_human_review": {"type": "boolean"},
        "reasoning": {"type": "string"},
        "candidate_rankings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "strategy": {"type": "string"},
                    "causal_chain": {"type": "number"},
                    "security_invariant": {"type": "number"},
                    "compatibility": {"type": "number"},
                    "verifiability": {"type": "number"},
                    "change_risk": {"type": "number"},
                    "weighted_score": {"type": "number"},
                    "selected": {"type": "boolean"},
                },
            },
        },
    },
    "required": ["status", "remediation_goal", "strategies", "planned_changes", "required_tests", "risk_points", "needs_human_review"],
}


# ── LLM Backend (multi-provider via OpenAI SDK) ────────────────────────

DEFAULT_MODEL = "deepseek-chat"


def _get_default_model() -> str:
    """读取默认模型：LLM_MODEL > DEEPSEEK_MODEL（向后兼容）> DEFAULT_MODEL。"""
    return os.environ.get("LLM_MODEL") or os.environ.get("DEEPSEEK_MODEL") or DEFAULT_MODEL


# Provider configs — model name prefix determines provider
_PROVIDER_CONFIG: dict[str, dict[str, str]] = {
    "glm": {
        "api_key_env": "GLM_API_KEY",
        "base_url_env": "GLM_BASE_URL",
        "default_base_url": "https://open.bigmodel.cn/api/paas/v4/",
    },
    "deepseek": {
        "api_key_env": "DEEPSEEK_API_KEY",
        "base_url_env": "DEEPSEEK_BASE_URL",
        "default_base_url": "https://api.deepseek.com",
    },
}


def _detect_provider(model: str) -> str:
    """Detect provider from model name. Returns 'deepseek' or 'glm'."""
    model_lower = model.lower()
    if "glm" in model_lower:
        return "glm"
    return "deepseek"


def _provider_credentials(model: str) -> tuple[str, str]:
    """Return (api_key, base_url) for the given model's provider."""
    provider = _detect_provider(model)
    cfg = _PROVIDER_CONFIG[provider]
    api_key = os.environ.get(cfg["api_key_env"], "")
    base_url = os.environ.get(cfg["base_url_env"], "") or cfg["default_base_url"]
    return api_key, base_url


# ── ChatResponse ────────────────────────────────────────────────────────


@dataclass(slots=True)
class ChatResponse:
    """LLM 多轮对话响应 — Agent 循环的核心数据类型。"""
    content: str | None
    tool_calls: list[dict[str, Any]] | None
    finish_reason: str | None


@dataclass(slots=True)
class LLMBackend:
    """多 provider LLM 后端（兼容 OpenAI SDK）。

    根据 model 名自动选择 provider：
      - glm-5.2           → 智谱 GLM  API
      - deepseek-v4-pro   → DeepSeek API
      - deepseek-chat     → DeepSeek API
      - deepseek-reasoner → DeepSeek API

    Usage:
        llm = LLMBackend()                       # 从环境变量读
        llm = LLMBackend(model="glm-5.2")        # 指定模型
        llm = LLMBackend(model="deepseek-chat")  # 自动切到 DeepSeek
    """

    model: str = DEFAULT_MODEL
    api_key: str | None = None
    base_url: str = ""
    max_tokens: int = 16384
    request_timeout_seconds: float = 120.0

    def __post_init__(self):
        # 环境变量兜底 model（LLM_MODEL 优先，DEEPSEEK_MODEL 向后兼容）
        env_model = _get_default_model()
        if env_model and self.model == DEFAULT_MODEL:
            self.model = env_model

        # 根据 model 自动选择 provider 的 api_key / base_url
        key, url = _provider_credentials(self.model)
        if not self.api_key:
            self.api_key = key
        if not self.base_url:
            self.base_url = url

        env_timeout = os.environ.get("DEEPSEEK_TIMEOUT_SECONDS")
        if env_timeout:
            self.request_timeout_seconds = float(env_timeout)

    def reason(
        self,
        user_prompt: str,
        *,
        system_prompt: str = "",
        output_schema: dict[str, Any] | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> dict[str, Any] | str:
        """调用 DeepSeek 进行推理。

        Args:
            user_prompt: 推理请求（包含所有需要的上下文）
            system_prompt: 系统提示
            output_schema: 可选的结构化输出 JSON Schema
            temperature: 推理温度

        Returns:
            如果给了 output_schema，返回解析后的 dict；
            否则返回 DeepSeek 的文本响应。
        """
        if not self.api_key:
            raise RuntimeError("未设置 DEEPSEEK_API_KEY 环境变量，无法调用 LLM。")

        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError(
                "需要安装 openai SDK：pip install openai"
            )

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            max_retries=1,
        )

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        if output_schema:
            return self._structured_call(client, messages, output_schema, temperature, max_tokens)

        # 非结构化调用
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens or self.max_tokens,
            temperature=temperature,
        )
        content = response.choices[0].message.content
        return content or ""

    # ── 多轮对话接口（Agent 循环使用）──────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
        max_tokens: int | None = None,
    ) -> "ChatResponse":
        """多轮对话接口 — 支持工具调用的 Agent 推理循环。

        Args:
            messages: 完整对话历史（含 system/user/assistant/tool 角色）
            tools: 可用的工具定义列表（OpenAI function calling 格式）
            temperature: 推理温度

        Returns:
            ChatResponse: 包含 content、tool_calls、finish_reason
        """
        if not self.api_key:
            raise RuntimeError("未设置 DEEPSEEK_API_KEY 环境变量，无法调用 LLM。")

        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError("需要安装 openai SDK：pip install openai")

        client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            max_retries=1,
        )

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature,
        }
        if tools:
            kwargs["tools"] = tools

        response = client.chat.completions.create(**kwargs)
        msg = response.choices[0].message
        finish = response.choices[0].finish_reason

        # 提取 tool_calls
        raw_tool_calls: list[dict[str, Any]] | None = None
        if msg.tool_calls:
            raw_tool_calls = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]

        return ChatResponse(
            content=msg.content,
            tool_calls=raw_tool_calls,
            finish_reason=finish,
        )

    def _structured_call(
        self,
        client,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        temperature: float,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        """使用 OpenAI function calling 实现结构化输出。

        DeepSeek 思考模式（deepseek-v4-pro 等）不支持 tool_choice 参数，
        因此只传 tools 让模型自行决定调用 function。

        解析失败时返回原始文本字符串（而非抛异常），
        以便调用方通过 isinstance(raw, str) 回退到确定性模式。
        """
        tool_name = schema.get("title", "output_result")

        function_def = {
            "name": tool_name,
            "description": schema.get("description", "Structured output"),
            "parameters": {
                "type": schema.get("type", "object"),
                "properties": schema.get("properties", {}),
                "required": schema.get("required", []),
            },
        }

        # 不传 tool_choice（兼容 DeepSeek 思考模式）
        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                tools=[{"type": "function", "function": function_def}],
            )
        except Exception as exc:
            # API 调用本身失败 → 返回文本让调用方降级
            return f"[LLM API Error] {exc}"

        msg = response.choices[0].message

        # 优先从 tool_calls 提取
        if msg.tool_calls:
            tool_args_raw = msg.tool_calls[0].function.arguments
            try:
                parsed = json.loads(tool_args_raw)
            except (json.JSONDecodeError, AttributeError):
                parsed = None

            if parsed is None:
                # JSON 可能被截断 — 使用 robust repair 模块
                from .json_repair import repair_json
                parsed = repair_json(tool_args_raw)
                if parsed is not None:
                    print(f"[LLM] JSON 被截断，已自动修复")

            if isinstance(parsed, dict):
                # ── 校验 output_schema 必需字段 ──
                missing = _validate_schema_required(parsed, schema)
                if missing:
                    print(f"[LLM] JSON 缺少必需字段: {missing}，仍返回但标记 _schema_missing")
                    parsed["_schema_missing"] = list(missing)
                return parsed

            # 无法修复 → 返回 raw string 触发 fallback
            return tool_args_raw

        # Fallback: 从文本内容中解析 JSON
        if msg.content:
            text = msg.content
            try:
                parsed = self._extract_json_from_text(text)
                if isinstance(parsed, dict):
                    # ── 校验 output_schema 必需字段 ──
                    missing = _validate_schema_required(parsed, schema)
                    if missing:
                        print(f"[LLM] 文本提取 JSON 缺少必需字段: {missing}")
                        parsed["_schema_missing"] = list(missing)
                    return parsed
                if parsed is not None:
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            return text

        # 如果 thinking 模式返回了 reasoning_content，尝试从中提取
        if hasattr(msg, "reasoning_content") and msg.reasoning_content:
            text = msg.reasoning_content
            try:
                parsed = self._extract_json_from_text(text)
                if parsed is not None:
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            return text

        # 完全空响应
        return "[LLM] 空响应"

    @staticmethod
    def _extract_json_from_text(text: str) -> dict[str, Any] | None:
        """从文本中提取 JSON 对象，尝试 repair 回退。"""
        from .json_repair import repair_json

        if "```json" in text:
            start = text.index("```json") + 7
            end = text.index("```", start)
            block = text[start:end]
            try:
                return json.loads(block)
            except json.JSONDecodeError:
                repaired = repair_json(block)
                if repaired is not None:
                    return repaired
        if "{" in text:
            start = text.index("{")
            end = text.rindex("}") + 1
            block = text[start:end]
            try:
                return json.loads(block)
            except json.JSONDecodeError:
                repaired = repair_json(block)
                if repaired is not None:
                    return repaired
        return None

    @staticmethod
    def _try_fix_truncated_json(raw: str) -> dict[str, Any] | None:
        """[DEPRECATED] 委托给 json_repair.repair_json。"""
        from .json_repair import repair_json
        return repair_json(raw)


# ── 便捷函数 ──────────────────────────────────────────────────────────

def create_llm_backend(model: str | None = None) -> LLMBackend | None:
    """如果任一 provider 的 API Key 已设置，返回 LLMBackend；否则返回 None。

    根据 model 名自动选择 provider：
      - glm-5.2           → GLM_API_KEY + GLM_BASE_URL
      - deepseek-*        → DEEPSEEK_API_KEY + DEEPSEEK_BASE_URL

    用法:
        llm = create_llm_backend()
        llm = create_llm_backend(model="glm-5.2")
        agent = ImpactAnalysisAgent(..., llm=llm)
    """
    selected_model = model or _get_default_model()
    key, _ = _provider_credentials(selected_model)
    if not key:
        return None
    return LLMBackend(model=selected_model)
