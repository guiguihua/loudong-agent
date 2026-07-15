"""BaseAgent — ReAct 风格的 Agent 基类。

每个 Agent 继承 BaseAgent，获得：
  - 多轮推理循环 (Observe → Think → Act → Observe → ...)
  - 工具调用能力（读文件、搜索代码、运行命令）
  - 结构化输出解析

真正的 Agent = 大模型 + 工具 + 循环决策，而不是"拼 prompt → 一次 API 调用 → 解析 JSON"。
"""

from __future__ import annotations

import json
import hashlib
import html
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .llm import ChatResponse, LLMBackend


# ── Tool 定义 ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class Tool:
    """Agent 可调用的工具。"""
    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema properties
    required: list[str]         # 必需参数名
    handler: Callable[..., str]  # 实际执行函数，返回字符串结果

    def to_openai_schema(self) -> dict[str, Any]:
        """转为 OpenAI/DeepSeek function calling 格式。"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.parameters,
                    "required": self.required,
                },
            },
        }


# ── BaseAgent ───────────────────────────────────────────────────────────


@dataclass(slots=True)
class BaseAgent:
    """ReAct Agent 基类。

    子类只需定义 name, system_prompt, tools 三个属性，
    然后调用 self.run(task) 即可触发多轮推理循环。

    循环逻辑：
      1. 发送 messages（system + user + 历史工具调用）
      2. LLM 返回 → 有 tool_calls？执行工具，结果追加到 messages，回到步骤1
      3. LLM 返回 → 无 tool_calls？解析 content 为结构化输出，结束
    """

    name: str = "BaseAgent"
    system_prompt: str = ""
    tools: list[Tool] = field(default_factory=list)
    llm: LLMBackend | None = None
    max_turns: int = 10
    workspace: Path = field(default_factory=Path.cwd)
    reasoning_mode: str = "bounded_react"
    tool_budget: dict[str, int] = field(default_factory=dict)
    allowed_paths: list[str] = field(default_factory=list)
    no_progress_limit: int = 2
    max_fallback_calls: int = 2
    max_output_tokens: int | None = None
    last_run_stats: dict[str, Any] = field(default_factory=dict)

    # 子类可覆盖，定义最终输出的 JSON Schema
    output_schema: dict[str, Any] | None = None

    def run(
        self,
        task: str,
        context: dict[str, Any] | None = None,
        *,
        continuation_messages: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """执行 Agent 任务。

        Args:
            task: 用户任务描述
            context: 额外上下文（可选）
            continuation_messages: 预构建的对话历史（可选）。
                提供后跳过 _build_initial_messages，直接从此历史继续 ReAct 循环。
                用于 single-shot 结果续接到深度推理，避免丢弃已有分析。

        Returns:
            结构化输出字典（LLM 最后一轮的内容解析为 JSON）
        """
        if not self.llm:
            raise RuntimeError(f"Agent '{self.name}' 需要 LLM 后端，但 llm 为 None")

        self.last_run_stats = {
            "reasoning_mode": self.reasoning_mode,
            "llm_calls": 0,
            "tool_calls": {},
            "stopped_reason": None,
        }
        if continuation_messages is not None:
            messages = list(continuation_messages)
        else:
            messages = self._build_initial_messages(task, context or {})
        tool_call_counts: dict[str, int] = {}
        seen_search_results: set[str] = set()
        consecutive_no_progress = 0

        # 构建本轮的全部工具（含 submit_final_result）
        active_tools = list(self.tools)
        if self.output_schema:
            active_tools.append(_make_submit_result_tool(self.output_schema))

        for turn in range(1, self.max_turns + 1):
            response = self._call_llm(messages, active_tools)

            # Some OpenAI-compatible reasoning models occasionally render a
            # function call as XML-like text instead of populating tool_calls.
            # Treat a strictly recognizable call as a tool action, otherwise
            # BaseAgent would incorrectly accept it as the final answer.
            tool_calls = response.tool_calls or self._tool_calls_from_text(
                response.content or "", active_tools, turn
            )

            # 有工具调用 → 先检查是否调用了 submit_final_result
            if tool_calls:
                # 检查是否调用了 submit_final_result（优先处理）
                for tc in tool_calls:
                    func_name = tc.get("function", {}).get("name", "")
                    if func_name == "submit_final_result":
                        args_str = tc.get("function", {}).get("arguments", "{}")
                        args_str = args_str if isinstance(args_str, str) else str(args_str)

                        # Tier 1: direct parse → validate required fields.
                        t1_missing: list[str] | None = None
                        try:
                            parsed = json.loads(args_str)
                            t1_missing = self._validate_against_schema(parsed, self.output_schema)
                            if not t1_missing:
                                self.last_run_stats["stopped_reason"] = "submitted_result"
                                return parsed
                            _safe_print(
                                f"  [{self.name}] [WARN] submit_final_result 缺少字段: {t1_missing}，尝试修复..."
                            )
                        except json.JSONDecodeError:
                            t1_missing = None

                        # Tier 2: JSON repair → validate required fields.
                        from .json_repair import repair_json
                        repaired = repair_json(args_str)
                        if repaired is not None:
                            t2_missing = self._validate_against_schema(repaired, self.output_schema)
                            if not t2_missing:
                                _safe_print(f"  [{self.name}] [INFO] submit_final_result JSON repaired successfully")
                                self.last_run_stats["stopped_reason"] = "submitted_result_repaired"
                                return repaired
                            _safe_print(
                                f"  [{self.name}] [WARN] JSON 修复后仍缺少字段: {t2_missing}，重新提交..."
                            )
                            missing = t2_missing
                        else:
                            # Preserve Tier 1's missing fields if available
                            missing = t1_missing if t1_missing else ["<JSON 修复失败>"]

                        # Tier 3: Resubmit — give the LLM one chance to fix.
                        resubmitted = self._try_resubmit_final_result(
                            args_str, messages, active_tools, missing_fields=missing
                        )
                        if resubmitted is not None:
                            self.last_run_stats["stopped_reason"] = "submitted_result_resubmitted"
                            return resubmitted

                        # Tier 4: Text extraction (improved).
                        _safe_print(f"  [{self.name}] [WARN] submit_final_result JSON 解析失败，尝试从文本提取")
                        return self._parse_final_output(str(args_str))

                # 1. 先添加 assistant 消息（含 tool_calls）
                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": response.content,
                    "tool_calls": tool_calls,
                }
                messages.append(assistant_msg)

                # 2. 执行每个工具，添加 tool 结果消息
                stop_requested = False
                for tc in tool_calls:
                    tool_msg = self._handle_tool_call(tc, tool_call_counts)
                    messages.append(tool_msg)
                    func_name = tc.get("function", {}).get("name", "")
                    if func_name == "search_code":
                        content = str(tool_msg.get("content", ""))
                        fingerprint = hashlib.sha256(content.encode("utf-8")).hexdigest()
                        no_result = content.startswith("未找到") or content.startswith("错误:")
                        if no_result or fingerprint in seen_search_results:
                            consecutive_no_progress += 1
                        else:
                            consecutive_no_progress = 0
                            seen_search_results.add(fingerprint)
                        if consecutive_no_progress >= self.no_progress_limit:
                            self.last_run_stats["stopped_reason"] = "no_new_evidence"
                            stop_requested = True
                if stop_requested:
                    break
                continue

            # 无工具调用 → Agent 完成，解析输出
            self.last_run_stats["stopped_reason"] = "model_completed"
            return self._parse_final_output(response.content or "")

        # 超过 max_turns — 多级回退策略
        if not self.last_run_stats.get("stopped_reason"):
            self.last_run_stats["stopped_reason"] = "max_turns"
        _safe_print(f"  [{self.name}] [WARN] 受限推理停止（{self.last_run_stats['stopped_reason']}），尝试最终结构化输出...")

        # 回退 1：追加强制输出指令，不带工具再试一次
        force_msg = (
            "你已达到最大推理轮数限制。现在**必须立即**输出最终 JSON 分析结果。\n"
            "不要再调用任何工具！直接在文本中输出完整的 JSON 对象。"
        )
        messages.append({"role": "user", "content": force_msg})
        try:
            final_response = self._call_llm(messages, tools=None)
            if final_response.content:
                result = self._parse_final_output(final_response.content)
                if "_raw_output" not in result:
                    _safe_print(f"  [{self.name}] 回退成功（第1级）")
                    return result
        except Exception:
            pass

        if self.max_fallback_calls <= 1:
            raise RuntimeError(
                f"Agent '{self.name}' 受限推理停止，最终结构化输出失败: "
                f"{self.last_run_stats['stopped_reason']}"
            )

        # 回退 2：仅供显式允许的兼容模式使用
        _safe_print(f"  [{self.name}] [WARN] 回退1失败，尝试纯净上下文...")
        try:
            clean_messages: list[dict[str, Any]] = [
                {"role": "system", "content": self.system_prompt + "\n\n你现在必须立即输出最终 JSON 分析结果。不要再调用工具，不要输出其他内容。"},
                {"role": "user", "content": task + "\n\n请立即输出完整的 JSON 结果。"},
            ]
            final_response = self._call_llm(clean_messages, tools=None)
            if final_response.content:
                result = self._parse_final_output(final_response.content)
                if "_raw_output" not in result:
                    _safe_print(f"  [{self.name}] 回退成功（第2级-纯净上下文）")
                    return result
                # 即使只有 raw_output 也返回
                _safe_print(f"  [{self.name}] 回退2获得非结构化文本，按 raw_output 返回")
                return result
        except Exception:
            pass

        raise RuntimeError(
            f"Agent '{self.name}' 超过最大推理轮数 {self.max_turns}，"
            f"所有回退策略均失败"
        )

    @staticmethod
    def _tool_calls_from_text(
        content: str,
        active_tools: list[Tool],
        turn: int,
    ) -> list[dict[str, Any]] | None:
        """Convert legacy ``<tool><arg>...</arg></tool>`` text to tool calls.

        This adapter is deliberately narrow: the outer tag must name an
        active non-submit tool and every required argument must be present.
        Arbitrary prose or incomplete XML is still treated as normal model
        output and will fail structured-output validation.
        """
        if not content or "<" not in content:
            return None
        tools_by_name = {
            tool.name: tool for tool in active_tools
            if tool.name != "submit_final_result"
        }
        if not tools_by_name:
            return None

        names = "|".join(re.escape(name) for name in sorted(tools_by_name, key=len, reverse=True))
        outer = re.compile(
            rf"<(?P<name>{names})>\s*(?P<body>[\s\S]*?)\s*</(?P=name)>",
            re.IGNORECASE,
        )
        calls: list[dict[str, Any]] = []
        for index, match in enumerate(outer.finditer(content), 1):
            matched_name = match.group("name")
            canonical_name = next(
                (name for name in tools_by_name if name.lower() == matched_name.lower()),
                matched_name,
            )
            tool = tools_by_name[canonical_name]
            body = match.group("body")
            arguments: dict[str, Any] = {}
            for parameter, schema in tool.parameters.items():
                value_match = re.search(
                    rf"<{re.escape(parameter)}>\s*([\s\S]*?)\s*</{re.escape(parameter)}>",
                    body,
                    re.IGNORECASE,
                )
                if not value_match:
                    continue
                raw_value = html.unescape(value_match.group(1).strip())
                value_type = schema.get("type") if isinstance(schema, dict) else None
                if value_type == "integer":
                    try:
                        arguments[parameter] = int(raw_value)
                    except ValueError:
                        continue
                elif value_type == "boolean":
                    arguments[parameter] = raw_value.lower() in {"1", "true", "yes"}
                else:
                    arguments[parameter] = raw_value
            if any(required not in arguments for required in tool.required):
                continue
            calls.append({
                "id": f"text-tool-{turn}-{index}",
                "type": "function",
                "function": {
                    "name": canonical_name,
                    "arguments": json.dumps(arguments, ensure_ascii=False),
                },
            })
        return calls or None

    # ── 内部方法 ────────────────────────────────────────────────────────

    def _build_initial_messages(
        self, task: str, context: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """构建初始 messages（system + user）。"""
        system = self.system_prompt
        if context:
            system += "\n\n## 受限推理控制\n" + json.dumps(context, ensure_ascii=False, indent=2)
        if self.output_schema:
            schema_str = json.dumps(self.output_schema, ensure_ascii=False, indent=2)
            system += (
                f"\n\n## 输出格式\n"
                f"你的最终输出必须符合以下 JSON Schema：\n```json\n{schema_str}\n```\n"
                f"**重要**：当你收集到足够信息、完成全部分析后，"
                f"必须调用 `submit_final_result` 工具来提交最终结果。"
                f"不要直接在文本中输出 JSON — 务必通过 submit_final_result 工具提交。"
            )

        # 添加工件目录信息
        workspace_info = f"\n\n当前工作目录: {self.workspace}"

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system + workspace_info},
            {"role": "user", "content": task},
        ]
        return messages

    def _call_llm(
        self,
        messages: list[dict[str, Any]],
        tools: list[Tool] | None = None,
    ) -> ChatResponse:
        """调用 LLM（支持工具）。

        Args:
            messages: 对话历史
            tools: 本轮可用的工具列表。为 None 时不传工具（强制 LLM 输出文本）。
                   传入空列表 [] 也不传工具。
        """
        if tools:
            tool_schemas = [t.to_openai_schema() for t in tools]
        else:
            tool_schemas = None
        if self.last_run_stats:
            self.last_run_stats["llm_calls"] = int(self.last_run_stats.get("llm_calls", 0)) + 1
        try:
            return self.llm.chat(  # type: ignore[union-attr]
                messages, tools=tool_schemas, max_tokens=self.max_output_tokens
            )
        except TypeError:
            # Compatibility with lightweight test doubles and custom backends.
            return self.llm.chat(messages, tools=tool_schemas)  # type: ignore[union-attr]

    def _handle_tool_call(
        self,
        tool_call: dict[str, Any],
        tool_call_counts: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        """执行工具调用，返回 assistant 消息格式。"""
        func_name = tool_call.get("function", {}).get("name", "unknown")
        func_args_str = tool_call.get("function", {}).get("arguments", "{}")

        # 解析参数
        try:
            func_args = json.loads(func_args_str) if isinstance(func_args_str, str) else func_args_str
        except json.JSONDecodeError:
            func_args = {}

        counts = tool_call_counts if tool_call_counts is not None else {}
        limit = self.tool_budget.get(func_name)
        if limit is not None and counts.get(func_name, 0) >= limit:
            result = f"工具预算已耗尽: {func_name} 最多允许 {limit} 次调用"
            self.last_run_stats["stopped_reason"] = "tool_budget_exhausted"
            return {
                "role": "tool",
                "tool_call_id": tool_call.get("id", ""),
                "content": result,
            }
        if not self._path_allowed(func_name, func_args):
            result = f"路径越界: {func_args.get('path', '.')} 不在本阶段 allowed_paths 内"
            return {
                "role": "tool",
                "tool_call_id": tool_call.get("id", ""),
                "content": result,
            }
        counts[func_name] = counts.get(func_name, 0) + 1
        self.last_run_stats["tool_calls"] = dict(counts)

        # 查找并执行工具
        tool = next((t for t in self.tools if t.name == func_name), None)
        if tool is None:
            result = f"错误: 未知工具 '{func_name}'"
        else:
            try:
                result = tool.handler(**func_args)
                _safe_print(f"  [{self.name}] [TOOL] {func_name}({_brief_args(func_args)}) -> {_brief_result(result)}")
            except Exception as exc:
                result = f"工具执行失败: {exc}"
                _safe_print(f"  [{self.name}] [ERR] {func_name}({_brief_args(func_args)}) -> {exc}")

        return {
            "role": "tool",
            "tool_call_id": tool_call.get("id", ""),
            "content": result,
        }

    def _path_allowed(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        if not self.allowed_paths or tool_name not in {"read_file", "search_code", "list_dir"}:
            return True
        requested = str(arguments.get("path", ".") or ".").replace("\\", "/").lstrip("./")
        if requested in {"", "."}:
            return False
        allowed = [item.replace("\\", "/").lstrip("./") for item in self.allowed_paths if item]
        if tool_name == "read_file":
            return any(requested == item or requested.endswith("/" + item) for item in allowed)
        return any(
            item == requested or item.startswith(requested.rstrip("/") + "/")
            for item in allowed
        )

    @staticmethod
    def _validate_against_schema(
        result: dict[str, Any], output_schema: dict[str, Any] | None
    ) -> list[str]:
        """Validate parsed result against output_schema required fields.

        Returns a list of missing/invalid field paths (empty = valid).
        Checks top-level required fields and one level of nesting.
        """
        if not output_schema or not isinstance(result, dict):
            return []
        required = output_schema.get("required", [])
        if not isinstance(required, list):
            return []
        properties = output_schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        missing: list[str] = []
        for field in required:
            if field not in result or result[field] is None:
                missing.append(field)
                continue
            # Check nested required fields for object-type properties
            field_schema = properties.get(field, {})
            if isinstance(field_schema, dict):
                nested_required = field_schema.get("required", [])
                if isinstance(nested_required, list):
                    nested_value = result[field]
                    if isinstance(nested_value, dict):
                        for nested_field in nested_required:
                            if nested_field not in nested_value or nested_value[nested_field] is None:
                                missing.append(f"{field}.{nested_field}")
        return missing

    def _try_resubmit_final_result(
        self,
        broken_args: str,
        messages: list[dict[str, Any]],
        active_tools: list[Tool],
        missing_fields: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Give the LLM one chance to fix malformed/incomplete JSON in submit_final_result.

        Returns a parsed dict on success, or None if the LLM could not produce
        valid JSON after one correction attempt.
        """
        if not self.llm or self.max_fallback_calls < 1:
            return None

        missing_hint = ""
        if missing_fields:
            missing_hint = (
                "\n\n**关键问题**：你的输出缺少以下必需字段，请补充完整：\n"
                + "\n".join(f"  - `{f}`" for f in missing_fields)
                + "\n请基于你的分析结论填充这些字段的合理值，不要编造没有证据支持的内容。"
            )

        correction_prompt = (
            "你刚才调用了 submit_final_result 工具，但传入的 JSON 参数格式有误"
            "（可能被截断、包含非法的 JSON 语法，或缺少必需字段）。\n\n"
            "下面是你在工具调用中传入的原始内容：\n"
            "```\n" + broken_args[:4000] + "\n```\n"
            + missing_hint + "\n\n"
            "请**更正 JSON 语法错误并补全缺失字段**后再次调用 submit_final_result 工具提交正确的 JSON。\n"
            "保持原有的分析结论不变，只修复 JSON 格式和补充缺失字段。直接调用 submit_final_result。"
        )

        try:
            messages.append({"role": "user", "content": correction_prompt})
            response = self._call_llm(messages, active_tools)

            resubmit_ok: dict[str, Any] | None = None
            if response.tool_calls:
                for tc in response.tool_calls:
                    if tc.get("function", {}).get("name") == "submit_final_result":
                        args_str = tc.get("function", {}).get("arguments", "{}")
                        args_str = args_str if isinstance(args_str, str) else str(args_str)
                        try:
                            parsed = json.loads(args_str)
                        except json.JSONDecodeError:
                            from .json_repair import repair_json
                            parsed = repair_json(args_str)
                        if parsed is not None and isinstance(parsed, dict):
                            # Validate against schema one more time
                            schema_missing = self._validate_against_schema(parsed, self.output_schema)
                            if not schema_missing:
                                return parsed
                            _safe_print(
                                f"  [{self.name}] [WARN] resubmit 后仍缺少字段: {schema_missing}"
                            )
                            # Don't return None — fall through to text fallback below
                            resubmit_ok = parsed  # preserve partial result

            # Try text parsing (either no tool_calls, or tool_call validation failed)
            if response.content:
                parsed = self._parse_final_output(response.content)
                if "_raw_output" not in parsed:
                    schema_missing = self._validate_against_schema(parsed, self.output_schema)
                    if not schema_missing:
                        return parsed
                # Return best-effort partial result if available
                if resubmit_ok is not None:
                    return resubmit_ok
        except Exception:
            pass

        return None

    def _parse_final_output(self, content: str) -> dict[str, Any]:
        """解析 Agent 的最终文本输出为结构化 dict。

        Uses the robust JSON repair module before falling back to raw text.
        After each parse/repair tier, validates against output_schema required fields.
        """
        from .json_repair import repair_json, extract_largest_json_object

        def _valid_or_missing(parsed: dict) -> dict | None:
            """Return parsed if schema-valid, else return a dict with _missing fields so
            callers higher up can decide to resubmit or fall back."""
            missing = self._validate_against_schema(parsed, self.output_schema)
            if not missing:
                return parsed
            _safe_print(
                f"  [{self.name}] [WARN] _parse_final_output 修复后仍缺少字段: {missing}"
            )
            # Return with marker so BaseAgent.run can detect and handle
            parsed["_schema_missing"] = list(missing)
            return parsed

        # Tier 1: parse ```json fenced block directly.
        if "```json" in content:
            start = content.index("```json") + 7
            try:
                end = content.index("```", start)
            except ValueError:
                end = len(content)  # unclosed fence — use rest of content
            block = content[start:end].strip()
            try:
                parsed = json.loads(block)
                valid = _valid_or_missing(parsed)
                if valid is not None and "_schema_missing" not in valid:
                    return valid
                if valid is not None:
                    return valid  # has _schema_missing marker, let caller decide
            except json.JSONDecodeError:
                repaired = repair_json(block)
                if repaired is not None:
                    valid = _valid_or_missing(repaired)
                    if valid is not None:
                        return valid

        # Tier 2: extract the largest valid/reparable JSON object.
        obj = extract_largest_json_object(content)
        if obj is not None:
            valid = _valid_or_missing(obj)
            if valid is not None:
                return valid

        # Tier 3: attempt repair on the full text.
        repaired = repair_json(content)
        if repaired is not None:
            valid = _valid_or_missing(repaired)
            if valid is not None:
                return valid

        # Tier 4: ultimate fallback — return raw text.
        return {"_raw_output": content}


# ── 内置工具 ────────────────────────────────────────────────────────────


def _make_read_file(workspace: Path) -> Tool:
    """创建 read_file 工具（闭包捕获 workspace）。"""

    def read_file(path: str, start_line: int = 0, end_line: int = 0) -> str:
        """读取文件内容。"""
        file_path = _resolve_path(workspace, path)
        if not file_path.exists():
            return f"错误: 文件不存在: {path}"
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as exc:
            return f"错误: 无法读取 {path}: {exc}"

        total = len(lines)
        if start_line > 0 and end_line > 0:
            selected = lines[max(0, start_line - 1):end_line]
        elif start_line > 0:
            selected = lines[max(0, start_line - 1):]
        else:
            selected = lines[:500] if total > 500 else lines  # 默认最多500行

        result = "\n".join(
            f"{i+1:4d}|{line}"
            for i, line in enumerate(
                selected,
                max(0, start_line - 1) if start_line > 0 else 0,
            )
        )
        if total > len(selected):
            result += f"\n... (共 {total} 行，已显示 {len(selected)} 行)"
        return result

    return Tool(
        name="read_file",
        description="读取源码文件内容。返回带行号的文本。参数: path (文件路径), start_line (起始行，可选), end_line (结束行，可选)",
        parameters={
            "path": {"type": "string", "description": "文件路径（相对于工作目录）"},
            "start_line": {"type": "integer", "description": "起始行号（可选，从1开始）"},
            "end_line": {"type": "integer", "description": "结束行号（可选）"},
        },
        required=["path"],
        handler=read_file,
    )


def _make_search_code(workspace: Path) -> Tool:
    """创建 search_code 工具。"""
    import re
    import subprocess

    def search_code(pattern: str, path: str = ".") -> str:
        """在代码库中搜索模式。"""
        search_dir = _resolve_path(workspace, path)
        if not search_dir.exists():
            return f"错误: 目录不存在: {path}"

        try:
            # 用 ripgrep 风格的 grep
            result = subprocess.run(
                ["grep", "-rn", "--include=*.py", "--include=*.java", "--include=*.go",
                 "--include=*.js", "--include=*.ts", "--include=*.c", "--include=*.cpp",
                 "--include=*.html", "--include=*.yaml", "--include=*.yml",
                 "--include=*.json", "--include=*.xml",
                 "-E", pattern, str(search_dir)],
                capture_output=True, text=True, timeout=30, shell=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # grep 不可用（例如 Windows 上 Git Bash 的 grep 缺失 DLL）
            return _python_search(search_dir, pattern)

        # 防御性检查：某些 Windows 环境下 stdout 可能为 None
        stdout = getattr(result, "stdout", None)
        if stdout is None:
            return _python_search(search_dir, pattern)

        output = stdout.strip()
        if not output:
            return f"未找到匹配 '{pattern}' 的结果"
        lines = output.splitlines()[:50]
        total_matches = len(stdout.splitlines())
        header = f"找到 {total_matches} 处匹配 (显示前50):\n"
        return header + "\n".join(lines)

    return Tool(
        name="search_code",
        description="在代码库中搜索正则模式。返回匹配的文件名、行号和内容。参数: pattern (正则表达式), path (搜索目录，默认 '.')",
        parameters={
            "pattern": {"type": "string", "description": "正则表达式搜索模式"},
            "path": {"type": "string", "description": "搜索目录（默认当前目录）"},
        },
        required=["pattern"],
        handler=search_code,
    )


def _python_search(directory: Path, pattern: str) -> str:
    """纯 Python 实现的代码搜索（grep 不可用时的回退）。"""
    import re
    results: list[str] = []
    extensions = {".py", ".java", ".go", ".js", ".ts", ".c", ".cpp", ".html", ".yaml", ".yml", ".json", ".xml"}
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build", ".tox"}
    try:
        compiled = re.compile(pattern)
    except re.error:
        return f"无效的正则表达式: {pattern}"

    count = 0
    for f in directory.rglob("*"):
        if count >= 200:
            break
        if any(skip in f.parts for skip in skip_dirs):
            continue
        if not f.is_file() or f.suffix not in extensions:
            continue
        try:
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if compiled.search(line):
                    results.append(f"{f.relative_to(directory)}:{i}: {line.strip()[:120]}")
                    count += 1
                    if count >= 200:
                        break
        except Exception:
            continue

    if not results:
        return f"未找到匹配 '{pattern}' 的结果"
    return f"找到 {count} 处匹配:\n" + "\n".join(results[:50])


def _make_list_dir(workspace: Path) -> Tool:
    """创建 list_dir 工具。"""

    def list_dir(path: str = ".") -> str:
        """列出目录内容。"""
        target = _resolve_path(workspace, path)
        if not target.exists():
            return f"错误: 目录不存在: {path}"
        if not target.is_dir():
            return f"错误: 不是目录: {path}"

        items = sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        lines = []
        for item in items[:100]:
            kind = "📁" if item.is_dir() else "📄"
            try:
                size = item.stat().st_size
                size_str = f" ({_fmt_size(size)})" if not item.is_dir() else ""
            except OSError:
                size_str = ""
            lines.append(f"  {kind} {item.name}{size_str}")
        if len(items) > 100:
            lines.append(f"  ... 还有 {len(items) - 100} 项")
        return f"{target} ({len(items)} 项):\n" + "\n".join(lines)

    return Tool(
        name="list_dir",
        description="列出目录内容。返回文件和子目录列表。参数: path (目录路径，默认 '.')",
        parameters={
            "path": {"type": "string", "description": "目录路径（默认当前目录）"},
        },
        required=[],
        handler=list_dir,
    )


def _make_run_shell(workspace: Path) -> Tool:
    """创建 run_shell 工具。"""
    import subprocess

    def run_shell(command: str) -> str:
        """执行 shell 命令。"""
        # 安全检查：禁止危险命令
        dangerous = ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:", "> /dev/"]
        cmd_lower = command.lower()
        if any(d in cmd_lower for d in dangerous):
            return "错误: 命令可能具有破坏性，已被拒绝"

        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=60, cwd=str(workspace),
            )
        except subprocess.TimeoutExpired:
            return "错误: 命令超时 (60s)"

        output = result.stdout.strip()
        if result.stderr.strip():
            output += "\n[stderr]\n" + result.stderr.strip()
        if not output:
            output = f"(exit code: {result.returncode})"
        return _truncate(output, 3000)

    return Tool(
        name="run_shell",
        description="执行 shell 命令并返回输出。用于运行测试、检查语法、git 操作等。参数: command (shell 命令字符串)",
        parameters={
            "command": {"type": "string", "description": "要执行的 shell 命令"},
        },
        required=["command"],
        handler=run_shell,
    )


# ── 工具集创建 ──────────────────────────────────────────────────────────


def create_default_tools(
    workspace: Path,
    *,
    include_shell: bool = False,
) -> list[Tool]:
    """创建默认工具集。

    Args:
        workspace: 工作目录
        include_shell: 是否包含 run_shell（Patch/FailureAnalysis 用）
    """
    tools = [
        _make_read_file(workspace),
        _make_search_code(workspace),
        _make_list_dir(workspace),
    ]
    if include_shell:
        tools.append(_make_run_shell(workspace))
    return tools


# ── submit_final_result 工具 ─────────────────────────────────────────────


def _make_submit_result_tool(output_schema: dict[str, Any]) -> Tool:
    """根据 output_schema 创建 submit_final_result 工具。

    Agent 调用此工具提交最终结果，参数即为 output_schema 的 properties。
    这样 LLM 通过工具调用机制（而非文本输出）来提交结构化结果，
    避免思考模型在"探索工具"和"输出 JSON"之间犹豫不决。
    """

    def _handler(**kwargs: Any) -> str:
        return json.dumps(kwargs, ensure_ascii=False)

    return Tool(
        name="submit_final_result",
        description=(
            "提交最终分析结果。当你收集到足够信息、完成全部分析后，"
            "调用此工具提交完整的结构化 JSON 结果。调用后分析立即结束。"
        ),
        parameters=output_schema.get("properties", {}),
        required=output_schema.get("required", []),
        handler=_handler,
    )


# ── 辅助函数 ────────────────────────────────────────────────────────────


def _safe_print(msg: str) -> None:
    """安全打印 — 处理 Windows GBK 编码无法输出 emoji 的问题。"""
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        # 移除无法编码的字符后重试
        print(msg.encode("gbk", errors="replace").decode("gbk", errors="replace"), flush=True)


def _resolve_path(workspace: Path, path: str) -> Path:
    """解析路径（相对路径基于 workspace）。"""
    p = Path(path)
    if p.is_absolute():
        return p
    return (workspace / p).resolve()


def _fmt_size(size: int) -> str:
    """格式化文件大小。"""
    if size < 1024:
        return f"{size}B"
    if size < 1024 * 1024:
        return f"{size/1024:.1f}KB"
    return f"{size/(1024*1024):.1f}MB"


def _truncate(text: str, max_len: int) -> str:
    """截断过长的文本。"""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... (截断，原长度 {len(text)} 字符)"


def _brief_args(args: dict[str, Any]) -> str:
    """参数简要展示。"""
    parts = []
    for k, v in args.items():
        s = str(v)
        if len(s) > 50:
            s = s[:47] + "..."
        parts.append(f"{k}={s}")
    return ", ".join(parts)


def _brief_result(result: str) -> str:
    """结果简要展示。"""
    first_line = result.split("\n")[0][:80]
    return f"{len(result)} chars: {first_line}"
