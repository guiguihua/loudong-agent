"""BaseAgent — ReAct 风格的 Agent 基类。

每个 Agent 继承 BaseAgent，获得：
  - 多轮推理循环 (Observe → Think → Act → Observe → ...)
  - 工具调用能力（读文件、搜索代码、运行命令）
  - 结构化输出解析

真正的 Agent = 大模型 + 工具 + 循环决策，而不是"拼 prompt → 一次 API 调用 → 解析 JSON"。
"""

from __future__ import annotations

import json
import traceback
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

    # 子类可覆盖，定义最终输出的 JSON Schema
    output_schema: dict[str, Any] | None = None

    def run(self, task: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行 Agent 任务。

        Args:
            task: 用户任务描述
            context: 额外上下文（可选）

        Returns:
            结构化输出字典（LLM 最后一轮的内容解析为 JSON）
        """
        if not self.llm:
            raise RuntimeError(f"Agent '{self.name}' 需要 LLM 后端，但 llm 为 None")

        messages = self._build_initial_messages(task, context or {})

        for turn in range(1, self.max_turns + 1):
            response = self._call_llm(messages)

            # 有工具调用 → 执行并继续循环
            if response.tool_calls:
                # 1. 先添加 assistant 消息（含 tool_calls）
                assistant_msg = {
                    "role": "assistant",
                    "content": response.content,
                    "tool_calls": response.tool_calls,
                }
                messages.append(assistant_msg)

                # 2. 执行每个工具，添加 tool 结果消息
                for tc in response.tool_calls:
                    tool_msg = self._handle_tool_call(tc)
                    messages.append(tool_msg)
                continue

            # 无工具调用 → Agent 完成，解析输出
            return self._parse_final_output(response.content or "")

        # 超过 max_turns
        raise RuntimeError(
            f"Agent '{self.name}' 超过最大推理轮数 {self.max_turns}，"
            f"仍未给出最终答案"
        )

    # ── 内部方法 ────────────────────────────────────────────────────────

    def _build_initial_messages(
        self, task: str, context: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """构建初始 messages（system + user）。"""
        system = self.system_prompt
        if self.output_schema:
            schema_str = json.dumps(self.output_schema, ensure_ascii=False, indent=2)
            system += (
                f"\n\n最终输出必须是 JSON 格式，符合以下 Schema：\n```json\n{schema_str}\n```\n"
                "当你收集到足够信息后，直接输出 JSON，不要再调用工具。"
            )

        # 添加工件目录信息
        workspace_info = f"\n\n当前工作目录: {self.workspace}"

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system + workspace_info},
            {"role": "user", "content": task},
        ]
        return messages

    def _call_llm(self, messages: list[dict[str, Any]]) -> ChatResponse:
        """调用 LLM（支持工具）。"""
        tool_schemas = [t.to_openai_schema() for t in self.tools] if self.tools else None
        return self.llm.chat(messages, tools=tool_schemas)  # type: ignore[union-attr]

    def _handle_tool_call(self, tool_call: dict[str, Any]) -> dict[str, Any]:
        """执行工具调用，返回 assistant 消息格式。"""
        func_name = tool_call.get("function", {}).get("name", "unknown")
        func_args_str = tool_call.get("function", {}).get("arguments", "{}")

        # 解析参数
        try:
            func_args = json.loads(func_args_str) if isinstance(func_args_str, str) else func_args_str
        except json.JSONDecodeError:
            func_args = {}

        # 查找并执行工具
        tool = next((t for t in self.tools if t.name == func_name), None)
        if tool is None:
            result = f"错误: 未知工具 '{func_name}'"
        else:
            try:
                result = tool.handler(**func_args)
                print(f"  [{self.name}] 🔧 {func_name}({_brief_args(func_args)}) → {_brief_result(result)}")
            except Exception as exc:
                result = f"工具执行失败: {exc}"
                print(f"  [{self.name}] ❌ {func_name}({_brief_args(func_args)}) → {exc}")

        return {
            "role": "tool",
            "tool_call_id": tool_call.get("id", ""),
            "content": result,
        }

    def _parse_final_output(self, content: str) -> dict[str, Any]:
        """解析 Agent 的最终文本输出为结构化 dict。"""
        try:
            # 尝试解析 JSON（可能在 ```json 代码块中）
            if "```json" in content:
                start = content.index("```json") + 7
                end = content.index("```", start)
                return json.loads(content[start:end])
            if "{" in content:
                start = content.index("{")
                end = content.rindex("}") + 1
                return json.loads(content[start:end])
        except (json.JSONDecodeError, ValueError):
            pass

        # 无法解析为 JSON，返回原始文本
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
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # grep 不可用，用 Python 实现
            return _python_search(search_dir, pattern)

        output = result.stdout.strip()
        if not output:
            return f"未找到匹配 '{pattern}' 的结果"
        lines = output.splitlines()[:50]
        header = f"找到 {len(result.stdout.splitlines())} 处匹配 (显示前50):\n"
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


# ── 辅助函数 ────────────────────────────────────────────────────────────


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
