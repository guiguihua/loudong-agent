"""WebSocket 聊天 — 实时对话漏洞分析。"""

from __future__ import annotations

import json
import os
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect


class ChatManager:
    """管理 WebSocket 聊天连接和消息路由。"""

    def __init__(self):
        self._connections: dict[str, WebSocket] = {}
        self._counter = 0

    async def handle(self, ws: WebSocket) -> None:
        await ws.accept()
        self._counter += 1
        conn_id = f"chat-{self._counter}"
        self._connections[conn_id] = ws

        try:
            # 欢迎消息
            await ws.send_json({
                "role": "agent",
                "content": (
                    "👋 你好！我是**漏洞修复智能体**。\n\n"
                    "我可以帮你：\n"
                    "- 🔍 **分析漏洞**：描述漏洞信息，我推理影响面和根因\n"
                    "- 🔧 **生成补丁**：提供漏洞 + 源码，我生成精准修复代码\n"
                    "- 📋 **查看进度**：查询正在运行的修复任务\n\n"
                    "直接发送消息开始吧！也可以粘贴漏洞 JSON 或代码片段。"
                ),
            })

            while True:
                data = await ws.receive_text()
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    msg = {"content": data}

                user_content = msg.get("content", data) if isinstance(msg, dict) else data

                # 回显用户消息
                await ws.send_json({"role": "user", "content": user_content})

                # 生成回复
                reply = await self._generate_reply(user_content)
                await ws.send_json({"role": "agent", "content": reply})

        except WebSocketDisconnect:
            pass
        finally:
            self._connections.pop(conn_id, None)

    async def _generate_reply(self, content: str) -> str:
        """根据用户输入生成回复。"""
        content_lower = content.lower().strip()

        # 意图识别
        if any(kw in content_lower for kw in ("分析", "analyze", "影响面", "根因")):
            return await self._handle_analysis(content)

        if any(kw in content_lower for kw in ("修复", "补丁", "fix", "patch", "生成补丁")):
            return await self._handle_fix(content)

        if any(kw in content_lower for kw in ("进度", "状态", "任务", "progress", "task")):
            return await self._handle_status(content)

        if any(kw in content_lower for kw in ("帮助", "help", "能做什么", "功能")):
            return (
                "### 🔧 我能做什么\n\n"
                "1. **分析漏洞**：发送漏洞信息（类型、文件、证据），我推理影响面和根因\n"
                "2. **生成补丁**：发送漏洞 JSON + 源码，我生成精准修复\n"
                "3. **查看进度**：查询任务状态\n\n"
                "示例：\n"
                '```json\n{"finding_id":"F-001","vulnerability_type":"SQL Injection",'
                '"severity":"high","affected_file":"src/api/search.py",'
                '"evidence":"user input concatenated into SQL"}\n```\n\n'
                "也可以直接粘贴代码和描述，我会自动分析。"
            )

        # 通用对话 → 调用 LLM
        return await self._llm_chat(content)

    async def _handle_analysis(self, content: str) -> str:
        """处理分析请求。"""
        # 尝试从消息中提取漏洞信息
        vuln_data = self._extract_vuln_data(content)
        if vuln_data is None:
            return (
                "要分析漏洞，请提供以下信息：\n"
                "- **漏洞类型**（如 SQL Injection, XSS）\n"
                "- **受影响文件/函数**\n"
                "- **漏洞证据/描述**\n\n"
                "也可以直接粘贴漏洞 JSON。"
            )

        try:
            from ..runner import run_dict_simple
            result = run_dict_simple(vuln_data)
            finding = result.get("finding", {})
            impact = result.get("impact", {})
            root_cause = result.get("root_cause", {})

            return (
                f"### 📊 分析结果\n\n"
                f"**漏洞 ID**：{finding.get('finding_id', 'N/A')}\n"
                f"**类型**：{finding.get('vulnerability_type', 'N/A')}\n"
                f"**严重性**：{finding.get('severity', 'N/A')}\n\n"
                f"**影响面状态**：{impact.get('status', 'N/A')}\n"
                f"**受影响服务**：{', '.join(impact.get('affected_services', ['N/A']))}\n\n"
                f"**根因分类**：{root_cause.get('root_cause_category', 'N/A')}\n"
                f"**根因摘要**：{root_cause.get('root_cause', {}).get('summary', 'N/A')}\n\n"
                f"输入 `/new` 启动完整修复流水线。"
            )
        except Exception as e:
            return f"❌ 分析失败：{e}"

    async def _handle_fix(self, content: str) -> str:
        """处理修复请求。"""
        vuln_data = self._extract_vuln_data(content)
        if vuln_data is None:
            return "要生成补丁，请提供漏洞 JSON 和源码。建议通过 Web 界面 `/new` 提交完整的修复任务。"

        return (
            "🔧 完整修复流水线需要源码上下文。\n\n"
            "**推荐操作**：\n"
            "1. 打开 `/new` 页面提交完整的漏洞报告 + 源码\n"
            "2. 或通过 API 调用：`POST /v1/findings/fix`\n\n"
            "我已提取到以下漏洞信息：\n"
            f'```json\n{json.dumps(vuln_data, ensure_ascii=False, indent=2)}\n```\n'
        )

    async def _handle_status(self, content: str) -> str:
        """查询任务进度。"""
        try:
            from .tasks import task_manager
            recent = task_manager.list_recent(5)
            if not recent:
                return "📋 暂无运行中的任务。"
            lines = ["### 📋 最近任务\n"]
            for t in recent:
                icon = (
                    "✅" if t.status == "succeeded"
                    else "⚠️" if t.status == "blocked"
                    else "❌" if t.status == "failed"
                    else "⏳"
                )
                lines.append(f"- {icon} `{t.task_id}` — {t.vuln_type or '未知'} — *{t.progress}*")
            return "\n".join(lines)
        except Exception:
            return "📋 无法查询任务状态。"

    async def _llm_chat(self, content: str) -> str:
        """通用 LLM 对话。"""
        try:
            from ..llm import create_llm_backend
            llm = create_llm_backend()
            if llm is None:
                return (
                    "LLM 未配置。设置 `DEEPSEEK_API_KEY` 环境变量以启用 AI 对话。\n\n"
                    "当前可使用确定性模式进行分析和修复。"
                )
            reply = llm.reason(
                content,
                system_prompt=(
                    "你是漏洞修复智能助手。简洁专业地回答用户关于安全漏洞的问题。"
                    "用中文回复，使用 Markdown 格式。不超过 300 字。"
                ),
                temperature=0.7,
            )
            return reply if isinstance(reply, str) else reply.get("content", str(reply))
        except Exception:
            return (
                "我目前以确定性模式运行。\n\n"
                "你可以：\n"
                "- 通过 Web 界面 `/new` 提交漏洞修复任务\n"
                "- 粘贴漏洞 JSON 进行分析\n"
                "- 输入 `help` 查看完整功能"
            )

    @staticmethod
    def _extract_vuln_data(content: str) -> dict[str, Any] | None:
        """从消息中提取漏洞信息。"""
        # 尝试解析 JSON
        try:
            # 查找 JSON 块
            if "```json" in content:
                start = content.index("```json") + 7
                end = content.index("```", start)
                return json.loads(content[start:end])
            if "```" in content:
                start = content.index("```") + 3
                end = content.index("```", start)
                text = content[start:end]
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    pass
            # 整个消息就是 JSON
            if content.strip().startswith("{"):
                return json.loads(content.strip())
        except (json.JSONDecodeError, ValueError):
            pass

        # 尝试从自然语言提取
        import re
        vuln_type = None
        for vt in ["sql injection", "xss", "cross-site scripting", "path traversal",
                     "command injection", "ssrf", "deserialization", "敏感信息泄露",
                     "认证绕过", "弱加密"]:
            if vt in content.lower():
                vuln_type = vt.title()
                break

        if vuln_type:
            file_match = re.search(r'(?:文件|file)[:\s]*([^\s,，]+\.\w{1,6})', content, re.IGNORECASE)
            func_match = re.search(r'(?:函数|function)[:\s]*(\w+)', content, re.IGNORECASE)
            return {
                "finding_id": f"CHAT-{hash(content) % 10000:04d}",
                "vulnerability_type": vuln_type,
                "severity": "medium",
                "affected_file": file_match.group(1) if file_match else "unknown",
                "affected_function": func_match.group(1) if func_match else "unknown",
                "evidence": content[:500],
                "scanner": "Chat",
            }

        return None


# 全局单例
chat_manager = ChatManager()
