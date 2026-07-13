"""REST API + Web UI — 漏洞修复智能体平台。

端点:
  GET  /                         Web UI 仪表盘
  GET  /new                      新建修复任务页面
  GET  /finding/{id}             漏洞详情/结果
  GET  /chat                     聊天页面
  GET  /repo                     仓库浏览器
  GET  /history                  历史记录
  GET  /health                   健康检查
  POST /v1/findings/analyze      分析（标准化 + 影响面 + 根因）
  POST /v1/findings/fix          同步修复流水线
  POST /api/tasks                异步修复任务
  GET  /api/tasks/{id}           任务状态
  GET  /api/tasks/{id}/result    任务结果
  POST /api/git/clone            克隆仓库
  GET  /api/git/repos            仓库列表
  GET  /api/git/{id}/branches    分支列表
  GET  /api/git/{id}/tree        文件树
  GET  /api/git/{id}/file        文件内容
  GET  /api/git/{id}/commits     提交历史
  WS   /ws/chat                  实时聊天
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader

from .config import config_status, load_env_file
from .normalization import VulnerabilityNormalizer

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"

load_env_file()


# ── Jinja2 模板引擎 ──

def _has_llm() -> bool:
    return bool(os.environ.get("DEEPSEEK_API_KEY"))


_jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    auto_reload=True,
)
_jinja_env.globals["has_llm"] = _has_llm()


def render_template(name: str, **context: Any) -> HTMLResponse:
    """渲染 Jinja2 模板并返回 HTMLResponse。"""
    template = _jinja_env.get_template(name)
    # 确保 request 在上下文中
    return HTMLResponse(content=template.render(**context))


def create_app() -> FastAPI:
    """创建 FastAPI 应用（工厂函数，供 serve 和测试使用）。"""

    app = FastAPI(title="漏洞修复智能体平台", version="0.3.0")

    # 暴露模板渲染函数到 app.state
    app.state.render = render_template

    # 静态文件
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ── 页面路由（来自 web 模块）──
    from .web.routes import router as web_router
    app.include_router(web_router, tags=["pages"])

    # ── 健康检查 ──
    @app.get("/health")
    def health() -> dict[str, Any]:
        status = config_status()
        pr = status["pull_request"]
        return {
            "status": "ok",
            "llm": "enabled" if status["llm"]["enabled"] else "disabled",
            "model": status["llm"]["model"],
            "pr_providers": [
                name for name, provider in pr.items()
                if provider.get("enabled")
            ],
        }

    @app.get("/api/config/status")
    def get_config_status() -> dict[str, Any]:
        return config_status()

    # ── 已有 API ──
    from .impact import ImpactAnalysisAgent
    from .tools import StaticAssetInventoryTool, StaticCodeContextTool, StaticRuntimeEvidenceTool
    from .root_cause import RootCauseAnalysisAgent
    from .tools import StaticRootCauseEvidenceTool
    from .service import IntakeImpactService

    analyze_service = IntakeImpactService(
        normalizer=VulnerabilityNormalizer(),
        impact_agent=ImpactAnalysisAgent(
            code_tool=StaticCodeContextTool({}),
            asset_tool=StaticAssetInventoryTool({}),
            runtime_tool=StaticRuntimeEvidenceTool({}),
        ),
        root_cause_agent=RootCauseAnalysisAgent(StaticRootCauseEvidenceTool()),
    )

    @app.post("/v1/findings/analyze")
    def analyze_finding(payload: dict[str, Any]) -> dict[str, Any]:
        """分析漏洞 — 标准化 + 影响面评估 + 根因分析。"""
        return analyze_service.process(payload)

    @app.post("/v1/findings/fix")
    def fix_finding(payload: dict[str, Any]) -> dict[str, Any]:
        """完整修复流水线 — 从漏洞报告到补丁和报告。"""
        return _run_fix_pipeline(payload)

    # ── 异步任务 API ──
    from .web.tasks import task_manager

    @app.post("/api/tasks")
    async def create_task(request: Request) -> dict[str, Any]:
        """创建异步修复任务。"""
        body: dict[str, Any] = {}
        content_type = request.headers.get("content-type", "")

        if "application/json" in content_type:
            body = await request.json()
        elif "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
            form = await request.form()
            body = dict(form)

            # 处理 JSON 模式
            if body.get("json_mode") == "1":
                try:
                    json_data = json.loads(body.get("json_data", "{}"))
                    body = json_data
                except json.JSONDecodeError:
                    return JSONResponse(
                        {"error": "JSON 解析失败，请检查格式"}, status_code=400
                    )

            # 提取源码文件
            source_files: dict[str, str] = {}
            for key, val in body.items():
                if key.startswith("source_file_"):
                    path = key[len("source_file_"):].replace("_", "/")
                    source_files[path] = val
            if source_files:
                body["source_files"] = source_files

        if not body:
            return JSONResponse({"error": "空请求体"}, status_code=400)

        # 创建任务
        repo_id = str(body.get("repo_id") or "")
        if repo_id:
            try:
                from .web.git_handler import git_handler

                repo_info = git_handler.get_repo_info(repo_id)
                if repo_info is None:
                    return JSONResponse({"error": f"repository not found: {repo_id}"}, status_code=404)
                branch = str(body.get("branch") or body.get("git_branch") or repo_info.get("branch") or "main")
                body["repo_id"] = repo_id
                body["branch"] = branch
                body["repository"] = repo_info.get("name") or repo_id
                body["repository_url"] = repo_info.get("url", "")
                body["source_dir"] = str(git_handler.get_repo_path(repo_id))
                if not body.get("source_files"):
                    body["source_files"] = git_handler.load_all_source_files(repo_id, branch)
                body["repository_context"] = {
                    "repo_id": repo_id,
                    "name": repo_info.get("name"),
                    "provider": repo_info.get("provider"),
                    "branch": branch,
                    "url": repo_info.get("url"),
                    "local_path": repo_info.get("local_path"),
                    "index_status": repo_info.get("index_status", {}),
                    "source_file_count": len(body.get("source_files") or {}),
                }
            except Exception as exc:
                return JSONResponse({"error": f"failed to load repository context: {exc}"}, status_code=400)

        body = _prepare_raw_report(body)

        info = task_manager.create(
            vuln_type=body.get("vulnerability_type", ""),
            severity=body.get("severity", ""),
        )
        task_manager.update(info.task_id, status="running", progress="标准化漏洞报告...", stage=1)

        # 后台执行流水线（线程池，不阻塞事件循环）
        import asyncio
        asyncio.create_task(asyncio.to_thread(_run_pipeline_sync, info.task_id, body))

        return {"task_id": info.task_id, "status": "running"}

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str) -> dict[str, Any]:
        """查询任务状态/进度。"""
        info = task_manager.get(task_id)
        if info is None:
            return JSONResponse({"error": "任务不存在"}, status_code=404)
        return info.to_dict()

    @app.get("/api/tasks/{task_id}/result")
    def get_task_result(task_id: str) -> dict[str, Any]:
        """获取任务完整结果。"""
        info = task_manager.get(task_id)
        if info is None:
            return JSONResponse({"error": "任务不存在"}, status_code=404)
        if info.status not in ("succeeded", "failed"):
            return {"task_id": task_id, "ready": False, "status": info.status}
        return {"task_id": task_id, "ready": True, "result": info.result}

    @app.get("/api/history")
    def get_history() -> list[dict[str, Any]]:
        """历史记录列表。"""
        return [t.to_dict() for t in task_manager.list_all()]

    # ── Git API ──
    try:
        from .web.git_handler import git_handler

        @app.post("/api/git/clone")
        async def git_clone(request: Request) -> dict[str, Any]:
            body = await request.json()
            url = body.get("url", "")
            if not url:
                return JSONResponse({"error": "缺少仓库 URL"}, status_code=400)
            try:
                repo_id = git_handler.clone(
                    url,
                    name=body.get("name", ""),
                    provider=body.get("provider", "git"),
                    default_branch=body.get("default_branch", ""),
                )
                return {"repo_id": repo_id, "url": url}
            except Exception as e:
                return JSONResponse({"error": str(e)}, status_code=400)

        @app.post("/api/git/bind-local")
        async def git_bind_local(request: Request) -> dict[str, Any]:
            body = await request.json()
            path = body.get("path", "")
            if not path:
                return JSONResponse({"error": "missing local repository path"}, status_code=400)
            try:
                repo_id = git_handler.bind_local(
                    path,
                    name=body.get("name", ""),
                    provider=body.get("provider", "local"),
                )
                return {"repo_id": repo_id, "path": path}
            except Exception as e:
                return JSONResponse({"error": str(e)}, status_code=400)

        @app.get("/api/git/repos")
        def git_repos() -> list[dict[str, Any]]:
            return git_handler.list_repos()

        @app.get("/api/git/{repo_id}/branches")
        def git_branches(repo_id: str) -> list[str]:
            return git_handler.list_branches(repo_id)

        @app.get("/api/git/{repo_id}/tree")
        def git_tree(repo_id: str, branch: str = "main") -> list[dict[str, Any]]:
            return git_handler.get_file_tree(repo_id, branch)

        @app.get("/api/git/{repo_id}/file")
        def git_file(repo_id: str, path: str = "", branch: str = "main") -> dict[str, Any]:
            content = git_handler.get_file_content(repo_id, path, branch)
            return {"path": path, "content": content}

        @app.get("/api/git/{repo_id}/commits")
        def git_commits(repo_id: str, branch: str = "main", n: int = 30) -> list[dict[str, Any]]:
            return git_handler.list_commits(repo_id, branch, n)

    except ImportError:
        pass  # gitpython 未安装时跳过

    # ── 示例库 API ──
    @app.get("/api/examples")
    def list_examples() -> list[dict[str, Any]]:
        """列出 validation-coverage 中所有可用的漏洞实例。"""
        import yaml
        vc_dir = ROOT / "validation-coverage"
        if not vc_dir.exists():
            return []
        examples: list[dict[str, Any]] = []
        for cat_dir in sorted(vc_dir.iterdir()):
            if not cat_dir.is_dir():
                continue
            finding_file = None
            for f in sorted(cat_dir.glob("*.yaml")):
                finding_file = f
                break
            if finding_file is None:
                for f in sorted(cat_dir.glob("*.json")):
                    finding_file = f
                    break
            if finding_file is None:
                continue
            try:
                if finding_file.suffix in (".yaml", ".yml"):
                    data = yaml.safe_load(finding_file.read_text(encoding="utf-8"))
                else:
                    data = json.loads(finding_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            # 查找源码目录
            src_dir = None
            for d in sorted(cat_dir.iterdir()):
                if d.is_dir() and d.name != "reports":
                    src_dir = str(d.relative_to(vc_dir))
                    break
            affected = data.get("affected", {}) if isinstance(data.get("affected"), dict) else {}
            title = str(data.get("title", ""))
            if not title:
                title = str(affected.get("file_or_component", ""))
            examples.append({
                "id": f"{cat_dir.name}/{finding_file.stem}",
                "category": cat_dir.name,
                "cve_id": str(data.get("cve") or data.get("id", "")),
                "title": title[:120],
                "vulnerability_type": str(data.get("vulnerability_type", "")),
                "severity": str(data.get("severity", "")),
                "source_dir": src_dir,
            })
        return examples

    @app.post("/api/examples/load")
    async def load_example(request: Request) -> dict[str, Any]:
        """加载指定示例的漏洞数据 + 源码。"""
        import yaml
        body = await request.json()
        example_id = body.get("id", "")
        if not example_id:
            return JSONResponse({"error": "缺少 example id"}, status_code=400)

        parts = example_id.split("/")
        if len(parts) != 2:
            return JSONResponse({"error": "无效的 example id 格式"}, status_code=400)
        cat, name = parts
        vc_dir = ROOT / "validation-coverage" / cat

        if not vc_dir.exists():
            return JSONResponse({"error": f"分类不存在: {cat}"}, status_code=404)

        # 读取 finding
        finding_file = None
        for ext in (".yaml", ".yml", ".json"):
            candidate = vc_dir / f"{name}{ext}"
            if candidate.exists():
                finding_file = candidate
                break
        if finding_file is None:
            return JSONResponse({"error": f"示例不存在: {example_id}"}, status_code=404)

        try:
            if finding_file.suffix in (".yaml", ".yml"):
                finding_data = yaml.safe_load(finding_file.read_text(encoding="utf-8"))
            else:
                finding_data = json.loads(finding_file.read_text(encoding="utf-8"))
        except Exception as e:
            return JSONResponse({"error": f"解析失败: {e}"}, status_code=400)

        # 映射到标准字段
        affected = finding_data.get("affected", {}) if isinstance(finding_data.get("affected"), dict) else {}
        finding_dict: dict[str, Any] = {
            "finding_id": str(finding_data.get("id") or finding_data.get("cve") or name),
            "vulnerability_type": str(finding_data.get("vulnerability_type", "")),
            "severity": str(finding_data.get("severity", "")),
            "confidence": str(finding_data.get("confidence", "medium")),
            "scanner": "CVE",
            "cve": str(finding_data.get("cve") or ""),
            "cwe": str(finding_data.get("cwe") or ""),
            "affected_file": str(affected.get("file_or_component", "")),
            "affected_function": str(affected.get("function_or_version", "")),
            "evidence": str(finding_data.get("evidence", "")).replace("\n", " "),
            "recommendation": str(finding_data.get("scanner_recommendation", "")),
            "repository": str(affected.get("repository", "")),
            "revision": str(affected.get("branch_or_revision", "")),
        }

        # 加载源码文件
        source_files: dict[str, str] = {}
        src_dir_name = None
        for d in sorted(vc_dir.iterdir()):
            if d.is_dir() and d.name != "reports":
                src_dir_name = d.name
                break

        if src_dir_name:
            src_path = vc_dir / src_dir_name
            for f in src_path.rglob("*"):
                if not f.is_file():
                    continue
                if any(excl in f.parts for excl in (".git", ".svn", "__pycache__", "node_modules", ".venv", ".tox")):
                    continue
                if f.name.endswith((".py", ".java", ".go", ".js", ".ts", ".jsx", ".tsx",
                                     ".c", ".cpp", ".h", ".hpp", ".rs", ".rb", ".php",
                                     ".yaml", ".yml", ".json", ".xml", ".html", ".css",
                                     ".vue", ".svelte", ".sql", ".md", ".txt", ".cfg",
                                     ".ini", ".toml", ".conf")):
                    try:
                        content = f.read_text(encoding="utf-8", errors="replace")
                        rel = str(f.relative_to(src_path))
                        source_files[rel] = content
                    except Exception:
                        pass

        return {
            "finding": finding_dict,
            "source_files": source_files,
            "file_count": len(source_files),
        }

    # ── WebSocket 聊天 ──
    try:
        from .web.chat import chat_manager

        @app.websocket("/ws/chat")
        async def ws_chat(ws: WebSocket):
            await chat_manager.handle(ws)

    except ImportError:
        @app.websocket("/ws/chat")
        async def ws_chat(ws: WebSocket):
            await ws.accept()
            await ws.send_json({"role": "agent", "content": "聊天模块未就绪（缺少依赖）。"})
            await ws.close()

    return app


# ── 内部辅助 ──────────────────────────────────────────────────────────


def _run_fix_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    """同步执行修复流水线（原有 /v1/findings/fix 逻辑）。"""
    from .runner import run_dict

    payload = _prepare_raw_report(payload)
    source_files_raw = payload.pop("source_files", {})
    source_files: dict[str, str] = {}
    if isinstance(source_files_raw, dict):
        source_files = source_files_raw
    elif isinstance(source_files_raw, list):
        for item in source_files_raw:
            if isinstance(item, dict):
                source_files[item.get("path", item.get("file", ""))] = item.get("content", "")
            else:
                source_files[str(item)] = ""

    overrides = {
        k: v for k, v in payload.items()
        if k in (
            "language", "framework", "database", "package_manager",
            "repository", "branch", "services", "entry_points",
            "call_paths", "test_framework", "max_attempts",
        )
    }

    finding_data = {k: v for k, v in payload.items() if k not in overrides}

    return run_dict(
        finding_data,
        source_files=source_files,
        **overrides,
    )


def _prepare_raw_report(body: dict[str, Any]) -> dict[str, Any]:
    """Extract minimal deterministic fields from a pasted/uploaded report.

    This is intentionally conservative. It makes raw reports usable without
    pretending to replace the specialist report parser Skill/sub-agent.
    """
    raw_report = str(body.get("raw_report") or "").strip()
    if not raw_report:
        return body

    import re

    body = dict(body)
    try:
        import yaml

        parsed = yaml.safe_load(raw_report)
    except Exception:
        parsed = None

    if isinstance(parsed, dict):
        affected = parsed.get("affected") if isinstance(parsed.get("affected"), dict) else {}
        field_map = {
            "finding_id": parsed.get("id") or parsed.get("finding_id"),
            "vulnerability_type": parsed.get("vulnerability_type"),
            "severity": parsed.get("severity"),
            "confidence": parsed.get("confidence"),
            "scanner": parsed.get("source") or parsed.get("scanner"),
            "cve": parsed.get("cve"),
            "cwe": parsed.get("cwe"),
            "evidence": parsed.get("evidence"),
            "recommendation": parsed.get("scanner_recommendation") or parsed.get("recommendation"),
            "affected_file": affected.get("file_or_component"),
            "affected_function": affected.get("function_or_version"),
            "revision": affected.get("branch_or_revision"),
            "reported_repository": affected.get("repository"),
        }
        for key, value in field_map.items():
            if value is not None and value != "" and not body.get(key):
                body[key] = value

    if not body.get("evidence"):
        body["evidence"] = raw_report

    cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", raw_report, flags=re.IGNORECASE)
    if cve_match and not body.get("cve"):
        body["cve"] = cve_match.group(0).upper()

    cwe_match = re.search(r"\bCWE-\d+\b", raw_report, flags=re.IGNORECASE)
    if cwe_match and not body.get("cwe"):
        body["cwe"] = cwe_match.group(0).upper()

    if not body.get("vulnerability_type"):
        lowered = raw_report.lower()
        type_markers = [
            ("sql injection", "SQL Injection"),
            ("sqli", "SQL Injection"),
            ("cross-site scripting", "Cross-Site Scripting"),
            ("xss", "Cross-Site Scripting"),
            ("ssrf", "SSRF"),
            ("server-side request forgery", "SSRF"),
            ("path traversal", "Path Traversal"),
            ("directory traversal", "Path Traversal"),
            ("command injection", "Command Injection"),
            ("deserialization", "Deserialization"),
            ("authorization bypass", "Authorization Bypass"),
            ("authentication bypass", "Authentication Bypass"),
            ("race condition", "Race Condition"),
            ("weak cryptography", "Weak Cryptography"),
            ("vulnerable dependency", "Dependency"),
        ]
        for marker, vuln_type in type_markers:
            if marker in lowered:
                body["vulnerability_type"] = vuln_type
                break

    return body


def _manual_review_validation_results():
    from .models import ToolExecutionStatus, ValidationLayer, ValidationToolResult

    summary = "No executable validation tool is configured in the Web task; manual review is required."
    return [
        ValidationToolResult(layer=layer, tool_name="manual review", status=ToolExecutionStatus.SKIPPED, summary=summary)
        for layer in (
            ValidationLayer.BUILD,
            ValidationLayer.BUSINESS_REGRESSION,
            ValidationLayer.SECURITY_REGRESSION,
            ValidationLayer.SCANNER_RESCAN,
            ValidationLayer.DIFFERENTIAL_RISK,
        )
    ]


def _pipeline_mode(body: dict[str, Any]) -> str:
    """运行模式：fast=轻量（max_turns 较少），deep=完整推理（默认）。

    注意：两种模式都会运行完整的 5-Agent 流水线（Impact → RootCause →
    Remediation → Patch → Validation）。区别仅在于 Agent 的 max_turns
    （推理轮数），不会跳过任何分析阶段。
    """
    mode = str(body.get("run_mode") or body.get("mode") or "deep").strip().lower()
    if mode not in {"fast", "deep"}:
        return "deep"
    return mode


def _fallback_impact(finding, code_ctx, asset_ctx, runtime_ctx, exc: Exception | None):
    from .models import ApiEntryPoint, AssessmentStatus, Confidence, Evidence, ImpactAssessment

    reason = "LLM agent failed — static fallback"
    if exc is not None:
        reason = f"LLM agent failed: {exc}"
    services = code_ctx.services or [finding.repository or "unknown-service"]
    entry_points = code_ctx.entry_points or [
        ApiEntryPoint(
            route=finding.locations[0].function or "unknown-entry"
            if finding.locations else "unknown-entry",
            method="ANY",
            authentication="unknown",
            internet_exposed=None,
        )
    ]
    return ImpactAssessment(
        finding_id=finding.finding_id,
        status=AssessmentStatus.POSSIBLE,
        affected_services=services,
        entry_points=entry_points,
        call_paths=code_ctx.call_paths,
        affected_assets=asset_ctx.deployed_assets,
        affected_artifacts=asset_ctx.affected_artifacts,
        data_classification=code_ctx.data_classification,
        upstream_dependencies=code_ctx.upstream_dependencies,
        downstream_dependencies=code_ctx.downstream_dependencies,
        regression_targets=code_ctx.related_tests,
        suggested_tests=[f"security regression for {finding.vulnerability_type}"],
        evidence=[
            Evidence(
                "fallback-impact",
                "static_context",
                "LLM impact analysis was unavailable; static context fallback used",
                reason,
                Confidence.LOW,
            )
        ],
        unknowns=[reason, "impact needs human review because LLM/code-semantic analysis did not complete"],
        confidence_score=0.35,
        needs_human_review=True,
    )


def _fallback_root_cause(finding, root_cause_ctx, exc: Exception | None):
    from .models import (
        AffectedCode,
        AssessmentStatus,
        CodePoint,
        Confidence,
        Evidence,
        FailedControl,
        PropagationStep,
        RootCause,
        RootCauseAssessment,
        RootCauseCategory,
    )
    from .tools import DependencyRootCauseContext, RootCauseCodeContext

    reason = "LLM agent failed — static fallback"
    if exc is not None:
        reason = f"LLM agent failed: {exc}"

    category = RootCauseCategory.UNKNOWN
    source = None
    sink = None
    propagation: list[PropagationStep] = []
    failed_controls: list[FailedControl] = []
    trigger_conditions = list(finding.evidence)
    affected_code: list[AffectedCode] = []
    missing_control = "needs_human_review"

    if isinstance(root_cause_ctx, DependencyRootCauseContext):
        category = RootCauseCategory.VULNERABLE_DEPENDENCY
        missing_control = "dependency_upgrade_or_mitigation"
        trigger_conditions = root_cause_ctx.dependency_path or trigger_conditions
    elif isinstance(root_cause_ctx, RootCauseCodeContext):
        source = root_cause_ctx.source
        sink = root_cause_ctx.sink
        propagation = root_cause_ctx.propagation
        failed_controls = root_cause_ctx.failed_controls
        trigger_conditions = root_cause_ctx.trigger_conditions or trigger_conditions
        if failed_controls:
            missing_control = failed_controls[0].control
        if source and source.file:
            affected_code.append(AffectedCode(source.file, source.symbol, [source.line] if source.line else [], "source"))
        if sink and sink.file:
            affected_code.append(AffectedCode(sink.file, sink.symbol, [sink.line] if sink.line else [], "sink"))

    if not affected_code and finding.locations:
        affected_code = [
            AffectedCode(loc.file, loc.function, [loc.line] if loc.line else [], "reported_location")
            for loc in finding.locations
        ]

    summary = (
        f"Static fallback could not fully confirm root cause for {finding.vulnerability_type}; "
        "manual review is required."
    )
    return RootCauseAssessment(
        finding_id=finding.finding_id,
        status=AssessmentStatus.POSSIBLE,
        root_cause_category=category,
        root_cause=RootCause(
            summary=summary,
            source=source or (CodePoint(finding.locations[0].function or "reported location", finding.locations[0].file, finding.locations[0].line) if finding.locations else None),
            propagation=propagation,
            sink=sink,
            missing_control=missing_control,
            failed_existing_controls=failed_controls,
            trigger_conditions=trigger_conditions,
        ),
        contributing_factors=[reason],
        causal_chain=[summary],
        affected_code=affected_code,
        evidence=[
            Evidence(
                "fallback-root-cause",
                "static_context",
                "LLM root cause analysis was unavailable; static context fallback used",
                reason,
                Confidence.LOW,
            )
        ],
        alternative_hypotheses=[],
        confidence_score=0.3,
        unknowns=[reason, "root cause needs human review because semantic analysis did not complete"],
        needs_human_review=True,
        recommended_fix_constraints=[
            "do not apply production changes until a human confirms the root cause",
            "add a regression test that reproduces the reported vulnerability",
        ],
        security_invariant=None,
        guardrail=missing_control,
        broken_mechanism=[],
        exploitability_note="Static fallback did not verify exploitability.",
    )


def _fallback_remediation_plan(finding, impact, root_cause, engineering, exc: Exception | None):
    from .models import (
        CompatibilityAssessment,
        PatchBoundaries,
        PlannedChange,
        RejectedAlternative,
        RemediationPlan,
        RemediationPlanStatus,
        RemediationStrategy,
        RemediationStrategyType,
        RollbackPlan,
        Severity,
        TestPlanItem,
    )

    reason = "LLM disabled"
    if exc is not None:
        reason = f"LLM unavailable: {exc}"
    target_files = [item.file for item in root_cause.affected_code] or [loc.file for loc in finding.locations]
    if not target_files:
        target_files = ["unknown"]
    strategy_type = (
        RemediationStrategyType.DEPENDENCY_UPGRADE
        if finding.dependency is not None
        else RemediationStrategyType.INVESTIGATION_REQUIRED
    )
    planned_changes = [
        PlannedChange(
            file=target,
            change_type="investigation",
            description="Review and patch the reported vulnerable code path after human confirmation.",
            reason="LLM remediation planning was unavailable.",
            risk_level=Severity.MEDIUM,
        )
        for target in target_files[:5]
    ]
    return RemediationPlan(
        finding_id=finding.finding_id,
        status=RemediationPlanStatus.NEEDS_HUMAN_REVIEW,
        remediation_goal=f"Review and remediate {finding.vulnerability_type}; {reason}",
        strategies=[
            RemediationStrategy(
                strategy_type=strategy_type,
                summary="Manual review required before generating a patch.",
                steps=[
                    "Confirm the affected code path and trigger condition.",
                    "Choose the minimal secure fix.",
                    "Add a regression test for the reported vulnerability.",
                    "Run build and security validation before PR.",
                ],
                preferred=True,
            )
        ],
        planned_changes=planned_changes,
        dependency_upgrade=None,
        compatibility=CompatibilityAssessment(
            summary="Fallback plan generated without LLM connectivity.",
            risks=[reason],
            required_checks=engineering.available_test_commands if engineering else [],
        ),
        risk_points=[reason, "patch generation should wait for human confirmation"],
        required_tests=[
            TestPlanItem(
                name=f"{finding.vulnerability_type} regression",
                test_type="security_regression",
                target=finding.finding_id,
                assertion="the reported exploit path no longer succeeds",
            )
        ],
        rejected_alternatives=[
            RejectedAlternative(
                "automatic patch without confirmed root cause",
                "LLM connection failed and static fallback has low confidence.",
            )
        ],
        rollback=RollbackPlan(summary="Revert generated changes if validation fails.", steps=["revert patch", "rerun validation"]),
        patch_boundaries=PatchBoundaries(
            allowed_files=target_files,
            forbidden_changes=["do not weaken authentication, authorization, validation, or cryptographic checks"],
            maximum_changed_files=5,
            maximum_diff_lines=250,
        ),
        assumptions=[],
        unknowns=[reason],
        confidence_score=0.25,
        needs_human_review=True,
    )


def _run_pipeline_sync(task_id: str, body: dict[str, Any]) -> None:
    """后台同步执行修复流水线（运行在线程池中），实时更新任务状态。"""
    from .web.tasks import task_manager

    try:
        # 标准化
        task_manager.update(task_id, progress="标准化漏洞报告...", stage=1)
        normalizer = VulnerabilityNormalizer()
        finding = normalizer.normalize(body)
        run_mode = _pipeline_mode(body)
        fast_mode = run_mode == "fast"

        # LLM 后端
        from .llm import create_llm_backend
        llm = create_llm_backend()
        if not llm:
            raise RuntimeError(
                "未设置 DEEPSEEK_API_KEY 环境变量。\n"
                "请设置: $env:DEEPSEEK_API_KEY = 'sk-...'"
            )
        print(f"[Agent] 使用 {llm.model} 进行推理")

        # 上下文构建
        from .runner import (
            _build_engineering, _build_repository, _build_source_files,
            _build_validation_results, _build_code_context,
            _build_asset_context, _build_runtime_context,
            _is_dependency_type, _build_code_root_cause, _build_dependency_root_cause,
        )

        is_dep = _is_dependency_type(body, finding)
        eng = _build_engineering(finding, body, is_dep, {})
        repo = _build_repository(body, {})
        sources = _build_source_files(body, body.get("source_files") or {}, {})
        tool_results = _build_validation_results(body, {})
        if not tool_results:
            tool_results = _manual_review_validation_results()
        workspace = Path(body.get("source_dir") or Path.cwd()).resolve()

        code_ctx = _build_code_context(finding, body, {})
        asset_ctx = _build_asset_context(finding, body, {})
        runtime_ctx = _build_runtime_context(finding, body, {})
        if is_dep:
            root_cause_ctx = _build_dependency_root_cause(finding, body, {})
        else:
            root_cause_ctx = _build_code_root_cause(finding, body, {})

        # ── 1. Impact Analysis（始终运行 LLM Agent）──
        task_manager.update(task_id, progress="分析影响面...", stage=2)
        from .impact import ImpactAnalysisAgent
        from .tools import StaticAssetInventoryTool, StaticCodeContextTool, StaticRuntimeEvidenceTool
        try:
            impact_agent = ImpactAnalysisAgent(
                StaticCodeContextTool({finding.finding_id: code_ctx}),
                StaticAssetInventoryTool({finding.finding_id: asset_ctx}),
                StaticRuntimeEvidenceTool({finding.finding_id: runtime_ctx}),
                llm=llm,
                workspace=workspace,
            )
            impact_agent.max_turns = 12 if not fast_mode else 6
            impact = impact_agent.analyze(finding)
        except Exception as exc:
            impact = _fallback_impact(finding, code_ctx, asset_ctx, runtime_ctx, exc)

        # ── 2. Root Cause（始终运行 LLM Agent）──
        task_manager.update(task_id, progress="分析根因...", stage=3)
        from .root_cause import RootCauseAnalysisAgent
        from .tools import StaticRootCauseEvidenceTool, RootCauseCodeContext, DependencyRootCauseContext

        try:
            rc_agent = RootCauseAnalysisAgent(StaticRootCauseEvidenceTool(
                code_contexts={finding.finding_id: root_cause_ctx}
                if isinstance(root_cause_ctx, RootCauseCodeContext) else {},
                dependency_contexts={finding.finding_id: root_cause_ctx}
                if isinstance(root_cause_ctx, DependencyRootCauseContext) else {},
            ), llm=llm, workspace=workspace)
            rc_agent.max_turns = 12 if not fast_mode else 6
            root_cause = rc_agent.analyze(finding, impact)
        except Exception as exc:
            root_cause = _fallback_root_cause(finding, root_cause_ctx, exc)

        # ── 3. 修复循环 (Remediation → Patch → Validation → Report) ──
        task_manager.update(task_id, progress="制定修复方案并生成补丁...", stage=4)
        from .failure_analysis import FailureAnalysisAgent
        from .models import PatchGenerationPolicy
        from .orchestration import PatchRepairLoopOrchestrator
        from .patching import PatchGenerationAgent
        from .remediation import RemediationPlanAgent
        from .reporting import RemediationReportAgent
        from .validation import ValidationToolchain
        from .execution import WorkspaceValidationExecutor

        max_attempts = int(body.get("max_attempts") or 2)

        validation_commands = body.get("validation_commands") or {}
        validation_executor = WorkspaceValidationExecutor(
            workspace=workspace,
            commands=validation_commands,
            timeout_seconds=int(body.get("validation_timeout") or 300),
        )
        loop = PatchRepairLoopOrchestrator(
            remediation_agent=RemediationPlanAgent(
                llm=llm,
                workspace=workspace,
                prefer_static=False,  # 始终使用 LLM Agent 进行修复方案推理
                max_turns=10 if not fast_mode else 6,
            ),
            patch_generation_agent=PatchGenerationAgent(PatchGenerationPolicy(), llm=llm, workspace=workspace),
            validation_toolchain=ValidationToolchain(executor=validation_executor),
            failure_analysis_agent=FailureAnalysisAgent(llm=llm, workspace=workspace),
            report_agent=RemediationReportAgent(),
            max_attempts=max_attempts,
        )
        loop.patch_generation_agent.max_turns = 12 if not fast_mode else 8
        loop.failure_analysis_agent.max_turns = 6 if not fast_mode else 4

        try:
            result = loop.run(finding, impact, root_cause, eng, repo, sources, [tool_results])
        except Exception as loop_exc:
            # 循环失败时生成回退的修复方案用于报告展示
            fallback_plan = _fallback_remediation_plan(finding, impact, root_cause, eng, loop_exc)
            output: dict[str, Any] = {
                "finding": finding.to_dict(),
                "impact": impact.to_dict(),
                "root_cause": root_cause.to_dict(),
                "remediation_plan": fallback_plan.to_dict(),
                "status": "error",
                "repository_context": body.get("repository_context"),
            }
            task_manager.update(task_id, status="failed",
                                progress=f"❌ 修复循环异常: {loop_exc}",
                                result=output,
                                error=str(loop_exc))
            return

        # ── 4. 构建输出 ──
        task_manager.update(task_id, progress="生成报告...", stage=5)

        output: dict[str, Any] = {
            "finding": finding.to_dict(),
            "impact": impact.to_dict(),
            "root_cause": root_cause.to_dict(),
            "status": result.status.value,
            "run_mode": run_mode,
            "repository_context": body.get("repository_context"),
        }
        if result.attempts:
            attempt = result.attempts[-1]
            output["remediation_plan"] = attempt.remediation_plan.to_dict()
            output["patch_candidate"] = attempt.patch_candidate.to_dict()
            output["patch_validation"] = attempt.validation.to_dict()
        if result.final_report is not None:
            output["report"] = result.final_report.to_dict()
            output["report_markdown"] = result.final_report.pr_description_markdown
        if result.final_failure_analysis is not None:
            output["failure_analysis"] = result.final_failure_analysis.to_dict()

        if result.status.value == "succeeded":
            task_manager.update(task_id, status="succeeded", progress="✅ 候选补丁生成并完成验证", result=output)
        elif result.status.value == "blocked":
            candidate_status = output.get("patch_candidate", {}).get("status")
            if candidate_status == "generated":
                progress = "⚠️ 候选补丁已生成；部分验证待补充，需人工复核"
            else:
                progress = "⚠️ 流程完成：补丁生成被阻断，需人工复核"
            task_manager.update(task_id, status="succeeded", progress=progress, result=output)
        else:
            task_manager.update(task_id, status="failed", progress="❌ 修复失败",
                                result=output,
                                error=output.get("failure_analysis", {}).get("summary", "未知错误"))

    except Exception as exc:
        task_manager.update(task_id, status="failed",
                            progress=f"❌ 异常: {exc}",
                            error=str(exc))


# 模块级 app 实例（兼容 uvicorn 直接引用）
app = create_app()
