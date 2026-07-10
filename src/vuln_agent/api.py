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

from .normalization import VulnerabilityNormalizer

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


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
    def health() -> dict[str, str]:
        return {"status": "ok", "llm": "enabled" if _has_llm() else "disabled"}

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

            # LLM 开关
            body["use_llm"] = body.get("use_llm") in ("1", "true", "True", True)

        if not body:
            return JSONResponse({"error": "空请求体"}, status_code=400)

        # 创建任务
        info = task_manager.create(
            vuln_type=body.get("vulnerability_type", ""),
            severity=body.get("severity", ""),
        )
        task_manager.update(info.task_id, status="running", progress="标准化漏洞报告...", stage=1)

        # 后台执行流水线
        import asyncio
        asyncio.create_task(_run_pipeline_async(info.task_id, body))

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
                repo_id = git_handler.clone(url)
                return {"repo_id": repo_id, "url": url}
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


async def _run_pipeline_async(task_id: str, body: dict[str, Any]) -> None:
    """后台异步执行修复流水线，实时更新任务状态。"""
    from .runner import run_dict
    from .web.tasks import task_manager

    try:
        # 标准化
        task_manager.update(task_id, progress="标准化漏洞报告...", stage=1)
        normalizer = VulnerabilityNormalizer()
        finding = normalizer.normalize(body)

        # LLM 后端（始终启用）
        from .llm import create_llm_backend
        llm = create_llm_backend()
        if llm:
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
        sources = _build_source_files(body, {})
        tool_results = _build_validation_results(body, {})

        code_ctx = _build_code_context(finding, body, {})
        asset_ctx = _build_asset_context(finding, body, {})
        runtime_ctx = _build_runtime_context(finding, body, {})

        # ── 1. Impact Analysis ──
        task_manager.update(task_id, progress="分析影响面...", stage=2)
        from .impact import ImpactAnalysisAgent
        from .tools import StaticAssetInventoryTool, StaticCodeContextTool, StaticRuntimeEvidenceTool
        impact = ImpactAnalysisAgent(
            StaticCodeContextTool({finding.finding_id: code_ctx}),
            StaticAssetInventoryTool({finding.finding_id: asset_ctx}),
            StaticRuntimeEvidenceTool({finding.finding_id: runtime_ctx}),
            llm=llm,
        ).analyze(finding)

        # ── 2. Root Cause ──
        task_manager.update(task_id, progress="分析根因...", stage=3)
        from .root_cause import RootCauseAnalysisAgent
        from .tools import StaticRootCauseEvidenceTool, RootCauseCodeContext, DependencyRootCauseContext

        if is_dep:
            root_cause_ctx = _build_dependency_root_cause(finding, body, {})
        else:
            root_cause_ctx = _build_code_root_cause(finding, body, {})

        rc_agent = RootCauseAnalysisAgent(StaticRootCauseEvidenceTool(
            code_contexts={finding.finding_id: root_cause_ctx}
            if isinstance(root_cause_ctx, RootCauseCodeContext) else {},
            dependency_contexts={finding.finding_id: root_cause_ctx}
            if isinstance(root_cause_ctx, DependencyRootCauseContext) else {},
        ), llm=llm)
        root_cause = rc_agent.analyze(finding, impact)

        # ── 3. Repair Loop ──
        task_manager.update(task_id, progress="制定修复方案并生成补丁...", stage=4)
        from .failure_analysis import FailureAnalysisAgent
        from .models import PatchGenerationPolicy, RemediationPolicy
        from .orchestration import PatchRepairLoopOrchestrator
        from .patching import PatchGenerationAgent
        from .remediation import RemediationPlanAgent
        from .reporting import RemediationReportAgent
        from .validation import ValidationToolchain

        loop = PatchRepairLoopOrchestrator(
            remediation_agent=RemediationPlanAgent(RemediationPolicy(), llm=llm),
            patch_generation_agent=PatchGenerationAgent(PatchGenerationPolicy(), llm=llm),
            validation_toolchain=ValidationToolchain(),
            failure_analysis_agent=FailureAnalysisAgent(llm=llm),
            report_agent=RemediationReportAgent(),
            max_attempts=body.get("max_attempts", 1),
        )

        result = loop.run(finding, impact, root_cause, eng, repo, sources, [tool_results])

        # ── 4. Build output ──
        task_manager.update(task_id, progress="生成报告...", stage=6)

        output: dict[str, Any] = {
            "finding": finding.to_dict(),
            "impact": impact.to_dict(),
            "root_cause": root_cause.to_dict(),
            "status": result.status.value,
        }
        if result.final_report is not None:
            output["report"] = result.final_report.to_dict()
            output["report_markdown"] = result.final_report.pr_description_markdown
        if result.attempts:
            attempt = result.attempts[-1]
            output["patch_candidate"] = attempt.patch_candidate.to_dict()
            output["patch_validation"] = attempt.validation.to_dict()
        if result.final_failure_analysis is not None:
            output["failure_analysis"] = result.final_failure_analysis.to_dict()

        if result.status.value == "succeeded":
            task_manager.update(task_id, status="succeeded", progress="✅ 修复完成！", result=output)
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
