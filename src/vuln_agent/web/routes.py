"""页面路由 — Jinja2 模板渲染 + 基础 API。"""

from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/")
async def dashboard(request: Request):
    """仪表盘首页。"""
    from .tasks import task_manager

    recent = [t.to_dict() for t in task_manager.list_recent(20)]
    stats = task_manager.stats()
    return request.app.state.render(
        "dashboard.html",
        request=request, stats=stats, recent_tasks=recent,
    )


@router.get("/new")
async def new_fix(request: Request):
    """新建修复任务页面。"""
    return request.app.state.render(
        "new_fix.html",
        request=request,
        initial_repo_id=request.query_params.get("repo_id", ""),
    )


@router.get("/finding/{finding_id}")
async def finding_detail(request: Request, finding_id: str):
    """漏洞详情/结果页面。"""
    from .tasks import task_manager

    task = task_manager.get(finding_id)
    return request.app.state.render(
        "finding.html",
        request=request, finding_id=finding_id,
        task=task.to_dict() if task else None,
    )


@router.get("/chat")
async def chat_page(request: Request):
    """聊天页面。"""
    return request.app.state.render("chat.html", request=request)


@router.get("/repo")
async def repo_list(request: Request):
    """代码仓库管理。"""
    try:
        from .git_handler import git_handler
        repos = git_handler.list_repos()
    except Exception:
        repos = []
    return request.app.state.render(
        "repo.html",
        request=request, repos=repos, current_repo=None, repo_id=None,
    )


@router.get("/repo/{repo_id}")
async def repo_browse(request: Request, repo_id: str):
    """浏览仓库。"""
    try:
        from .git_handler import git_handler
        info = git_handler.get_repo_info(repo_id)
        branch = request.query_params.get("branch")
        if info and branch:
            info["branch"] = branch
    except Exception:
        info = None
    return request.app.state.render(
        "repo.html",
        request=request, repos=[], current_repo=info, repo_id=repo_id,
    )


@router.get("/history")
async def history_page(request: Request):
    """历史记录页面。"""
    from .tasks import task_manager

    all_tasks = [t.to_dict() for t in task_manager.list_all()]
    return request.app.state.render(
        "history.html", request=request, tasks=all_tasks,
    )
