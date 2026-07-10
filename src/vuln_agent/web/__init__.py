"""Web UI 模块 — 前端平台路由、聊天、任务管理、Git 集成。"""

from .routes import router as web_router
from .tasks import TaskManager, task_manager
from .chat import ChatManager, chat_manager

__all__ = ["web_router", "TaskManager", "task_manager", "ChatManager", "chat_manager"]
