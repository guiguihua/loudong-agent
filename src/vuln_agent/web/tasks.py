"""异步任务管理 — 内存队列 + JSON 文件持久化历史记录。"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).resolve().parents[3] / ".data"
HISTORY_FILE = DATA_DIR / "task_history.json"


@dataclass
class StageEvent:
    """单个阶段内的事件记录。"""
    timestamp: float = field(default_factory=time.time)
    stage: int = 0
    event_type: str = ""  # started | progress | llm_call | tool_call | completed | error
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskInfo:
    task_id: str
    status: str = "pending"  # pending | running | succeeded | blocked | failed
    progress: str = "等待开始..."
    stage: int = 0  # 0=创建, 1=标准化, 2=影响面, 3=根因, 4=补丁, 5=验证, 6=报告
    result: dict[str, Any] | None = None
    error: str | None = None
    vuln_type: str | None = None
    severity: str | None = None
    created_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    # ── 可观测性增强 ──
    events: list[StageEvent] = field(default_factory=list)
    attempt: int = 0
    current_target: str | None = None
    stage_started_at: dict[int, float] = field(default_factory=dict)
    total_llm_calls: int = 0
    total_tokens: int = 0

    def add_event(
        self, event_type: str, message: str, stage: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """添加事件记录并更新进度。"""
        evt = StageEvent(
            timestamp=time.time(),
            stage=stage if stage is not None else self.stage,
            event_type=event_type,
            message=message,
            details=details or {},
        )
        self.events.append(evt)
        self.progress = message
        # 跟踪 LLM 调用和 token
        if event_type == "llm_call":
            self.total_llm_calls += 1
            self.total_tokens += (details or {}).get("tokens", 0)

    def start_stage(self, stage: int, message: str, attempt: int = 0) -> None:
        """标记阶段开始。"""
        self.stage = stage
        self.attempt = attempt
        self.stage_started_at[stage] = time.time()
        self.add_event("started", message, stage=stage, details={"attempt": attempt})

    def complete_stage(self, stage: int, message: str) -> None:
        """标记阶段完成。"""
        elapsed = 0.0
        if stage in self.stage_started_at:
            elapsed = time.time() - self.stage_started_at[stage]
        self.add_event("completed", message, stage=stage,
                      details={"elapsed_sec": round(elapsed, 2)})

    @property
    def created_at_str(self) -> str:
        return datetime.fromtimestamp(self.created_at).strftime("%m-%d %H:%M")

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "progress": self.progress,
            "stage": self.stage,
            "result": self.result,
            "error": self.error,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "created_at": self.created_at,
            "created_at_str": self.created_at_str,
            "finished_at": self.finished_at,
            "attempt": self.attempt,
            "current_target": self.current_target,
            "total_llm_calls": self.total_llm_calls,
            "total_tokens": self.total_tokens,
            "events": [
                {
                    "timestamp": e.timestamp,
                    "stage": e.stage,
                    "type": e.event_type,
                    "message": e.message,
                    "details": e.details,
                }
                for e in self.events[-50:]  # 最近 50 条
            ],
        }


class TaskManager:
    """内存中的任务管理器 + JSON 历史持久化（线程安全）。"""

    def __init__(self):
        self._tasks: dict[str, TaskInfo] = {}
        self._lock = __import__("threading").Lock()
        self._load_history()

    # ── CRUD ──

    def create(self, vuln_type: str = "", severity: str = "") -> TaskInfo:
        task_id = self._generate_id(vuln_type, severity)
        info = TaskInfo(task_id=task_id, vuln_type=vuln_type, severity=severity)
        with self._lock:
            self._tasks[task_id] = info
        return info

    def get(self, task_id: str) -> TaskInfo | None:
        with self._lock:
            return self._tasks.get(task_id)

    def update(self, task_id: str, **kwargs: Any) -> TaskInfo | None:
        with self._lock:
            info = self._tasks.get(task_id)
            if info is None:
                return None
            for k, v in kwargs.items():
                if hasattr(info, k):
                    setattr(info, k, v)
            if kwargs.get("status") in ("succeeded", "blocked", "failed"):
                info.finished_at = time.time()
        # 持久化在锁外进行（避免 I/O 阻塞锁）
        if kwargs.get("status") in ("succeeded", "blocked", "failed"):
            self._persist_task(info)
        return info

    def list_recent(self, n: int = 20) -> list[TaskInfo]:
        with self._lock:
            tasks = sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)
        return tasks[:n]

    def list_all(self) -> list[TaskInfo]:
        with self._lock:
            tasks = sorted(self._tasks.values(), key=lambda t: t.created_at, reverse=True)
        return tasks

    def stats(self) -> dict[str, int]:
        with self._lock:
            total = len(self._tasks)
            succeeded = sum(1 for t in self._tasks.values() if t.status == "succeeded")
            blocked = sum(1 for t in self._tasks.values() if t.status == "blocked")
            failed = sum(1 for t in self._tasks.values() if t.status == "failed")
            pending = total - succeeded - blocked - failed
        return {
            "total": total,
            "succeeded": succeeded,
            "blocked": blocked,
            "failed": failed,
            "pending": pending,
        }

    # ── Private ──

    @staticmethod
    def _generate_id(vuln_type: str, severity: str) -> str:
        prefix = "FIX"
        if vuln_type:
            prefix = "".join(w[0].upper() for w in vuln_type.split()[:3])
        idx = str(uuid.uuid4().fields[0])[:6].upper()
        return f"{prefix}-{idx}"

    def _persist_task(self, info: TaskInfo) -> None:
        """追加一条任务到历史文件。"""
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            existing: list[dict[str, Any]] = []
            if HISTORY_FILE.exists():
                existing = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            existing.append(info.to_dict())
            HISTORY_FILE.write_text(
                json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except Exception:
            pass  # 持久化失败不影响主流程

    def _load_history(self) -> None:
        """从历史文件恢复任务记录（仅用于 history 页面展示）。"""
        try:
            if HISTORY_FILE.exists():
                records = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
                for rec in records[-100:]:  # 最多恢复 100 条
                    tid = rec.get("task_id", "")
                    if tid and tid not in self._tasks:
                        info = TaskInfo(
                            task_id=tid,
                            status=rec.get("status", "unknown"),
                            vuln_type=rec.get("vuln_type"),
                            severity=rec.get("severity"),
                            created_at=rec.get("created_at", 0),
                            finished_at=rec.get("finished_at"),
                            result=rec.get("result"),
                            error=rec.get("error"),
                        )
                        self._tasks[tid] = info
        except Exception:
            pass


# 全局单例
task_manager = TaskManager()
