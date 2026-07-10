"""Git 仓库操作 — 克隆、浏览分支/文件/提交历史。"""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

import git

from ..cli import _SOURCE_EXTENSIONS, _SOURCE_EXCLUDE_DIRS, _SOURCE_EXCLUDE_NAMES

DATA_DIR = Path(__file__).resolve().parents[3] / ".data"
REPOS_ROOT = DATA_DIR / "repos"


class GitHandler:
    """Git 仓库管理器。"""

    def __init__(self):
        REPOS_ROOT.mkdir(parents=True, exist_ok=True)

    def clone(self, url: str) -> str:
        """浅克隆仓库，返回 repo_id。"""
        repo_id = self._repo_id(url)
        dest = REPOS_ROOT / repo_id
        if dest.exists():
            # 已存在 → pull
            try:
                repo = git.Repo(dest)
                repo.remotes.origin.pull(depth=50)
                return repo_id
            except Exception:
                import shutil
                shutil.rmtree(dest, ignore_errors=True)

        git.Repo.clone_from(url, dest, depth=50, single_branch=True)
        return repo_id

    def list_repos(self) -> list[dict[str, Any]]:
        """列出已克隆的仓库。"""
        repos = []
        for d in REPOS_ROOT.iterdir():
            if d.is_dir() and (d / ".git").exists():
                try:
                    repo = git.Repo(d)
                    repos.append({
                        "id": d.name,
                        "name": d.name,
                        "branch": repo.active_branch.name,
                        "url": repo.remotes.origin.url,
                    })
                except Exception:
                    pass
        return repos

    def get_repo_info(self, repo_id: str) -> dict[str, Any] | None:
        """获取仓库基本信息。"""
        try:
            repo = self._get_repo(repo_id)
            return {
                "id": repo_id,
                "name": repo_id,
                "branch": repo.active_branch.name,
                "branches": [b.name for b in repo.branches],
                "url": repo.remotes.origin.url,
            }
        except Exception:
            return None

    def list_branches(self, repo_id: str) -> list[str]:
        """列出所有分支。"""
        try:
            repo = self._get_repo(repo_id)
            return [b.name for b in repo.branches]
        except Exception:
            return []

    def list_commits(self, repo_id: str, branch: str = "main", n: int = 30) -> list[dict[str, Any]]:
        """列出最近 n 条提交。"""
        try:
            repo = self._get_repo(repo_id)
            commits = []
            for commit in repo.iter_commits(branch, max_count=n):
                commits.append({
                    "sha": commit.hexsha[:8],
                    "full_sha": commit.hexsha,
                    "message": commit.message.strip().split("\n")[0][:80],
                    "author": str(commit.author),
                    "date": time.strftime("%Y-%m-%d %H:%M", time.localtime(commit.committed_date)),
                })
            return commits
        except Exception:
            return []

    def get_file_tree(self, repo_id: str, branch: str = "main") -> list[dict[str, Any]]:
        """获取仓库文件树（仅源码文件）。"""
        try:
            repo = self._get_repo(repo_id)
            commit = repo.branches[branch].commit if branch in repo.branches else repo.head.commit
            tree = commit.tree
            return self._build_tree(repo, tree, "")
        except Exception:
            return []

    def get_file_content(self, repo_id: str, path: str, branch: str = "main") -> str:
        """获取文件内容。"""
        try:
            repo = self._get_repo(repo_id)
            commit = repo.branches[branch].commit if branch in repo.branches else repo.head.commit
            blob = commit.tree / path
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except Exception:
            return f"// 无法读取文件: {path}"

    def load_all_source_files(self, repo_id: str, branch: str = "main") -> dict[str, str]:
        """递归加载所有源码文件（复用 CLI 的扩展名规则）。"""
        try:
            repo = self._get_repo(repo_id)
            commit = repo.branches[branch].commit if branch in repo.branches else repo.head.commit
            files: dict[str, str] = {}
            self._walk_tree(repo, commit.tree, "", files)
            return files
        except Exception:
            return {}

    # ── Private ──

    def _get_repo(self, repo_id: str) -> git.Repo:
        dest = REPOS_ROOT / repo_id
        if not dest.exists():
            raise FileNotFoundError(f"仓库不存在: {repo_id}")
        return git.Repo(dest)

    @staticmethod
    def _repo_id(url: str) -> str:
        """从 URL 生成唯一 repo_id。"""
        name = re.sub(r"https?://|github\.com/|\.git$", "", url).strip("/")
        name = name.replace("/", "-").replace(":", "-")
        return hashlib.md5(name.encode()).hexdigest()[:12]

    def _build_tree(self, repo: git.Repo, tree, prefix: str, depth: int = 0) -> list[dict[str, Any]]:
        """递归构建文件树。"""
        items = []
        for blob in tree:
            path = f"{prefix}/{blob.name}" if prefix else blob.name
            if blob.type == "tree":
                if blob.name in _SOURCE_EXCLUDE_DIRS or blob.name.startswith("."):
                    continue
                children = self._build_tree(repo, blob, path, depth + 1)
                if children:
                    items.append({
                        "name": blob.name,
                        "path": path,
                        "type": "dir",
                        "children": children,
                    })
            else:
                ext = Path(blob.name).suffix.lower()
                name_lower = blob.name.lower()
                if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                    continue
                if blob.name in _SOURCE_EXCLUDE_NAMES:
                    continue
                items.append({
                    "name": blob.name,
                    "path": path,
                    "type": "file",
                    "size": blob.size,
                })
        return sorted(items, key=lambda x: (0 if x["type"] == "dir" else 1, x["name"]))

    def _walk_tree(self, repo: git.Repo, tree, prefix: str, files: dict[str, str]) -> None:
        """递归遍历加载所有源码文件。"""
        for blob in tree:
            path = f"{prefix}/{blob.name}" if prefix else blob.name
            if blob.type == "tree":
                if blob.name in _SOURCE_EXCLUDE_DIRS or blob.name.startswith("."):
                    continue
                self._walk_tree(repo, blob, path, files)
            else:
                ext = Path(blob.name).suffix.lower()
                name_lower = blob.name.lower()
                if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                    continue
                if blob.name in _SOURCE_EXCLUDE_NAMES:
                    continue
                try:
                    content = blob.data_stream.read().decode("utf-8", errors="replace")
                    files[path] = content
                except Exception:
                    pass


# 全局单例
git_handler = GitHandler()
