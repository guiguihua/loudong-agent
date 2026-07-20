"""Repository binding and Git browsing helpers."""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

import git

from ..cli import _SOURCE_EXCLUDE_DIRS, _SOURCE_EXCLUDE_NAMES, _SOURCE_EXTENSIONS

DATA_DIR = Path(__file__).resolve().parents[3] / ".data"
REPOS_ROOT = DATA_DIR / "repos"
REPO_REGISTRY_FILE = DATA_DIR / "repo_registry.json"


class GitHandler:
    """Manage long-lived repository bindings.

    A binding can be a cloned remote repository, an existing local Git repo,
    or a plain local source directory.
    The public methods intentionally keep the old names used by the UI/API.
    """

    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        REPOS_ROOT.mkdir(parents=True, exist_ok=True)

    def clone(
        self,
        url: str,
        *,
        name: str = "",
        provider: str = "git",
        default_branch: str = "",
    ) -> str:
        """Clone or update a remote repository, then persist its binding."""
        repo_id = self._repo_id(url)
        dest = REPOS_ROOT / repo_id
        if dest.exists():
            try:
                repo = git.Repo(dest)
                repo.remotes.origin.pull(depth=50)
                self._save_repo_meta(repo_id, repo, name=name, provider=provider, url=url)
                return repo_id
            except Exception:
                import shutil

                shutil.rmtree(dest, ignore_errors=True)

        git.Repo.clone_from(url, dest, depth=50, single_branch=True)
        repo = git.Repo(dest)
        self._save_repo_meta(
            repo_id,
            repo,
            name=name,
            provider=provider,
            url=url,
            default_branch=default_branch,
        )
        return repo_id

    def bind_local(self, path: str, *, name: str = "", provider: str = "local") -> str:
        """Bind a local source directory without copying source code.

        If the directory is inside a Git repository, Git metadata is recorded.
        Source browsing/loading still uses the selected directory itself, so
        uncommitted local files are visible.
        """
        repo_path = Path(path).expanduser().resolve()
        if not repo_path.exists() or not repo_path.is_dir():
            raise FileNotFoundError(f"local source directory not found: {repo_path}")
        repo_id = self._repo_id(str(repo_path))
        try:
            repo = git.Repo(repo_path, search_parent_directories=True)
        except Exception:
            repo = None

        meta = {
            "id": repo_id,
            "name": name or repo_path.name,
            "provider": provider,
            "url": self._safe_remote(repo) if repo else str(repo_path),
            "local_path": str(repo_path),
            "git_root": str(repo.working_tree_dir) if repo and repo.working_tree_dir else "",
            "default_branch": self._safe_branch(repo) if repo else "filesystem",
            "auth_mode": "local",
            "source_mode": "filesystem",
            "permissions": {"read": True, "write_branch": False, "create_pr": False},
            "index_status": self._index_status(repo) if repo else self._filesystem_index_status(repo_path),
        }
        self._save_binding(repo_id, meta)
        return repo_id

    def list_repos(self) -> list[dict[str, Any]]:
        """List repository bindings, including legacy clones."""
        registry = self._load_registry()
        repos: list[dict[str, Any]] = []
        seen: set[str] = set()

        for repo_id, meta in sorted(registry.items(), key=lambda item: item[1].get("name", item[0])):
            item = dict(meta)
            item["id"] = repo_id
            local_path = Path(str(item.get("local_path", "")))
            if item.get("source_mode") == "filesystem":
                item["branch"] = item.get("default_branch", "filesystem")
                item["branches"] = self._local_branches(item)
                item["index_status"] = self._filesystem_index_status(local_path)
                item["unavailable"] = not local_path.exists()
            else:
                try:
                    repo = self._get_repo(repo_id)
                    item["branch"] = self._safe_branch(repo)
                    item["branches"] = [b.name for b in repo.branches]
                    item["index_status"] = self._index_status(repo)
                    item["unavailable"] = False
                except Exception:
                    item["branch"] = item.get("default_branch", "")
                    item["branches"] = []
                    item["unavailable"] = True
            repos.append(item)
            seen.add(repo_id)

        for path in REPOS_ROOT.iterdir():
            if not path.is_dir() or not (path / ".git").exists() or path.name in seen:
                continue
            try:
                repo = git.Repo(path)
                repos.append(self._meta_from_repo(path.name, repo, local_path=path))
            except Exception:
                continue
        return repos

    def get_repo_info(self, repo_id: str) -> dict[str, Any] | None:
        """Return metadata for a bound repository."""
        try:
            meta = self._load_registry().get(repo_id, {})
            if meta.get("source_mode") == "filesystem":
                local_path = Path(str(meta.get("local_path", "")))
                info = dict(meta)
                info["id"] = repo_id
                info["branch"] = meta.get("default_branch", "filesystem")
                info["branches"] = self._local_branches(meta)
                info["index_status"] = self._filesystem_index_status(local_path)
                return info
            repo = self._get_repo(repo_id)
            info = self._meta_from_repo(repo_id, repo, local_path=self._repo_path(repo_id))
            info.update(meta)
            info["id"] = repo_id
            info["branch"] = self._safe_branch(repo)
            info["branches"] = [b.name for b in repo.branches]
            info["index_status"] = self._index_status(repo)
            return info
        except Exception:
            return None

    def list_branches(self, repo_id: str) -> list[str]:
        try:
            meta = self._load_registry().get(repo_id, {})
            if meta.get("source_mode") == "filesystem":
                return self._local_branches(meta)
            return [b.name for b in self._get_repo(repo_id).branches]
        except Exception:
            return []

    def list_commits(self, repo_id: str, branch: str = "main", n: int = 30) -> list[dict[str, Any]]:
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
        try:
            meta = self._load_registry().get(repo_id, {})
            if meta.get("source_mode") == "filesystem":
                return self._build_fs_tree(Path(str(meta["local_path"])), "")
            repo = self._get_repo(repo_id)
            commit = self._commit_for_branch(repo, branch)
            return self._build_tree(commit.tree, "")
        except Exception:
            return []

    def get_file_content(self, repo_id: str, path: str, branch: str = "main") -> str:
        try:
            meta = self._load_registry().get(repo_id, {})
            if meta.get("source_mode") == "filesystem":
                root = Path(str(meta["local_path"])).resolve()
                target = (root / path).resolve()
                if root != target and root not in target.parents:
                    raise ValueError("path escapes local source root")
                return target.read_text(encoding="utf-8", errors="replace")
            repo = self._get_repo(repo_id)
            commit = self._commit_for_branch(repo, branch)
            blob = commit.tree / path
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except Exception:
            return f"// unable to read file: {path}"

    def load_all_source_files(self, repo_id: str, branch: str = "main") -> dict[str, str]:
        try:
            meta = self._load_registry().get(repo_id, {})
            if meta.get("source_mode") == "filesystem":
                return self._load_filesystem_source(Path(str(meta["local_path"])))
            repo = self._get_repo(repo_id)
            commit = self._commit_for_branch(repo, branch)
            files: dict[str, str] = {}
            self._walk_tree(commit.tree, "", files)
            return files
        except Exception:
            return {}

    def get_repo_path(self, repo_id: str) -> Path:
        return self._repo_path(repo_id)

    def _get_repo(self, repo_id: str) -> git.Repo:
        path = self._repo_path(repo_id)
        if not path.exists():
            raise FileNotFoundError(f"repository not found: {repo_id}")
        return git.Repo(path)

    def _repo_path(self, repo_id: str) -> Path:
        meta = self._load_registry().get(repo_id, {})
        if meta.get("local_path"):
            return Path(str(meta["local_path"]))
        return REPOS_ROOT / repo_id

    @staticmethod
    def _repo_id(value: str) -> str:
        name = re.sub(r"https?://|github\.com/|gitlab\.com/|\.git$", "", value).strip("/")
        name = name.replace("/", "-").replace("\\", "-").replace(":", "-")
        return hashlib.md5(name.encode()).hexdigest()[:12]

    @staticmethod
    def _display_name(url: str, fallback: str) -> str:
        cleaned = url.rstrip("/").removesuffix(".git")
        return cleaned.split("/")[-1] if cleaned else fallback

    @staticmethod
    def _safe_branch(repo: git.Repo | None) -> str:
        if repo is None:
            return "filesystem"
        try:
            return repo.active_branch.name
        except Exception:
            return "HEAD"

    @staticmethod
    def _safe_remote(repo: git.Repo | None) -> str:
        if repo is None:
            return ""
        try:
            return repo.remotes.origin.url
        except Exception:
            return ""

    @staticmethod
    def _commit_for_branch(repo: git.Repo, branch: str):
        if branch and branch in repo.branches:
            return repo.branches[branch].commit
        return repo.head.commit

    @staticmethod
    def _index_status(repo: git.Repo | None) -> dict[str, Any]:
        if repo is None:
            return {
                "last_indexed_commit": "filesystem",
                "last_indexed_at": time.strftime("%Y-%m-%d %H:%M"),
                "file_index_ready": True,
                "dependency_index_ready": False,
                "semantic_index_ready": False,
            }
        try:
            commit = repo.head.commit.hexsha
        except Exception:
            commit = ""
        return {
            "last_indexed_commit": commit[:12],
            "last_indexed_at": time.strftime("%Y-%m-%d %H:%M"),
            "file_index_ready": True,
            "dependency_index_ready": False,
            "semantic_index_ready": False,
        }

    def _meta_from_repo(self, repo_id: str, repo: git.Repo, *, local_path: Path) -> dict[str, Any]:
        return {
            "id": repo_id,
            "name": local_path.name or repo_id,
            "provider": "git",
            "url": self._safe_remote(repo),
            "local_path": str(local_path),
            "default_branch": self._safe_branch(repo),
            "branch": self._safe_branch(repo),
            "branches": [b.name for b in repo.branches],
            "auth_mode": "none",
            "permissions": {"read": True, "write_branch": False, "create_pr": False},
            "index_status": self._index_status(repo),
        }

    def _save_repo_meta(
        self,
        repo_id: str,
        repo: git.Repo,
        *,
        name: str = "",
        provider: str = "git",
        url: str = "",
        local_path: Path | None = None,
        default_branch: str = "",
        auth_mode: str = "none",
    ) -> None:
        path = local_path or Path(repo.working_tree_dir or REPOS_ROOT / repo_id)
        meta = {
            "id": repo_id,
            "name": name or self._display_name(url or str(path), repo_id),
            "provider": provider,
            "url": url or self._safe_remote(repo),
            "local_path": str(path),
            "default_branch": default_branch or self._safe_branch(repo),
            "auth_mode": auth_mode,
            "permissions": {"read": True, "write_branch": False, "create_pr": False},
            "index_status": self._index_status(repo),
        }
        registry = self._load_registry()
        current = registry.get(repo_id, {})
        current.update(meta)
        registry[repo_id] = current
        REPO_REGISTRY_FILE.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")

    def _save_binding(self, repo_id: str, meta: dict[str, Any]) -> None:
        registry = self._load_registry()
        current = registry.get(repo_id, {})
        current.update(meta)
        registry[repo_id] = current
        REPO_REGISTRY_FILE.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")

    def _load_registry(self) -> dict[str, dict[str, Any]]:
        try:
            if REPO_REGISTRY_FILE.exists():
                data = json.loads(REPO_REGISTRY_FILE.read_text(encoding="utf-8"))
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}
        return {}

    def _build_tree(self, tree, prefix: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for blob in tree:
            path = f"{prefix}/{blob.name}" if prefix else blob.name
            if blob.type == "tree":
                if blob.name in _SOURCE_EXCLUDE_DIRS or blob.name.startswith("."):
                    continue
                children = self._build_tree(blob, path)
                if children:
                    items.append({"name": blob.name, "path": path, "type": "dir", "children": children})
                continue

            ext = Path(blob.name).suffix.lower()
            name_lower = blob.name.lower()
            if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                continue
            if blob.name in _SOURCE_EXCLUDE_NAMES:
                continue
            items.append({"name": blob.name, "path": path, "type": "file", "size": blob.size})
        return sorted(items, key=lambda item: (0 if item["type"] == "dir" else 1, item["name"]))

    def _build_fs_tree(self, root: Path, prefix: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        directory = root / prefix if prefix else root
        if not directory.exists() or not directory.is_dir():
            return items
        for child in sorted(directory.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if child.name in _SOURCE_EXCLUDE_DIRS or child.name.startswith("."):
                continue
            rel = str(child.relative_to(root)).replace("\\", "/")
            if child.is_dir():
                children = self._build_fs_tree(root, rel)
                if children:
                    items.append({"name": child.name, "path": rel, "type": "dir", "children": children})
                continue
            ext = child.suffix.lower()
            name_lower = child.name.lower()
            if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                continue
            if child.name in _SOURCE_EXCLUDE_NAMES:
                continue
            try:
                size = child.stat().st_size
            except OSError:
                size = 0
            items.append({"name": child.name, "path": rel, "type": "file", "size": size})
        return items

    def _walk_tree(self, tree, prefix: str, files: dict[str, str]) -> None:
        for blob in tree:
            path = f"{prefix}/{blob.name}" if prefix else blob.name
            if blob.type == "tree":
                if blob.name in _SOURCE_EXCLUDE_DIRS or blob.name.startswith("."):
                    continue
                self._walk_tree(blob, path, files)
                continue

            ext = Path(blob.name).suffix.lower()
            name_lower = blob.name.lower()
            if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                continue
            if blob.name in _SOURCE_EXCLUDE_NAMES:
                continue
            try:
                files[path] = blob.data_stream.read().decode("utf-8", errors="replace")
            except Exception:
                continue

    def _load_filesystem_source(self, root: Path) -> dict[str, str]:
        files: dict[str, str] = {}
        if not root.exists() or not root.is_dir():
            return files
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            if any(part in _SOURCE_EXCLUDE_DIRS for part in file_path.parts):
                continue
            if file_path.name in _SOURCE_EXCLUDE_NAMES:
                continue
            ext = file_path.suffix.lower()
            name_lower = file_path.name.lower()
            if ext not in _SOURCE_EXTENSIONS and name_lower not in _SOURCE_EXTENSIONS:
                continue
            try:
                rel = str(file_path.relative_to(root)).replace("\\", "/")
                files[rel] = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
        return files

    @staticmethod
    def _filesystem_index_status(path: Path) -> dict[str, Any]:
        try:
            newest = max((p.stat().st_mtime for p in path.rglob("*") if p.is_file()), default=path.stat().st_mtime)
        except Exception:
            newest = time.time()
        return {
            "last_indexed_commit": "filesystem",
            "last_indexed_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(newest)),
            "file_index_ready": True,
            "dependency_index_ready": False,
            "semantic_index_ready": False,
        }

    @staticmethod
    def _local_branches(meta: dict[str, Any]) -> list[str]:
        branch = str(meta.get("default_branch") or "filesystem")
        return [branch]


git_handler = GitHandler()
