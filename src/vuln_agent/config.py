"""Application configuration helpers.

The web app should work when started from the project root without requiring
the caller to manually export every environment variable.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".env"


def load_env_file(path: Path = ENV_FILE) -> None:
    """Load simple KEY=VALUE pairs from .env without overriding real env vars."""
    if not path.exists():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def config_status() -> dict[str, Any]:
    """Return safe configuration status with secrets masked."""
    load_env_file()
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    return {
        "llm": {
            "enabled": bool(os.environ.get("DEEPSEEK_API_KEY")),
            "provider": "DeepSeek",
            "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
            "base_url": os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        },
        "pull_request": {
            "github": {
                "enabled": bool(github_token),
                "api_base": os.environ.get("GITHUB_API_BASE", "https://api.github.com"),
            },
            "gitlab": {
                "enabled": bool(gitlab_token),
                "api_base": os.environ.get("GITLAB_API_BASE", "https://gitlab.com/api/v4"),
            },
        },
    }
