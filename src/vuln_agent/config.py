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
AVAILABLE_LLM_MODELS = (
    "glm-5.2",
    "deepseek-v4-pro",
    "deepseek-chat",
    "deepseek-reasoner",
)


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
    deepseek_enabled = bool(os.environ.get("DEEPSEEK_API_KEY"))
    glm_enabled = bool(os.environ.get("GLM_API_KEY"))
    current_model = os.environ.get("LLM_MODEL") or os.environ.get("DEEPSEEK_MODEL") or "deepseek-chat"
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    gitlab_token = os.environ.get("GITLAB_TOKEN")
    return {
        "llm": {
            "enabled": deepseek_enabled or glm_enabled,
            "model": current_model,
            "providers": {
                "deepseek": {
                    "enabled": deepseek_enabled,
                    "base_url": os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                },
                "glm": {
                    "enabled": glm_enabled,
                    "base_url": os.environ.get("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4/"),
                },
            },
            "available_models": list(AVAILABLE_LLM_MODELS),
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
