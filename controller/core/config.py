# Centralized configuration scaffolding for controller
# Lightweight and dependency-free for Phase 1

import os
from dataclasses import dataclass


@dataclass
class Settings:
    data_dir: str = os.environ.get("DATA_DIR", "/opt/dns-proxy/data")
    default_git_repo: str = os.environ.get("DEFAULT_GIT_REPO", "")
    default_git_branch: str = os.environ.get("DEFAULT_GIT_BRANCH", "main")
    code_repo: str = os.environ.get("CODE_REPO", "https://github.com/lokidv/dns-loki.git")
    code_branch: str = os.environ.get("CODE_BRANCH", "main")


def get_settings() -> Settings:
    """Return application settings (simple env-backed settings).

    In later phases we can switch to pydantic-settings without breaking callers.
    """
    return Settings()
