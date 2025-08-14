import os
import shutil
import subprocess
import tempfile
import zipfile
from typing import Generator, Optional
from urllib.request import urlopen

from .git_service import github_zip_url
from .fs_service import copy_tree


def iter_codeload_zip(repo_url: str, branch: str, *, chunk_size: int = 1024 * 64, timeout: int = 45) -> Generator[bytes, None, None]:
    """Yield chunks of a GitHub codeload zip stream for repo/branch.

    Raises ValueError if repo_url is unsupported.
    """
    url = github_zip_url(repo_url, branch)
    if not url:
        raise ValueError("Unsupported repo URL (only GitHub is supported)")

    with urlopen(url, timeout=timeout) as resp:  # nosec - trusted codeload domain
        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            yield chunk


def perform_self_update(code_repo: Optional[str], code_branch: Optional[str]) -> dict:
    """Download latest code bundle and update controller files/UI, then restart service.

    Mirrors legacy behavior: updates controller/api.py, optional requirements.txt, and controller/ui.
    """
    repo = code_repo or "https://github.com/lokidv/dns-loki.git"
    branch = code_branch or "main"

    url = github_zip_url(repo, branch)
    if not url:
        raise ValueError("Unsupported repo URL (only GitHub is supported)")

    tmpdir = tempfile.mkdtemp(prefix="dns_loki_upd_")
    zip_path = os.path.join(tmpdir, "src.zip")
    try:
        # Download archive
        with urlopen(url, timeout=30) as resp, open(zip_path, "wb") as f:  # nosec - trusted codeload domain
            shutil.copyfileobj(resp, f)
        # Extract
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmpdir)
        # Locate extracted root (prefer one containing controller/api.py)
        root = None
        for name in os.listdir(tmpdir):
            p = os.path.join(tmpdir, name)
            if os.path.isdir(p):
                if os.path.exists(os.path.join(p, "controller", "api.py")):
                    root = p
                    break
                if root is None:
                    root = p
        if not root:
            raise RuntimeError("Cannot locate extracted source root (zip format unexpected)")

        # Overlay-copy entire controller module into /opt/dns-proxy/controller
        controller_src = os.path.join(root, "controller")
        dst_root = "/opt/dns-proxy/controller"
        # Copy top-level files and subdirs (exclude venv and caches)
        for name in os.listdir(controller_src):
            if name in {"venv", "__pycache__", ".pytest_cache"}:
                continue
            src_path = os.path.join(controller_src, name)
            dst_path = os.path.join(dst_root, name)
            if os.path.isdir(src_path):
                if name == "ui":
                    # Replace UI fully to avoid stale assets
                    if os.path.isdir(dst_path):
                        shutil.rmtree(dst_path)
                    copy_tree(src_path, dst_path)
                else:
                    copy_tree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)

        # Best-effort dependencies upgrade
        try:
            req_file = os.path.join(dst_root, "requirements.txt")
            if os.path.exists(req_file):
                subprocess.run([
                    "/opt/dns-proxy/controller/venv/bin/pip", "install", "-r", req_file
                ], check=False)
        except Exception:
            pass
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Restart controller in background
    try:
        subprocess.Popen(["bash", "-lc", "sleep 1; systemctl restart dns-proxy-controller"])  # nosec
    except Exception:
        pass

    return {"ok": True, "restarting": True}
