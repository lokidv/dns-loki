import re
from typing import Optional


def github_zip_url(repo_url: str, branch: str) -> Optional[str]:
    """Return codeload zip URL for a GitHub repo URL and branch.

    Supports:
      - https://github.com/owner/repo(.git)
      - http(s)://github.com/owner/repo
      - git@github.com:owner/repo(.git)
    Returns None for unsupported formats.
    """
    if not repo_url:
        return None
    s = repo_url.strip()

    m_ssh = re.match(r"git@github\.com:([^/]+)/([^/]+)(?:\.git)?$", s)
    if m_ssh:
        owner, repo = m_ssh.group(1), m_ssh.group(2)
        return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"

    m_http = re.search(r"(?:https?://)?(?:www\.)?github\.com/([^/]+)/([^/]+)", s)
    if not m_http:
        return None
    owner, repo = m_http.group(1), m_http.group(2)
    repo = repo[:-4] if repo.endswith('.git') else repo
    return f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
