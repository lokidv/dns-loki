from typing import List


def normalize_domain(d: str) -> str:
    """Normalize a single domain: trim, lowercase, remove leading *.
    Returns empty string if invalid/empty after normalization.
    """
    if d is None:
        return ""
    s = str(d).strip().lower()
    if not s:
        return ""
    if s.startswith("*."):
        s = s[2:]
    return s


def normalize_domains(domains: List[str]) -> List[str]:
    """Normalize and deduplicate a list of domains, preserving order of first occurrence."""
    out: List[str] = []
    seen = set()
    for d in domains or []:
        nd = normalize_domain(d)
        if nd and nd not in seen:
            seen.add(nd)
            out.append(nd)
    return out
