from typing import Dict, List, Optional

from pydantic import BaseModel


class NodeInModel(BaseModel):
    ip: Optional[str] = None
    role: str  # dns|proxy
    enabled: Optional[bool] = None
    agents_version_applied: Optional[int] = None
    ts: Optional[float] = None
    diag: Optional[dict] = None


def upsert_node_in_state(state: Dict, payload: NodeInModel, request_ip: str) -> None:
    """Upsert node record in state with the same logic used previously in controller/api.py."""
    ip_str = payload.ip if payload.ip is not None else request_ip
    n_payload = {
        "ip": ip_str,
        "role": payload.role,
        "agents_version_applied": payload.agents_version_applied,
        "ts": payload.ts,
        "diag": payload.diag,
    }
    found = False
    for x in state["nodes"]:
        if str(x["ip"]) == ip_str:
            old_diag = x.get("diag")
            old_ver = x.get("agents_version_applied")
            x.update(n_payload)
            if x.get("diag") is None and old_diag is not None:
                x["diag"] = old_diag
            incoming_ver = n_payload.get("agents_version_applied")
            if incoming_ver is None:
                if old_ver is not None:
                    x["agents_version_applied"] = old_ver
            else:
                try:
                    old_i = int(old_ver) if old_ver is not None else 0
                except Exception:
                    old_i = 0
                try:
                    inc_i = int(incoming_ver)
                except Exception:
                    inc_i = old_i
                x["agents_version_applied"] = max(old_i, inc_i)
            found = True
    if not found:
        if n_payload.get("agents_version_applied") is None:
            n_payload["agents_version_applied"] = 0
        if n_payload.get("diag") is None:
            n_payload["diag"] = {}
        if payload.enabled is None:
            n_payload["enabled"] = True
        else:
            n_payload["enabled"] = bool(payload.enabled)
        state["nodes"].append(n_payload)


def set_node_enabled(state: Dict, ip: str, enabled: bool) -> None:
    for x in state["nodes"]:
        if str(x["ip"]) == ip:
            x["enabled"] = bool(enabled)
