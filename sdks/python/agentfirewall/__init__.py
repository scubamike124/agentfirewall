"""AgentFirewall Python SDK — wrap tool calls with pre-execution evaluation."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


class AgentFirewallError(Exception):
    def __init__(self, message: str, decision: str, evaluation: dict[str, Any]):
        super().__init__(message)
        self.decision = decision
        self.evaluation = evaluation


@dataclass
class AgentFirewallClient:
    api_key: str
    agent_id: str
    base_url: str = "http://localhost:8787"
    agent_token: Optional[str] = None
    session_id: Optional[str] = None
    throw_on_block: bool = True
    throw_on_approval_required: bool = True
    history: list[dict[str, Any]] = field(default_factory=list)

    def _request(self, path: str, body: dict[str, Any], method: str = "POST") -> dict[str, Any]:
        url = self.base_url.rstrip("/") + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"AgentFirewall HTTP {e.code}: {e.read().decode()}") from e

    def issue_credential(
        self,
        *,
        scopes: Optional[list[str]] = None,
        egress_allowlist: Optional[list[str]] = None,
        ttl: int = 3600,
    ) -> dict[str, Any]:
        data = self._request(
            f"/v1/agents?ttl={ttl}",
            {
                "agent_id": self.agent_id,
                "scopes": scopes,
                "egress_allowlist": egress_allowlist,
            },
        )
        self.agent_token = data.get("token")
        return data

    def evaluate(
        self,
        tool: str,
        parameters: Optional[dict[str, Any]] = None,
        *,
        type: str = "tool_call",
        destination: Optional[str] = None,
        untrusted_content: Optional[list[str]] = None,
        mcp_descriptions: Optional[list[Any]] = None,
    ) -> dict[str, Any]:
        body = {
            "agent": {"agent_id": self.agent_id},
            "agent_token": self.agent_token,
            "action": {
                "type": type,
                "tool": tool,
                "parameters": parameters or {},
                "destination": destination,
            },
            "context": {
                "session_id": self.session_id,
                "prior_actions": self.history[-20:],
                "untrusted_content": untrusted_content or [],
                "mcp_descriptions": mcp_descriptions or [],
            },
            "destination": destination,
        }
        evaluation = self._request("/v1/evaluate", body)
        decision = evaluation.get("decision")
        if decision == "block" and self.throw_on_block:
            raise AgentFirewallError(evaluation.get("explanation", "blocked"), "block", evaluation)
        if decision == "approval_required" and self.throw_on_approval_required:
            raise AgentFirewallError(
                evaluation.get("explanation", "approval required"),
                "approval_required",
                evaluation,
            )
        if decision == "allow":
            self.history.append(body["action"])
        return evaluation

    def inspect_output(self, result: Any, tool: Optional[str] = None) -> dict[str, Any]:
        return self._request(
            "/v1/inspect/output",
            {
                "agent_id": self.agent_id,
                "agent_token": self.agent_token,
                "tool": tool,
                "result": result,
            },
        )

    def gated_fetch(self, url: str, *, execute: bool = True) -> dict[str, Any]:
        if not self.agent_token:
            raise RuntimeError("agent_token required — call issue_credential()")
        return self._request(
            "/v1/gate/http",
            {
                "agent_id": self.agent_id,
                "agent_token": self.agent_token,
                "url": url,
                "execute": execute,
                "session_id": self.session_id,
            },
        )

    def resume_approval(
        self, approval_id: str, resume_token: str, action: dict[str, Any]
    ) -> dict[str, Any]:
        return self._request(
            f"/v1/approvals/{approval_id}/resume",
            {"resume_token": resume_token, "action": action, "destination": action.get("destination")},
        )

    def wrap_tool(self, tool: str, fn: Callable[..., T]) -> Callable[..., T]:
        def wrapped(**kwargs: Any) -> T:
            self.evaluate(tool=tool, parameters=kwargs)
            result = fn(**kwargs)
            out = self.inspect_output(result, tool=tool)
            if out.get("decision") == "block" and self.throw_on_block:
                raise AgentFirewallError(out.get("explanation", "output blocked"), "block", out)
            return out.get("result_redacted", result)  # type: ignore[return-value]

        return wrapped

    def evaluate_trajectory(self, proposed: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        return self._request(
            "/v1/trajectory/evaluate",
            {
                "agent": {"agent_id": self.agent_id},
                "agent_token": self.agent_token,
                "history": [{"action": a} for a in self.history],
                "proposed": proposed,
                "session_id": self.session_id,
            },
        )

    def wait_for_approval(
        self, approval_id: str, *, timeout_ms: int = 120_000, interval_ms: int = 2_000
    ) -> str:
        import time

        deadline = time.time() + timeout_ms / 1000.0
        while time.time() < deadline:
            req = urllib.request.Request(
                self.base_url.rstrip("/") + "/v1/approvals",
                headers={"authorization": f"Bearer {self.api_key}"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for a in data.get("approvals", []):
                if a.get("id") == approval_id and a.get("status") in (
                    "approved",
                    "denied",
                    "expired",
                ):
                    return a["status"]
            time.sleep(interval_ms / 1000.0)
        raise TimeoutError(f"Timed out waiting for approval {approval_id}")
