"""High-level client for the live AgentGrid API."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import AgentKey, b64d, canonical, task_digest, unsigned_card

DEFAULT_BASE_URL = "https://agentgrid-pied.vercel.app"
DEFAULT_SCOPE: dict[str, Any] = {"allowed": ["read"], "max_actions": 3}

Transport = Callable[[str, str, Optional[dict[str, Any]], dict[str, str]], tuple[int, dict[str, Any]]]


class AgentGridError(RuntimeError):
    """Raised for HTTP, transport, or configuration errors."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def default_key_path() -> Path:
    return Path.home() / ".agentgrid" / "credentials.json"


def load_api_key(key_path: Optional[Path] = None) -> Optional[str]:
    env_key = os.environ.get("AGENTGRID_API_KEY", "").strip()
    if env_key:
        return env_key
    path = Path(key_path) if key_path else default_key_path()
    if path.exists():
        try:
            stored = json.loads(path.read_text(encoding="utf-8")).get("api_key", "").strip()
        except (OSError, ValueError):
            return None
        if stored:
            return stored
    return None


def save_api_key(api_key: str, key_path: Optional[Path] = None) -> Path:
    path = Path(key_path) if key_path else default_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"api_key": api_key.strip()}) + "\n", encoding="utf-8")
    _restrict(path)
    return path


def default_pending_path() -> Path:
    return Path.home() / ".agentgrid" / "pending.json"


def save_pending_client(client_id: str, pending_path: Optional[Path] = None) -> Path:
    """Remember which unverified client the next `agrid verify` belongs to."""
    path = Path(pending_path) if pending_path else default_pending_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"client_id": client_id.strip()}) + "\n", encoding="utf-8")
    _restrict(path)
    return path


def load_pending_client(pending_path: Optional[Path] = None) -> Optional[str]:
    path = Path(pending_path) if pending_path else default_pending_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("client_id", "").strip() or None
    except (OSError, ValueError):
        return None


def clear_pending_client(pending_path: Optional[Path] = None) -> None:
    path = Path(pending_path) if pending_path else default_pending_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _restrict(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        # Windows ignores this mode; the file still stays in the user profile.
        pass


def _http_transport(base_url: str) -> Transport:
    def transport(
        method: str, path: str, body: Optional[dict[str, Any]], headers: dict[str, str]
    ) -> tuple[int, dict[str, Any]]:
        request = Request(
            base_url + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method=method,
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                payload = json.loads(raw)
                detail = payload.get("detail", raw)
            except ValueError:
                detail = raw
            return exc.code, {"detail": detail}
        except URLError as exc:
            raise AgentGridError(0, f"Cannot reach {base_url}: {exc.reason}") from exc

    return transport


@dataclass
class Agent:
    """A registered agent plus its local private key."""

    client: "AgentGrid"
    agent_id: str
    name: str
    key: AgentKey
    card: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def card_url(self) -> str:
        return self.client.base_url + "/a/" + self.agent_id

    def verify(self, offline: bool = True) -> dict[str, Any]:
        """Verify the card online and, optionally, offline with published keys."""
        return self.client.verify_card(self.agent_id, offline=offline)

    def handoff_to(
        self,
        target: "Agent",
        *,
        task: str = "a delegated task",
        scope: Optional[dict[str, Any]] = None,
        parent_handoff_id: str = "",
    ) -> dict[str, Any]:
        return self.client.handoff(
            self, target, task=task, scope=scope, parent_handoff_id=parent_handoff_id
        )

    def receipts(self) -> list[dict[str, Any]]:
        return self.client.receipts(self.agent_id).get("receipts", [])


class AgentGrid:
    """Client for signed identity, handoffs, receipts, and statements."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        key_path: Optional[Path] = None,
        transport: Optional[Transport] = None,
    ) -> None:
        self.api_key = api_key or load_api_key(key_path)
        self.base_url = (
            base_url or os.environ.get("AGENTGRID_BASE_URL") or DEFAULT_BASE_URL
        ).rstrip("/")
        self._transport = transport or _http_transport(self.base_url)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]] = None,
        *,
        auth: bool = True,
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if auth:
            if not self.api_key:
                raise AgentGridError(0, "No API key. Run `agrid register` (or `agrid login`) or set AGENTGRID_API_KEY.")
            headers["X-AgentGrid-API-Key"] = self.api_key
        status, payload = self._transport(method, path, body, headers)
        if status >= 400:
            raise AgentGridError(status, str(payload.get("detail", payload)))
        return payload

    # --- Discovery and account -------------------------------------------------
    def register(self, *, email: str, client_id: str = "") -> dict[str, Any]:
        """Create an unverified client; the key is issued only after verification.

        Registration is open self-service; no invite token is required, but a
        real email is. The service emails a 6-digit code and returns no
        ``api_key`` here. Call :meth:`verify_email` with that code.
        """
        if not email.strip():
            raise AgentGridError(0, "A real email is required. Pass email='you@example.com'.")
        body: dict[str, Any] = {"email": email.strip()}
        if client_id:
            body["client_id"] = client_id
        return self._request("POST", "/v1/clients/register", body, auth=False)

    def verify_email(self, client_id: str, code: str) -> dict[str, Any]:
        """Confirm the emailed code; the returned key becomes this client's key."""
        if not client_id or not re.fullmatch(r"\d{6}", code or ""):
            raise AgentGridError(0, "client_id and a 6-digit code are required.")
        result = self._request(
            "POST",
            "/v1/clients/verify-email",
            {"client_id": client_id, "code": code},
            auth=False,
        )
        self.api_key = result["api_key"]
        return result

    def resend_verification(self, client_id: str) -> dict[str, Any]:
        """Request a fresh code for an unverified client (60-second cooldown)."""
        if not client_id:
            raise AgentGridError(0, "client_id is required.")
        return self._request(
            "POST",
            "/v1/clients/resend-verification",
            {"client_id": client_id},
            auth=False,
        )

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health/ready", auth=False)

    def me(self) -> dict[str, Any]:
        return self._request("GET", "/v1/clients/me")

    def public_keys(self) -> dict[str, Any]:
        return self._request("GET", "/v1/agents/public-key", auth=False)

    # --- Agents ----------------------------------------------------------------
    def create_agent(
        self,
        name: str,
        *,
        capabilities: tuple[str, ...] | list[str] = ("read",),
        description: str = "",
        key: Optional[AgentKey] = None,
    ) -> Agent:
        agent_key = key or AgentKey.generate()
        card = self._request(
            "POST",
            "/v1/agents",
            {
                "name": name,
                "description": description,
                "capabilities": list(capabilities),
                "public_key": agent_key.public_b64,
            },
        )
        return Agent(
            client=self,
            agent_id=card["agent_id"],
            name=name,
            key=agent_key,
            card=card,
        )

    def card(self, agent_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/agents/{agent_id}.json", auth=False)

    def verify_card(self, agent_id: str, *, offline: bool = True) -> dict[str, Any]:
        online = self._request("GET", f"/v1/agents/{agent_id}/verify", auth=False)
        result: dict[str, Any] = {
            "agent_id": agent_id,
            "online": bool(online.get("signature_valid")),
            "status": online.get("status"),
        }
        if offline:
            card = self.card(agent_id)
            keys = self.public_keys()
            candidates = [keys.get("public_key", "")]
            if keys.get("previous_public_key"):
                candidates.append(keys["previous_public_key"])
            message = canonical(unsigned_card(card))
            signature = b64d(card.get("signature", ""))
            result["offline"] = False
            for candidate in candidates:
                if not candidate:
                    continue
                try:
                    Ed25519PublicKey.from_public_bytes(b64d(candidate)).verify(signature, message)
                    result["offline"] = True
                    break
                except Exception:
                    continue
        return result

    # --- Handoffs and receipts -------------------------------------------------
    def handoff(
        self,
        from_agent: Agent,
        to_agent: Agent,
        *,
        task: str = "a delegated task",
        task_hash: Optional[str] = None,
        scope: Optional[dict[str, Any]] = None,
        parent_handoff_id: str = "",
    ) -> dict[str, Any]:
        import uuid

        payload = {
            "v": 1,
            "handoff_id": "h_" + uuid.uuid4().hex,
            "from_agent_id": from_agent.agent_id,
            "to_agent_id": to_agent.agent_id,
            "task_hash": task_hash or task_digest(task),
            "scope": dict(scope or DEFAULT_SCOPE),
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "parent_handoff_id": parent_handoff_id,
        }
        signature = from_agent.key.sign(payload)
        return self._request(
            "POST",
            f"/v1/agents/{from_agent.agent_id}/handoffs",
            {**payload, "signature": signature},
        )

    def receipts(self, agent_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/agents/{agent_id}/receipts")

    # --- Billing ---------------------------------------------------------------
    def statement(self, cycle_start: Optional[str] = None) -> dict[str, Any]:
        path = "/v1/billing/statement"
        if cycle_start:
            path += "?cycle_start=" + cycle_start
        return self._request("GET", path)

    # --- Convenience -----------------------------------------------------------
    def quickstart(self) -> dict[str, Any]:
        """Register two agents, verify a card, and record a signed handoff."""
        planner = self.create_agent("Planner", capabilities=("plan",), description="Breaks work into tasks")
        worker = self.create_agent("Worker", capabilities=("read",), description="Executes approved tasks")
        verification = self.verify_card(planner.agent_id)
        receipt = planner.handoff_to(worker, task="summarize the quarterly report")
        return {
            "from_agent": planner,
            "to_agent": worker,
            "verification": verification,
            "receipt": receipt,
            "receipt_count": len(worker.receipts()),
        }
