# © 2026 TrinTech Digital Defense — authorized defensive use only
"""Wazuh read-only connector skeleton (Phase 6).

Uses the Wazuh API (manager) alerts endpoint when credentials are configured.
Designed for a safe lab / pilot tenant only. No write or active response actions.

Config keys (under connector config or env):
  url          — e.g. https://wazuh.example:55000
  user         — API user (read-only role preferred)
  password     — API password
  verify_tls   — default True; set false only for lab self-signed certs
  agent_id     — optional filter

Environment fallbacks:
  WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlencode

from modules.connectors.base import (
    Connector,
    ConnectorHealth,
    NormalizedAlert,
    Severity,
    utc_now_iso,
)


class WazuhConnector(Connector):
    name = "wazuh"

    def __init__(self, config: Optional[dict] = None):
        super().__init__(config)
        c = self.config
        self.url = (c.get("url") or os.environ.get("WAZUH_URL") or "").rstrip("/")
        self.user = c.get("user") or os.environ.get("WAZUH_USER") or ""
        self.password = c.get("password") or os.environ.get("WAZUH_PASSWORD") or ""
        self.verify_tls = c.get("verify_tls", True)
        if isinstance(self.verify_tls, str):
            self.verify_tls = self.verify_tls.lower() not in ("0", "false", "no")
        self.agent_id = c.get("agent_id") or ""
        self._token: Optional[str] = None
        self._last_success: Optional[str] = None

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if self.verify_tls:
            return None  # default verification
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _request(self, method: str, path: str, data: Optional[dict] = None, auth_token: bool = True) -> dict:
        if not self.url:
            raise RuntimeError("Wazuh URL not configured")
        headers = {"Content-Type": "application/json"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
        if auth_token and self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(
            self.url + path,
            data=body,
            headers=headers,
            method=method,
        )
        # Basic auth for token endpoint
        if not auth_token and self.user and self.password:
            import base64

            token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")

        ctx = self._ssl_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            return json.loads(resp.read().decode() or "{}")

    def _ensure_token(self) -> None:
        if self._token:
            return
        if not (self.url and self.user and self.password):
            raise RuntimeError("Wazuh credentials not configured")
        # Wazuh API v4: POST /security/user/authenticate
        try:
            out = self._request("POST", "/security/user/authenticate", auth_token=False)
            self._token = (out.get("data") or {}).get("token") or out.get("token")
            if not self._token:
                raise RuntimeError("No token in Wazuh auth response")
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Wazuh auth failed: HTTP {e.code}") from e

    def health_check(self) -> ConnectorHealth:
        if not self.url:
            return ConnectorHealth(
                name=self.name,
                ok=False,
                message="not configured (set url/user/password)",
            )
        try:
            self._ensure_token()
            # lightweight check
            self._request("GET", "/")
            self._last_success = utc_now_iso()
            return ConnectorHealth(
                name=self.name,
                ok=True,
                last_success=self._last_success,
                message="ok",
                detail={"url": self.url},
            )
        except Exception as e:
            return ConnectorHealth(name=self.name, ok=False, message=str(e))

    def normalize(self, raw_event: dict) -> Optional[NormalizedAlert]:
        if not isinstance(raw_event, dict):
            return None
        # Wazuh alert shapes vary; support common fields
        data = raw_event.get("data") if isinstance(raw_event.get("data"), dict) else raw_event
        rule = data.get("rule") or raw_event.get("rule") or {}
        agent = data.get("agent") or raw_event.get("agent") or {}
        alert_id = str(
            data.get("id")
            or raw_event.get("id")
            or data.get("_id")
            or rule.get("id")
            or ""
        )
        title = (
            rule.get("description")
            or data.get("title")
            or raw_event.get("title")
            or f"Wazuh rule {rule.get('id', '?')}"
        )
        if not title:
            return None
        level = rule.get("level") or data.get("level") or raw_event.get("level")
        ts = (
            data.get("timestamp")
            or data.get("@timestamp")
            or raw_event.get("timestamp")
            or utc_now_iso()
        )
        return NormalizedAlert(
            id=f"wazuh-{alert_id or title[:40]}",
            source=self.name,
            source_event_id=alert_id or title[:80],
            severity=Severity.from_raw(level),
            title=str(title)[:300],
            occurred_at=str(ts),
            received_at=utc_now_iso(),
            status="new",
            asset_id=str(agent.get("id") or agent.get("name") or ""),
            rule_id=str(rule.get("id") or ""),
            detail=str(data.get("full_log") or data.get("decoder") or "")[:1000],
            extra={"agent": agent, "rule": {"id": rule.get("id"), "level": rule.get("level")}},
        )

    def fetch_events(
        self,
        cursor: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> tuple[list[NormalizedAlert], Optional[str]]:
        limit = max(1, min(int(limit or 100), 500))
        if not self.url:
            return [], None

        self._ensure_token()
        # Wazuh manager API: GET /alerts or indexer-backed queries vary by version.
        # Use a conservative query shape; operators should point at a lab instance.
        params: dict[str, Any] = {"limit": limit, "sort": "-timestamp"}
        if since:
            params["q"] = f"timestamp>{since}"
        if self.agent_id:
            params["agents_list"] = self.agent_id
        if cursor:
            params["offset"] = cursor

        path = "/alerts?" + urlencode({k: v for k, v in params.items() if v is not None})
        try:
            out = self._request("GET", path)
        except Exception:
            # Fallback path used by some deployments
            path = "/security/events?" + urlencode({"limit": limit})
            out = self._request("GET", path)

        items = out.get("data") or out.get("alerts") or out.get("affected_items") or []
        if isinstance(items, dict):
            items = items.get("affected_items") or items.get("items") or []

        alerts: list[NormalizedAlert] = []
        for raw in items:
            n = self.normalize(raw if isinstance(raw, dict) else {})
            if n:
                alerts.append(n)

        self._last_success = utc_now_iso()
        next_cursor = None
        if len(items) >= limit:
            try:
                off = int(cursor or 0) + len(items)
                next_cursor = str(off)
            except ValueError:
                next_cursor = None
        return alerts, next_cursor
