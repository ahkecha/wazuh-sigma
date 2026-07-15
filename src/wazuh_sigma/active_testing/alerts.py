"""Alert-store polling for autonomous active detection tests."""

from __future__ import annotations

import base64
import json
import ssl
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from wazuh_sigma.active_testing.models import ActiveTestError, ExpectedAlertSpec
from wazuh_sigma.deploy.client import HttpResponse, Transport, redact_sensitive_text
from wazuh_sigma.wazuh_contract import validate_wazuh_host


class AlertVerificationError(ActiveTestError):
    """Raised when expected Wazuh alert evidence is not found."""


@dataclass(frozen=True)
class AlertSearchConfig:
    """Wazuh indexer search settings."""

    base_url: str
    index: str = "wazuh-alerts-*"
    username: str = ""
    password: str = ""
    timeout: int = 30
    verify_tls: bool = True
    ca_bundle: str | None = None


class WazuhIndexerAlertClient:
    """Tiny OpenSearch-compatible client for querying Wazuh alerts."""

    def __init__(
        self,
        config: AlertSearchConfig,
        *,
        transport: Transport | None = None,
    ) -> None:
        if config.timeout <= 0:
            raise AlertVerificationError("alert search timeout must be a positive integer")
        if not config.username or not config.password:
            raise AlertVerificationError("Wazuh indexer username and password are required")
        self.config = AlertSearchConfig(
            base_url=validate_wazuh_host(config.base_url, error_type=AlertVerificationError).rstrip("/") + "/",
            index=config.index,
            username=config.username,
            password=config.password,
            timeout=config.timeout,
            verify_tls=config.verify_tls,
            ca_bundle=config.ca_bundle,
        )
        self.transport = transport or self._urllib_transport

    def wait_for_alert(
        self,
        expected: ExpectedAlertSpec,
        *,
        marker: str,
        timeout: int,
        poll_interval: int,
    ) -> Mapping[str, Any]:
        """Poll the alert index until expected evidence appears."""
        deadline = time.monotonic() + timeout
        query = build_alert_query(expected, marker=marker)
        last_payload: Mapping[str, Any] = {}
        while time.monotonic() < deadline:
            last_payload = self.search(query)
            hits = _extract_hits(last_payload)
            if hits:
                return {
                    "matched": True,
                    "hit_count": len(hits),
                    "first_hit": hits[0],
                    "query": query,
                }
            time.sleep(poll_interval)
        raise AlertVerificationError(
            f"expected Wazuh alert was not found within {timeout} seconds: {query}"
        )

    def search(self, query: Mapping[str, Any]) -> Mapping[str, Any]:
        """Run a raw OpenSearch query against the configured Wazuh alert index."""
        endpoint = f"{self.config.index}/_search"
        body = json.dumps(query).encode("utf-8")
        response = self.transport(
            "POST",
            urljoin(self.config.base_url, endpoint),
            body,
            self._headers({"Content-Type": "application/json"}),
        )
        if response.status < 200 or response.status >= 300:
            raise AlertVerificationError(f"Wazuh alert search failed with HTTP {response.status}")
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise AlertVerificationError("Wazuh alert search returned non-JSON response") from error
        if not isinstance(payload, Mapping):
            raise AlertVerificationError("Wazuh alert search returned a non-object JSON response")
        return payload

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        credentials = f"{self.config.username}:{self.config.password}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _urllib_transport(
        self,
        method: str,
        url: str,
        body: bytes | None,
        headers: Mapping[str, str],
    ) -> HttpResponse:
        request = Request(url, data=body, headers=dict(headers), method=method)
        context = self._ssl_context(url)
        try:
            with urlopen(request, timeout=self.config.timeout, context=context) as response:
                return HttpResponse(
                    status=response.status,
                    body=response.read(),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as error:
            body_bytes = error.read()
            body_preview = redact_sensitive_text(body_bytes.decode("utf-8", "replace"))
            raise AlertVerificationError(
                f"Wazuh alert search failed with HTTP {error.code}: {body_preview}"
            ) from error
        except URLError as error:
            raise AlertVerificationError(f"Wazuh alert search connection failed: {error.reason}") from error

    def _ssl_context(self, url: str) -> ssl.SSLContext | None:
        if urlparse(url).scheme != "https":
            return None
        if not self.config.verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        if self.config.ca_bundle:
            return ssl.create_default_context(cafile=self.config.ca_bundle)
        return ssl.create_default_context()


def build_alert_query(expected: ExpectedAlertSpec, *, marker: str) -> Mapping[str, Any]:
    """Build an OpenSearch bool query for expected Wazuh alert evidence."""
    if expected.query is not None:
        return expected.query

    filters: list[Mapping[str, Any]] = []
    if expected.rule_id:
        filters.append({"term": {"rule.id": expected.rule_id}})
    if expected.rule_group:
        filters.append({"term": {"rule.groups": expected.rule_group}})

    expected_marker = expected.marker or marker
    if expected_marker:
        filters.append(
            {
                "query_string": {
                    "query": f'"{_escape_query_string(expected_marker)}"',
                    "fields": ["full_log", "data.*", "win.eventdata.*", "rule.description"],
                }
            }
        )

    return {
        "size": 3,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": filters,
            }
        },
    }


def _escape_query_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _extract_hits(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    hits = payload.get("hits")
    if not isinstance(hits, Mapping):
        return []
    items = hits.get("hits")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, Mapping)]
