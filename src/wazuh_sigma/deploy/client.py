"""Low-level Wazuh API client and HTTP transport helpers."""

from __future__ import annotations

import base64
import json
import re
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

from wazuh_sigma.wazuh_contract import (
    validate_remote_rule_filename as validate_remote_rule_filename_contract,
    validate_wazuh_host as validate_wazuh_host_contract,
)


ApiPayload = dict[str, Any]


class WazuhApiError(RuntimeError):
    """Raised when the Wazuh API returns an error or an unexpected response."""


def validate_wazuh_host(host: str) -> str:
    """Return a normalized Wazuh API host after validating it is an HTTP(S) URL."""
    return validate_wazuh_host_contract(host, error_type=WazuhApiError)


def validate_remote_rule_filename(remote_file: str) -> str:
    """Return a safe Wazuh custom-rule filename."""
    return validate_remote_rule_filename_contract(remote_file, error_type=WazuhApiError)


@dataclass(frozen=True)
class HttpResponse:
    """Minimal HTTP response object used by the deploy client."""

    status: int
    body: bytes
    headers: Mapping[str, str]


Transport = Callable[[str, str, bytes | None, Mapping[str, str]], HttpResponse]


class WazuhApiClient:
    """Small Wazuh API client for rule-file deployment."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        timeout: int = 30,
        verify_tls: bool = True,
        ca_bundle: str | None = None,
        transport: Transport | None = None,
    ) -> None:
        if timeout <= 0:
            raise WazuhApiError("Wazuh API timeout must be a positive integer")
        self.host = validate_wazuh_host(host)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.ca_bundle = ca_bundle
        self.transport = transport or self._urllib_transport
        self.token: str | None = None

    def authenticate(self) -> str:
        """Authenticate with basic auth and store the returned JWT token."""
        credentials = f"{self.username}:{self.password}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
            "Accept": "application/json",
        }
        response = self._request("POST", "security/user/authenticate", headers=headers)
        token = response.get("data", {}).get("token")
        if not token:
            raise WazuhApiError("Wazuh authentication response did not include a token")
        self.token = str(token)
        return self.token

    def upload_rule_file(self, local_file, remote_file: str, overwrite: bool = True) -> ApiPayload:
        """Upload or replace a custom Wazuh rule file."""
        if not local_file.is_file():
            raise WazuhApiError(f"Rule file does not exist: {local_file}")
        return self.upload_rule_bytes(local_file.read_bytes(), remote_file, overwrite=overwrite)

    def upload_rule_bytes(self, body: bytes, remote_file: str, overwrite: bool = True) -> ApiPayload:
        """Upload or replace a custom Wazuh rule file from bytes."""
        remote_file = validate_remote_rule_filename(remote_file)
        query = urlencode({"overwrite": str(overwrite).lower()})
        endpoint = f"rules/files/{remote_file}?{query}"
        headers = self._bearer_headers({"Content-Type": "application/xml"})
        return self._request("PUT", endpoint, body=body, headers=headers)

    def download_rule_file(self, remote_file: str) -> bytes:
        """Download a custom Wazuh rule file as raw bytes."""
        remote_file = validate_remote_rule_filename(remote_file)
        query = urlencode({"raw": "true"})
        endpoint = f"rules/files/{remote_file}?{query}"
        return self._request_raw("GET", endpoint, headers=self._bearer_headers())

    def validate_manager_configuration(self) -> ApiPayload:
        """Ask Wazuh to validate the manager configuration after upload."""
        return self._request(
            "GET",
            "manager/configuration/validation",
            headers=self._bearer_headers(),
        )

    def restart_manager(self) -> ApiPayload:
        """Restart the Wazuh manager so uploaded rule files are loaded."""
        return self._request("PUT", "manager/restart", headers=self._bearer_headers())

    def verify_rule_file(self, remote_file: str) -> ApiPayload:
        """Return Wazuh rules filtered by the deployed filename."""
        remote_file = validate_remote_rule_filename(remote_file)
        query = urlencode({"filename": remote_file, "limit": 1})
        return self._request("GET", f"rules?{query}", headers=self._bearer_headers())

    def find_rules_by_ids(self, rule_ids: Iterable[int], *, limit: int | None = None) -> ApiPayload:
        """Return Wazuh rules matching the supplied rule IDs."""
        normalized_ids = sorted({int(rule_id) for rule_id in rule_ids})
        if not normalized_ids:
            return {
                "data": {
                    "affected_items": [],
                    "total_affected_items": 0,
                    "failed_items": [],
                    "total_failed_items": 0,
                },
                "error": 0,
            }
        query = urlencode(
            {
                "rule_ids": ",".join(str(rule_id) for rule_id in normalized_ids),
                "limit": limit or max(len(normalized_ids) * 2, 1),
            }
        )
        return self._request("GET", f"rules?{query}", headers=self._bearer_headers())

    def _bearer_headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        if not self.token:
            raise WazuhApiError("Client is not authenticated")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> ApiPayload:
        url = urljoin(self.host, endpoint)
        response = self.transport(method, url, body, headers or {})
        if response.status < 200 or response.status >= 300:
            raise WazuhApiError(f"Wazuh API {method} {endpoint} failed with HTTP {response.status}")
        if not response.body:
            return {}
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise WazuhApiError(f"Wazuh API {method} {endpoint} returned non-JSON response") from error
        if not isinstance(payload, dict):
            raise WazuhApiError(f"Wazuh API {method} {endpoint} returned a non-object JSON response")
        if payload.get("error") not in (None, 0):
            detail = payload.get("message") or payload.get("detail") or "response payload omitted"
            raise WazuhApiError(
                f"Wazuh API {method} {endpoint} returned error {payload.get('error')}: "
                f"{redact_sensitive_text(str(detail))}"
            )
        return payload

    def _request_raw(
        self,
        method: str,
        endpoint: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        url = urljoin(self.host, endpoint)
        response = self.transport(method, url, body, headers or {})
        if response.status < 200 or response.status >= 300:
            raise WazuhApiError(f"Wazuh API {method} {endpoint} failed with HTTP {response.status}")
        return response.body

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
            with urlopen(request, timeout=self.timeout, context=context) as response:
                return HttpResponse(
                    status=response.status,
                    body=response.read(),
                    headers=dict(response.headers.items()),
                )
        except HTTPError as error:
            body_bytes = error.read()
            body_preview = redact_sensitive_text(body_bytes.decode("utf-8", "replace"))
            raise WazuhApiError(
                f"Wazuh API request failed with HTTP {error.code}: {body_preview}"
            ) from error
        except URLError as error:
            raise WazuhApiError(f"Wazuh API connection failed: {error.reason}") from error

    def _ssl_context(self, url: str) -> ssl.SSLContext | None:
        if urlparse(url).scheme != "https":
            return None
        if not self.verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        if self.ca_bundle:
            return ssl.create_default_context(cafile=self.ca_bundle)
        return ssl.create_default_context()


def redact_sensitive_text(value: str) -> str:
    """Return API diagnostic text with common credential-bearing values redacted."""
    redacted = re.sub(
        r"(?i)\b(authorization)\s*[:=]\s*(basic|bearer)\s+[A-Za-z0-9._~+/=-]+",
        r"\1: <redacted>",
        value,
    )
    redacted = re.sub(
        r'(?i)("?(?:password|token|api[_-]?key|authorization)"?\s*[:=]\s*)("[^"]*"|\'[^\']*\'|[^\s,}]+)',
        r"\1<redacted>",
        redacted,
    )
    return redacted
