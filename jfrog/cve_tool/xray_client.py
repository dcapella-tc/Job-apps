from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


class XrayClientError(RuntimeError):
    """Raised when an Xray API call fails."""


@dataclass
class XrayClientConfig:
    base_url: str
    access_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    verify_ssl: bool = True


class XrayClient:
    """
    Thin wrapper over the JFrog Xray REST APIs used for CVE search.
    """

    def __init__(
        self,
        base_url: str,
        access_token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 60,
    ) -> None:
        if not base_url:
            raise ValueError("base_url must not be empty.")

        self.config = XrayClientConfig(
            base_url=base_url.rstrip("/"),
            access_token=access_token,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
        )
        self._timeout = timeout

        self._session = requests.Session()
        self._session.verify = verify_ssl

        headers = {
            "Accept": "application/json",
        }
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        self._session.headers.update(headers)

        if not access_token and username and password:
            self._session.auth = (username, password)

    # --------------------------------------------------------------------- #
    # Low-level helpers
    # --------------------------------------------------------------------- #
    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    def _request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = self._url(path)
        try:
            response = self._session.request(
                method=method.upper(),
                url=url,
                json=json,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            raise XrayClientError(f"Request to {url} failed: {exc}") from exc

        if not response.ok:
            snippet = response.text[:500]
            raise XrayClientError(
                f"Xray API call {method} {url} failed with status {response.status_code}: {snippet}"
            )

        if not response.content:
            return {}

        try:
            return response.json()
        except ValueError as exc:
            raise XrayClientError(
                f"Failed to decode JSON response from {method} {url}: {exc}"
            ) from exc

    # --------------------------------------------------------------------- #
    # CVE report APIs
    # --------------------------------------------------------------------- #
    def create_cve_report(
        self,
        cve_id: str,
        filters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Start a CVE search report for the given CVE and return the report ID.

        The exact payload shape can be tuned as needed; here we send a minimal
        body with the CVE and optional filters.
        """
        payload: Dict[str, Any] = {"cves": [cve_id]}
        if filters:
            payload["filters"] = filters

        data = self._request("POST", "/xray/api/v1/reports/cveSearch", json=payload)

        # Different Xray versions may return slightly different keys.
        report_id = data.get("id") or data.get("report_id")
        if not report_id:
            raise XrayClientError(
                f"Unexpected response from create_cve_report, could not find report id in: {data!r}"
            )
        return str(report_id)

    def get_cve_report(self, report_id: str) -> Dict[str, Any]:
        """
        Retrieve the current state of a CVE search report.

        The API is invoked as a POST to /xray/api/v1/reports/cveSearch/{id}.
        """
        if not report_id:
            raise ValueError("report_id must not be empty.")

        path = f"/xray/api/v1/reports/cveSearch/{report_id}"
        return self._request("POST", path, json={})

    def run_cve_report(
        self,
        cve_id: str,
        poll_interval: int = 5,
        timeout: int = 300,
        filters: Optional[Dict[str, Any]] = None,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Convenience wrapper to create a CVE report and poll until completion.

        Returns the final report payload when completed.
        """
        report_id = self.create_cve_report(cve_id=cve_id, filters=filters)

        deadline = time.time() + timeout
        last_status: Optional[str] = None

        while time.time() < deadline:
            report = self.get_cve_report(report_id)
            status = str(report.get("status", "")).lower()

            if verbose and status and status != last_status:
                print(f"[Xray] Report {report_id} status: {status}")
                last_status = status

            if status in {"completed", "done", "ready"}:
                return report
            if status in {"failed", "error"}:
                raise XrayClientError(
                    f"CVE report {report_id} failed with status {status}: {report!r}"
                )

            time.sleep(max(1, poll_interval))

        raise XrayClientError(
            f"Timed out waiting for CVE report {report_id} to complete after {timeout} seconds."
        )

    # --------------------------------------------------------------------- #
    # Enrichment APIs
    # --------------------------------------------------------------------- #
    def search_components_by_cves(self, cves: List[str]) -> Dict[str, Any]:
        """
        Query the /xray/api/v1/component/searchByCves endpoint for additional
        component-level detail about the given CVEs.
        """
        if not cves:
            return {}
        payload = {"cves": cves}
        return self._request("POST", "/xray/api/v1/component/searchByCves", json=payload)

    def get_violations_for_cves(self, cves: List[str]) -> Dict[str, Any]:
        """
        Query the optional /xray/api/v1/violations endpoint for violations
        associated with the given CVEs.
        """
        if not cves:
            return {}
        payload = {"cves": cves}
        return self._request("POST", "/xray/api/v1/violations", json=payload)

