#!/usr/bin/env python3
"""Collect credential-free Keycloak activation read-back evidence.

This utility is intentionally read-only. The only POST it permits is the OAuth2
client-credentials token request used to authenticate subsequent Admin API GETs.
It never PUTs, PATCHes, DELETEs, creates clients, changes realms, or enables the
production mutation gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class CertificationError(RuntimeError):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CertificationError("redirects are forbidden during activation read-back")


def load_json(path: str | Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_absolute():
        target = ROOT / target
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertificationError(f"unable to load certification input: {target.relative_to(ROOT)}") from exc


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_https(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise CertificationError("activation read-back requires credential-free HTTPS URLs")


def request_json(
    method: str,
    url: str,
    *,
    token: str | None = None,
    form: dict[str, str] | None = None,
) -> tuple[int, Any]:
    method = method.upper()
    if method not in {"GET", "POST"}:
        raise CertificationError("activation read-back permits only GET and OAuth token POST")
    if method == "GET" and form is not None:
        raise CertificationError("GET requests cannot contain a form body")
    require_https(url)

    body = urlencode(form).encode("utf-8") if form is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token

    request = Request(url, data=body, headers=headers, method=method)
    opener = build_opener(NoRedirects())
    try:
        response = opener.open(request, timeout=30)
        status = int(response.getcode())
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
    except (URLError, OSError) as exc:
        raise CertificationError("activation read-back network request failed") from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise CertificationError("activation read-back response exceeded size limit")
    if 300 <= status < 400:
        raise CertificationError("activation read-back redirects are forbidden")
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificationError("activation read-back received malformed JSON") from exc
    return status, payload


def project_client(source: dict[str, Any], allowlist: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    top_level = allowlist.get("topLevelFields")
    attribute_fields = allowlist.get("attributeFields")
    if not isinstance(top_level, list) or not isinstance(attribute_fields, list):
        raise CertificationError("invalid client export allowlist")

    for key in top_level:
        if key not in source:
            raise CertificationError(f"live client is missing managed field: {key}")
        if key == "attributes":
            attributes = source.get("attributes")
            if not isinstance(attributes, dict):
                raise CertificationError("live client attributes are malformed")
            missing = [name for name in attribute_fields if name not in attributes]
            if missing:
                raise CertificationError("live client is missing managed attributes")
            projected[key] = {name: attributes[name] for name in attribute_fields}
        else:
            projected[key] = source[key]
    return projected


def repository_sha(explicit: str | None = None) -> str:
    candidate = explicit or os.environ.get("GITHUB_SHA", "")
    if not candidate:
        try:
            candidate = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise CertificationError("repository SHA is required") from exc
    candidate = candidate.strip()
    if not SHA_RE.fullmatch(candidate):
        raise CertificationError("repository SHA must be an exact 40-character lowercase commit SHA")
    return candidate


def certify(
    environment: str,
    admin_client_id: str,
    admin_client_secret: str,
    repo_sha: str,
    *,
    transport: Callable[..., tuple[int, Any]] = request_json,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    contract = load_json("config/certification/activation-readback.json")
    if environment not in {"staging", "production"} or environment not in contract.get("environments", {}):
        raise CertificationError("environment must be exactly staging or production")
    if not admin_client_id or not admin_client_secret:
        raise CertificationError("read-back credentials are required")
    if contract.get("mutationAllowed") is not False:
        raise CertificationError("activation read-back contract must remain mutation-disabled")

    repo_sha = repository_sha(repo_sha)
    env_contract = contract["environments"][environment]
    endpoints = load_json(env_contract["endpointContractPath"])
    desired = load_json(contract["desiredClientPath"])
    allowlist = load_json(contract["exportAllowlistPath"])

    expected_client_id = contract.get("clientId")
    if expected_client_id != "klyrow-portal" or desired.get("clientId") != expected_client_id:
        raise CertificationError("Klyrow activation target changed unexpectedly")
    if desired.get("redirectUris") != ["https://klyrow.com/"]:
        raise CertificationError("Klyrow redirect URI must remain exact")
    if allowlist.get("clientId") != expected_client_id:
        raise CertificationError("Klyrow export allowlist does not match the activation target")

    discovery_url = endpoints["discoveryUrl"]
    jwks_url = endpoints["jwksUri"]
    issuer = endpoints["issuer"]
    admin_base = endpoints["adminApiBaseUrl"].rstrip("/")
    admin_realm = endpoints["adminAuthenticationRealm"]
    for url in (discovery_url, jwks_url, issuer, admin_base):
        require_https(url)

    status, discovery = transport("GET", discovery_url)
    if status != 200 or not isinstance(discovery, dict):
        raise CertificationError("OIDC discovery read-back failed")
    if discovery.get("issuer") != issuer or discovery.get("jwks_uri") != jwks_url:
        raise CertificationError("OIDC discovery does not match the selected environment contract")

    status, jwks = transport("GET", jwks_url)
    if status != 200 or not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        raise CertificationError("JWKS read-back failed")

    token_url = f"{admin_base}/realms/{quote(admin_realm, safe='')}/protocol/openid-connect/token"
    status, token_response = transport(
        "POST",
        token_url,
        form={
            "grant_type": "client_credentials",
            "client_id": admin_client_id,
            "client_secret": admin_client_secret,
        },
    )
    if status != 200 or not isinstance(token_response, dict):
        raise CertificationError("read-back identity authentication failed")
    access_token = token_response.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise CertificationError("read-back identity did not receive an access token")

    admin_realm_endpoint = endpoints["adminRealmEndpoint"].rstrip("/")
    require_https(admin_realm_endpoint)
    lookup_url = (
        f"{admin_realm_endpoint}/clients?clientId={quote(expected_client_id, safe='')}&exact=true"
    )
    status, clients = transport("GET", lookup_url, token=access_token)
    if status != 200 or not isinstance(clients, list) or len(clients) != 1:
        raise CertificationError("Klyrow client read-back must resolve exactly one client")
    internal_id = clients[0].get("id") if isinstance(clients[0], dict) else None
    if not isinstance(internal_id, str) or not internal_id:
        raise CertificationError("Klyrow client read-back is missing its internal identifier")

    status, live_client = transport(
        "GET",
        f"{admin_realm_endpoint}/clients/{quote(internal_id, safe='')}",
        token=access_token,
    )
    if status != 200 or not isinstance(live_client, dict) or live_client.get("clientId") != expected_client_id:
        raise CertificationError("Klyrow client detail read-back failed")

    desired_projection = project_client(desired, allowlist)
    live_projection = project_client(live_client, allowlist)
    matches = live_projection == desired_projection
    if not matches:
        raise CertificationError("live Klyrow client does not match the protected desired projection")

    timestamp = (now or (lambda: datetime.now(timezone.utc)))()
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc).replace(microsecond=0)

    evidence = {
        "schemaVersion": 1,
        "repository_sha": repo_sha,
        "environment": environment,
        "issuer": issuer,
        "discovery_sha256": canonical_sha256(discovery),
        "jwks_fingerprint": canonical_sha256(jwks),
        "klyrow_desired_projection_sha256": canonical_sha256(desired_projection),
        "klyrow_live_projection_sha256": canonical_sha256(live_projection),
        "klyrow_projection_matches": matches,
        "klyrow_redirect_uris": live_projection["redirectUris"],
        "collected_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "mutation_attempted": False,
    }

    required = set(contract.get("requiredEvidence", []))
    if set(evidence) - {"schemaVersion"} != required:
        raise CertificationError("activation evidence fields do not match the protected contract")
    serialized = json.dumps(evidence, sort_keys=True)
    for sensitive in (admin_client_secret, access_token):
        if sensitive and sensitive in serialized:
            raise CertificationError("sensitive material reached activation evidence")
    return evidence


def validate_runtime_environment(environment: str) -> None:
    contract = load_json("config/certification/activation-readback.json")
    if environment not in contract.get("environments", {}):
        raise CertificationError("environment must be exactly staging or production")
    endpoints = load_json(contract["environments"][environment]["endpointContractPath"])
    expected = {
        "KC_BASE_URL": endpoints["adminApiBaseUrl"],
        "KC_PUBLIC_URL": endpoints["publicUrl"],
        "KC_TARGET_REALM": endpoints["realm"],
        "KC_ADMIN_REALM": endpoints["adminAuthenticationRealm"],
    }
    for name, value in expected.items():
        actual = os.environ.get(name, "").rstrip("/")
        if not actual or actual != str(value).rstrip("/"):
            raise CertificationError(f"{name} does not match the selected environment contract")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", required=True, choices=("staging", "production"))
    parser.add_argument("--repository-sha")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        validate_runtime_environment(args.environment)
        evidence = certify(
            args.environment,
            os.environ.get("KC_ADMIN_CLIENT_ID", ""),
            os.environ.get("KC_ADMIN_CLIENT_SECRET", ""),
            repository_sha(args.repository_sha),
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        os.umask(0o077)
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except CertificationError as exc:
        print(f"ACTIVATION_READBACK=FAIL\nERROR={exc}", file=os.sys.stderr)
        return 1

    print("ACTIVATION_READBACK=PASS")
    print(f"ENVIRONMENT={args.environment}")
    print("KLYROW_PROJECTION_MATCH=YES")
    print("PRODUCTION_MUTATION_ALLOWED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
