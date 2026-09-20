#!/usr/bin/env python3
"""Mint the TEST_SYN staging certification tokens and prove their claims.

Keycloak half of the Keycloak -> Caddy -> Kong -> Middleware certification:
for every identity declared in
``config/desired-state/edge-integration-certification/contract.json`` the
tool obtains one Client Credentials token from the staging realm, verifies
the RS256 signature against the realm JWKS with the standard library only,
and checks issuer, audience, authorized party, lifetime, scope exactness,
tenant binding, and the absence of any realm-wide grant.

Fail-closed rules:

* refuses unless ``CERTIFY_ENVIRONMENT=staging`` and ``CERTIFY_CAMPAIGN_ID=TEST_SYN``;
* refuses the production issuer and any issuer that is not the staging contract issuer;
* reads client secrets only from ``CERTIFY_CLIENT_SECRET_FILE_<ROLE>`` file
  references (the same names the Middleware runner uses) and refuses raw
  secrets in the environment;
* never prints or stores an access token, refresh token, or client secret;
  the redacted report carries claim values and SHA-256 fingerprints only;
* exits non-zero when any identity cannot be minted or any claim check fails.

Usage:
  CERTIFY_ENVIRONMENT=staging CERTIFY_CAMPAIGN_ID=TEST_SYN \\
  CERTIFY_CLIENT_SECRET_FILE_N8N_SUBMIT=/run/secrets/test-syn-n8n-submit ... \\
  python3 scripts/certify_edge_identity_staging.py --output /var/lib/codestra/evidence/keycloak-edge-identity.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "desired-state" / "edge-integration-certification" / "contract.json"
STAGING_ENDPOINTS = ROOT / "config" / "endpoints" / "codestra-staging.json"
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
REQUIRED_ENVIRONMENT = "staging"
REQUIRED_CAMPAIGN = "TEST_SYN"
MIN_LIFETIME = 60
MAX_LIFETIME = 300
CLOCK_SKEW = 5
# RFC 8017 section 9.2, DigestInfo prefix for SHA-256.
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
REDACTED_CLAIMS = (
    "iss", "aud", "azp", "typ", "scope", "environment", "tenant_id",
    "business_units", "campaigns", "iat", "nbf", "exp",
)
SECRET_MARKERS = ("SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")


class Refused(SystemExit):
    """Preconditions failed; nothing was minted."""

    def __init__(self, reason: str) -> None:
        super().__init__(2)
        self.reason = reason

    def __str__(self) -> str:
        return self.reason


class CertificationError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        raise CertificationError(f"redirect prohibited: HTTP {code}")


# --- helpers -------------------------------------------------------------------


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sha256_hex(value: bytes | str) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CertificationError(f"{path.name} must contain a JSON object")
    return value


def emsa_pkcs1_v15(message: bytes, em_len: int) -> bytes:
    """EMSA-PKCS1-v1_5 encoding of SHA-256(message) to em_len bytes (RFC 8017 9.2)."""
    digest = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_len = em_len - len(digest) - 3
    if padding_len < 8:
        raise CertificationError("RSA modulus too small for RS256")
    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest


def rs256_verify(jwk: dict[str, Any], signing_input: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 verification with SHA-256 using integer arithmetic only."""
    if jwk.get("kty") != "RSA":
        return False
    modulus = int.from_bytes(b64url_decode(str(jwk["n"])), "big")
    exponent = int.from_bytes(b64url_decode(str(jwk["e"])), "big")
    k = (modulus.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= modulus:
        return False
    em = pow(s, exponent, modulus).to_bytes(k, "big")
    return em == emsa_pkcs1_v15(signing_input, k)


def http_json(url: str, *, form: dict[str, str] | None = None, timeout: float) -> tuple[int, Any]:
    headers = {"Accept": "application/json", "User-Agent": "codestra-keycloak-edge-certification/1.0"}
    body = None
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urllib.parse.urlencode(form).encode()
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if form is not None else "GET")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            status, payload = response.status, response.read()
    except urllib.error.HTTPError as exc:
        status, payload = exc.code, exc.read()
    except CertificationError:
        raise
    except Exception as exc:  # noqa: BLE001 - never echo the request (it may carry a secret)
        raise CertificationError(f"{type(exc).__name__} while calling {urllib.parse.urlsplit(url).path}") from exc
    try:
        return status, json.loads(payload or b"null")
    except ValueError:
        return status, None


# --- preconditions --------------------------------------------------------------


def read_secret_file(reference: str, label: str) -> str:
    path = Path(reference)
    if not path.is_absolute():
        raise Refused(f"{label}: secret file reference must be an absolute path")
    if path.is_symlink():
        raise Refused(f"{label}: secret file must not be a symlink")
    try:
        info = path.stat()
    except OSError as exc:
        raise Refused(f"{label}: secret file is not readable ({type(exc).__name__})") from exc
    if not stat.S_ISREG(info.st_mode):
        raise Refused(f"{label}: secret file must be a regular file")
    if os.name != "nt" and info.st_mode & 0o077:
        raise Refused(f"{label}: secret file permissions must be 0600 or stricter")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value or len(value) < 16:
        raise Refused(f"{label}: secret file must hold one non-empty secret")
    return value


def load_preconditions(env: dict[str, str]) -> tuple[dict[str, Any], dict[str, str]]:
    if env.get("CERTIFY_ENVIRONMENT", "") != REQUIRED_ENVIRONMENT:
        raise Refused("CERTIFY_ENVIRONMENT must be 'staging'")
    if env.get("CERTIFY_CAMPAIGN_ID", "") != REQUIRED_CAMPAIGN:
        raise Refused("CERTIFY_CAMPAIGN_ID must be 'TEST_SYN'")
    raw = sorted(
        name for name in env
        if name.startswith(("CERTIFY_", "KC_"))
        and any(marker in name for marker in SECRET_MARKERS)
        and "_FILE" not in name
    )
    if raw:
        raise Refused("raw credentials in the environment are refused; use *_FILE references: " + ",".join(raw))
    contract = load_json(CONTRACT_PATH)
    staging = load_json(STAGING_ENDPOINTS)
    issuer = str(contract.get("issuer", "")).rstrip("/")
    if contract.get("environment") != REQUIRED_ENVIRONMENT or contract.get("campaign") != REQUIRED_CAMPAIGN:
        raise Refused("certification contract is not the staging TEST_SYN contract")
    host = urllib.parse.urlsplit(issuer).hostname or ""
    if issuer != staging["issuer"].rstrip("/") or issuer == PRODUCTION_ISSUER or "staging" not in host:
        raise Refused("contract issuer is not the canonical staging issuer")
    if env.get("CERTIFY_KEYCLOAK_ISSUER", issuer).rstrip("/") != issuer:
        raise Refused("CERTIFY_KEYCLOAK_ISSUER disagrees with the staging contract issuer")
    secrets: dict[str, str] = {}
    for identity in contract["identities"]:
        role = str(identity["role"]).upper()
        reference = env.get(f"CERTIFY_CLIENT_SECRET_FILE_{role}", "")
        if not reference:
            raise Refused(f"CERTIFY_CLIENT_SECRET_FILE_{role} is required for {identity['clientId']}")
        secrets[identity["clientId"]] = read_secret_file(reference, identity["clientId"])
    return contract, secrets


def validate_output_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise Refused("--output must be an absolute path outside the repository")
    resolved = path.resolve(strict=False)
    if ROOT.resolve() == resolved or ROOT.resolve() in resolved.parents:
        raise Refused("--output must stay outside the Git checkout")
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise Refused("--output must be a regular file")
    return path


# --- token checks ----------------------------------------------------------------


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def check_claims(
    identity: dict[str, Any],
    contract: dict[str, Any],
    claims: dict[str, Any],
    *,
    now: int,
) -> list[dict[str, str]]:
    """Every assertion the certification makes about one minted token."""
    client_id = identity["clientId"]
    checks: list[dict[str, str]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    add("iss", claims.get("iss") == contract["issuer"], str(claims.get("iss")))
    audiences = [str(a) for a in as_list(claims.get("aud"))]
    add("aud_exact", audiences == [identity["audience"]], json.dumps(audiences))
    if identity["role"] == "wrong_audience":
        add("aud_excludes_middleware", contract["audience"] not in audiences and "middleware-api" not in audiences, json.dumps(audiences))
    else:
        add("aud_includes_middleware", contract["audience"] in audiences, json.dumps(audiences))
    add("azp", claims.get("azp") == client_id, str(claims.get("azp")))
    add("typ_bearer", claims.get("typ") == "Bearer", str(claims.get("typ")))
    for claim in ("sub", "jti", "iat", "exp"):
        add(f"{claim}_present", bool(claims.get(claim)), "present" if claims.get(claim) else "missing")
    try:
        iat, exp = int(claims.get("iat", 0)), int(claims.get("exp", 0))
    except (TypeError, ValueError):
        iat, exp = 0, 0
    lifetime = exp - iat
    add("lifetime_bounded", MIN_LIFETIME <= lifetime <= MAX_LIFETIME, f"exp-iat={lifetime}s")
    add("exp_in_future", exp > now, f"exp-now={exp - now}s")
    nbf = claims.get("nbf")
    add("nbf_valid", nbf is None or int(nbf) <= now + CLOCK_SKEW, f"nbf={nbf}")
    scopes = set(str(claims.get("scope", "")).split())
    ingress = set(contract["ingressScopes"])
    add("scope_exact", scopes == set(identity["scopes"]), f"granted={sorted(scopes)} expected={sorted(identity['scopes'])}")
    add("no_extra_ingress_scope", scopes & ingress == set(identity["scopes"]), f"ingress={sorted(scopes & ingress)}")
    forbidden = set(contract["forbiddenScopes"]) | {contract["outboundScope"]["name"]}
    add("no_forbidden_or_outbound_scope", not (scopes & forbidden), f"present={sorted(scopes & forbidden)}")
    add("no_realm_role_grant", not claims.get("realm_access") and not claims.get("resource_access"), "realm_access/resource_access absent")
    add("environment_claim", claims.get("environment") == REQUIRED_ENVIRONMENT, str(claims.get("environment")))
    add("tenant_id", claims.get("tenant_id") == identity["tenant"], str(claims.get("tenant_id")))
    add("business_units", as_list(claims.get("business_units")) == identity["businessUnits"], json.dumps(claims.get("business_units")))
    add("campaigns", as_list(claims.get("campaigns")) == identity["campaigns"], json.dumps(claims.get("campaigns")))
    return checks


def redacted_view(claims: dict[str, Any]) -> dict[str, Any]:
    view = {name: claims.get(name) for name in REDACTED_CLAIMS if name in claims}
    for name in ("sub", "jti"):
        if claims.get(name):
            view[f"{name}_sha256_prefix"] = sha256_hex(str(claims[name]))[:16]
    return view


def decode_and_verify(token: str, jwks: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise CertificationError("token is not a compact JWS")
    header = json.loads(b64url_decode(parts[0]))
    claims = json.loads(b64url_decode(parts[1]))
    if header.get("alg") != "RS256":
        raise CertificationError(f"unexpected token algorithm {header.get('alg')!r}")
    keys = [k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid") and k.get("use", "sig") == "sig"]
    if len(keys) != 1:
        raise CertificationError("signing key is not uniquely resolvable from the staging JWKS")
    if not rs256_verify(keys[0], f"{parts[0]}.{parts[1]}".encode("ascii"), b64url_decode(parts[2])):
        raise CertificationError("token signature does not verify against the staging JWKS")
    return header, claims


def mint(token_endpoint: str, client_id: str, secret: str, timeout: float) -> str:
    status, payload = http_json(
        token_endpoint,
        form={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
        timeout=timeout,
    )
    if status != 200 or not isinstance(payload, dict):
        raise CertificationError(f"token endpoint answered HTTP {status}")
    token = payload.get("access_token")
    if not isinstance(token, str) or token.count(".") != 2:
        raise CertificationError("token endpoint returned no access token")
    if payload.get("refresh_token"):
        raise CertificationError("token endpoint issued a refresh token; machine clients must not receive one")
    return token


# --- main ------------------------------------------------------------------------


def certify(contract: dict[str, Any], secrets: dict[str, str], timeout: float) -> dict[str, Any]:
    issuer = contract["issuer"]
    status, discovery = http_json(f"{issuer}/.well-known/openid-configuration", timeout=timeout)
    if status != 200 or not isinstance(discovery, dict):
        raise CertificationError(f"discovery answered HTTP {status}")
    if discovery.get("issuer") != issuer:
        raise CertificationError("live discovery issuer differs from the staging contract issuer")
    for key in ("token_endpoint", "jwks_uri"):
        if not str(discovery.get(key, "")).startswith(issuer + "/"):
            raise CertificationError(f"discovery {key} is outside the staging issuer")
    if discovery["token_endpoint"] != contract["tokenEndpoint"] or discovery["jwks_uri"] != contract["jwksUri"]:
        raise CertificationError("discovery endpoints differ from the contract endpoints")
    status, jwks = http_json(discovery["jwks_uri"], timeout=timeout)
    if status != 200 or not isinstance(jwks, dict) or not jwks.get("keys"):
        raise CertificationError("staging JWKS is unavailable")

    report: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "CodestraKeycloakEdgeIdentityCertification",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "environment": REQUIRED_ENVIRONMENT,
        "campaign": REQUIRED_CAMPAIGN,
        "issuer": issuer,
        "audience": contract["audience"],
        "edgeContractSha256": contract["edgeContract"]["sha256"],
        "discovery": {"issuer": discovery["issuer"], "tokenEndpoint": discovery["token_endpoint"], "jwksUri": discovery["jwks_uri"]},
        "identities": {},
        "tokensRecorded": False,
        "secretsRecorded": False,
    }
    fingerprints: dict[str, str] = {}
    jtis: dict[str, str] = {}
    failures = 0
    for identity in contract["identities"]:
        client_id = identity["clientId"]
        entry: dict[str, Any] = {"role": identity["role"], "checks": []}
        report["identities"][client_id] = entry
        try:
            token = mint(discovery["token_endpoint"], client_id, secrets[client_id], timeout)
            header, claims = decode_and_verify(token, jwks)
        except CertificationError as exc:
            entry["checks"].append({"name": "mint_and_verify", "status": "FAIL", "detail": str(exc)})
            failures += 1
            continue
        entry["signature"] = {"alg": header.get("alg"), "kid": header.get("kid"), "verified": True}
        entry["tokenSha256"] = sha256_hex(token)
        entry["claims"] = redacted_view(claims)
        entry["checks"] = [{"name": "mint_and_verify", "status": "PASS", "detail": "RS256 verified against staging JWKS"}]
        entry["checks"].extend(check_claims(identity, contract, claims, now=int(time.time())))
        fingerprints[client_id] = entry["tokenSha256"]
        jtis[client_id] = str(claims.get("jti", ""))
        failures += sum(1 for check in entry["checks"] if check["status"] != "PASS")
        del token
    distinct_tokens = len(set(fingerprints.values())) == len(fingerprints)
    distinct_jtis = len(set(jtis.values())) == len(jtis)
    report["crossIdentity"] = [
        {"name": "tokens_distinct", "status": "PASS" if distinct_tokens else "FAIL"},
        {"name": "jti_distinct", "status": "PASS" if distinct_jtis else "FAIL"},
        {
            "name": "all_identities_minted",
            "status": "PASS" if len(fingerprints) == len(contract["identities"]) else "FAIL",
        },
    ]
    failures += sum(1 for check in report["crossIdentity"] if check["status"] != "PASS")
    report["totals"] = {
        "identities": len(contract["identities"]),
        "minted": len(fingerprints),
        "failedChecks": failures,
    }
    report["verdict"] = "PASS" if failures == 0 else "NO_GO"
    return report


def write_private(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True, help="absolute path for the redacted JSON report (0600)")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    try:
        output = validate_output_path(args.output)
        contract, secrets = load_preconditions(dict(os.environ))
    except Refused as exc:
        print(f"KEYCLOAK_EDGE_IDENTITY_CERTIFICATION=REFUSED\nREASON={exc.reason}", file=sys.stderr)
        return 2
    try:
        report = certify(contract, secrets, args.timeout)
    except CertificationError as exc:
        print(f"KEYCLOAK_EDGE_IDENTITY_CERTIFICATION=NO_GO\nREASON={exc}", file=sys.stderr)
        return 1
    finally:
        secrets.clear()
    write_private(output, json.dumps(report, indent=2, sort_keys=True) + "\n")
    for client_id, entry in report["identities"].items():
        failed = [c["name"] for c in entry["checks"] if c["status"] != "PASS"]
        claims = entry.get("claims", {})
        print(
            f"IDENTITY={client_id}|scope={claims.get('scope', '')!s}|aud={json.dumps(claims.get('aud'))}"
            f"|tenant={claims.get('tenant_id')}|{'PASS' if not failed else 'FAIL:' + ','.join(failed)}"
        )
    print(f"KEYCLOAK_EDGE_IDENTITY_CERTIFICATION={report['verdict']}")
    print(f"KEYCLOAK_EDGE_IDENTITY_REPORT={output}")
    print("TOKENS_RECORDED=false")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
