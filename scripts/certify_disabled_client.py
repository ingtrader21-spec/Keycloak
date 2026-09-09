#!/usr/bin/env python3
"""Certify an existing disabled fixture using authenticated, read-only client reads.

No imported evidence file is trusted. The current stored client secret is checked
before and after the rejected grant without enabling, disabling or rotating it.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE_BYTES = 1024 * 1024


class CertificationError(Exception):
    """Only fixed, sanitized error messages may reach the command line."""


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CertificationError("redirects are forbidden during certification")


def request_json(method, url, *, token=None, form=None):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise CertificationError("certification requires HTTPS without URL credentials")
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None if form is None else urlencode(form).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        req = Request(url, data=data, headers=headers, method=method)
        try:
            response = build_opener(NoRedirects()).open(req, timeout=30)
        except HTTPError as exc:
            response = exc
        with response:
            status = response.code
            body = response.read(MAX_RESPONSE_BYTES + 1)
        if 300 <= status < 400:
            raise CertificationError("redirects are forbidden during certification")
        if len(body) > MAX_RESPONSE_BYTES:
            raise CertificationError("certification response exceeds size limit")
        return status, json.loads(body)
    except (OSError, URLError, ValueError):
        # Never print exception text: URLs, headers or remote bodies may contain secrets.
        raise CertificationError("certification HTTP or JSON response failed") from None


def load_endpoints(environment):
    filenames = {"staging": "codestra-staging.json", "production": "codestra.json"}
    if environment not in filenames:
        raise CertificationError("DEPLOY_ENVIRONMENT must be staging or production")
    endpoints = json.loads((ROOT / "config/endpoints" / filenames[environment]).read_text())
    base = endpoints["adminApiBaseUrl"]
    issuer = endpoints["issuer"]
    if (endpoints["realm"] != "codestra"
            or issuer != endpoints["publicUrl"] + "/realms/codestra"
            or endpoints["tokenEndpoint"] != issuer + "/protocol/openid-connect/token"
            or endpoints["adminRealmEndpoint"] != base + "/admin/realms/codestra"):
        raise CertificationError("canonical endpoint contract is inconsistent")
    return endpoints


def certify(environment, admin_id, admin_secret, client_id, client_secret, *, transport=request_json):
    endpoints = load_endpoints(environment)
    if not all(isinstance(value, str) and value for value in (admin_id, admin_secret, client_id, client_secret)):
        raise CertificationError("certification credentials are required")
    if admin_id == client_id:
        raise CertificationError("read-back identity must differ from the disabled fixture")

    admin_token_url = (endpoints["adminApiBaseUrl"] + "/realms/"
                       + quote(endpoints["adminAuthenticationRealm"], safe="")
                       + "/protocol/openid-connect/token")
    status, auth = transport("POST", admin_token_url, form={
        "grant_type": "client_credentials", "client_id": admin_id, "client_secret": admin_secret,
    })
    if (status != 200 or not isinstance(auth, dict)
            or not isinstance(auth.get("access_token"), str) or not auth["access_token"]
            or any(c in auth["access_token"] for c in "\r\n")):
        raise CertificationError("certification read-back authentication failed")
    token = auth["access_token"]
    client_url = endpoints["adminRealmEndpoint"] + "/clients"
    lookup_url = client_url + "?" + urlencode({"clientId": client_id, "exact": "true"})

    def read_fixture():
        status, clients = transport("GET", lookup_url, token=token)
        if status != 200 or not isinstance(clients, list) or len(clients) != 1:
            raise CertificationError("disabled fixture must resolve to exactly one client")
        client = clients[0]
        if (not isinstance(client, dict) or client.get("clientId") != client_id
                or not isinstance(client.get("id"), str) or not client["id"]
                or client.get("enabled") is not False
                or client.get("publicClient") is not False
                or client.get("bearerOnly") is not False
                or client.get("serviceAccountsEnabled") is not True
                or client.get("protocol") != "openid-connect"
                or client.get("clientAuthenticatorType") != "client-secret"):
            raise CertificationError("fixture is not a disabled confidential service client")
        status, secret = transport(
            "GET", client_url + "/" + quote(client["id"], safe="") + "/client-secret", token=token)
        if (status != 200 or not isinstance(secret, dict) or secret.get("type") != "secret"
                or not isinstance(secret.get("value"), str)
                or not hmac.compare_digest(secret["value"].encode(), client_secret.encode())):
            raise CertificationError("disabled fixture credential does not match authenticated read-back")
        return client["id"]

    internal_id = read_fixture()
    status, rejection = transport("POST", endpoints["tokenEndpoint"], form={
        "grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret,
    })
    if (status not in (400, 401) or not isinstance(rejection, dict)
            or rejection.get("error") not in ("invalid_client", "unauthorized_client")
            or "access_token" in rejection):
        raise CertificationError("disabled fixture did not return an OAuth client rejection")
    if read_fixture() != internal_id:
        raise CertificationError("disabled fixture identity changed during certification")
    return {
        "schemaVersion": 1, "evidenceType": "authenticated-keycloak-admin-readback",
        "environment": environment, "issuer": endpoints["issuer"], "realm": endpoints["realm"],
        "clientId": client_id, "internalClientId": internal_id, "enabled": False,
        "credentialMatchedBeforeAndAfter": True, "httpStatus": status,
        "capturedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main():
    names = ("DEPLOY_ENVIRONMENT", "KC_CERT_ADMIN_CLIENT_ID", "KC_CERT_ADMIN_CLIENT_SECRET",
             "DISABLED_CLIENT_ID", "DISABLED_CLIENT_SECRET")
    try:
        evidence = certify(*(os.environ.get(name, "") for name in names))
    except CertificationError as exc:
        print("DISABLED_CLIENT_CERTIFICATION=FAIL\nERROR=" + str(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError):
        print("DISABLED_CLIENT_CERTIFICATION=FAIL\nERROR=invalid endpoint contract", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
