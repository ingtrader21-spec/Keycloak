#!/usr/bin/env python3
"""Run a fail-closed end-to-end Keycloak password-recovery acceptance test.

The script is intended for a protected, workflow_dispatch-only staging job on a
self-hosted runner. It never prints reset URLs, access tokens, passwords, SMTP
credentials, or mailbox credentials. Its JSON report contains status evidence
and hashes only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import imaplib
import json
import os
import re
import secrets
import string
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
FORBIDDEN_MIDDLEWARE_MARKERS = {
    "password",
    "new_password",
    "temporary_password",
    "reset_token",
    "reset_url",
    "action_token",
    "smtp_password",
    "kc_action",
    "login-actions/action-token",
}
SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
ACTION_URL_PATTERN = re.compile(
    r"https://[^\s\"'<>]+/realms/[^\s\"'<>]+/login-actions/action-token\?[^\s\"'<>]+",
    re.IGNORECASE,
)


class AcceptanceError(RuntimeError):
    """Raised when an acceptance gate fails."""


@dataclass(frozen=True)
class Config:
    issuer: str
    realm: str
    client_id: str
    redirect_uri: str
    expected_keycloak_sha: str
    expected_klyrow_sha: str
    keycloak_version_url: str
    klyrow_version_url: str
    admin_client_id: str
    admin_client_secret: str
    recipient_template: str
    imap_host: str
    imap_port: int
    imap_username: str
    imap_password: str
    imap_mailbox: str
    imap_starttls: bool
    klyrow_database_url: str
    klyrow_message_table: str
    middleware_audit_url: str
    middleware_audit_token: str
    request_timeout_seconds: int
    mailbox_timeout_seconds: int
    expiry_lifespan_seconds: int
    expiry_grace_seconds: int
    report_path: Path

    @classmethod
    def from_environment(cls, report_path: Path) -> "Config":
        issuer = required("KEYCLOAK_ISSUER").rstrip("/")
        if issuer != CANONICAL_ISSUER:
            raise AcceptanceError("KEYCLOAK_ISSUER is not the canonical Codestra issuer")
        realm = issuer.rsplit("/", 1)[-1]
        if realm != "codestra":
            raise AcceptanceError("the acceptance workflow may target only realm=codestra")

        table = os.getenv("KLYROW_E2E_MESSAGE_TABLE", "provider_messages")
        if not SAFE_IDENTIFIER.fullmatch(table):
            raise AcceptanceError("KLYROW_E2E_MESSAGE_TABLE is not a safe SQL identifier")

        expiry_lifespan = integer_environment(
            "E2E_EXPIRY_LIFESPAN_SECONDS", default=60, minimum=30, maximum=180
        )
        expiry_grace = integer_environment(
            "E2E_EXPIRY_GRACE_SECONDS", default=8, minimum=5, maximum=60
        )
        return cls(
            issuer=issuer,
            realm=realm,
            client_id=required("KEYCLOAK_CLIENT_ID"),
            redirect_uri=required("KEYCLOAK_REDIRECT_URI"),
            expected_keycloak_sha=validated_sha(required("EXPECTED_KEYCLOAK_SHA")),
            expected_klyrow_sha=validated_sha(required("EXPECTED_KLYROW_SHA")),
            keycloak_version_url=required("KEYCLOAK_VERSION_URL"),
            klyrow_version_url=required("KLYROW_VERSION_URL"),
            admin_client_id=required("KEYCLOAK_E2E_ADMIN_CLIENT_ID"),
            admin_client_secret=required("KEYCLOAK_E2E_ADMIN_CLIENT_SECRET"),
            recipient_template=required("E2E_RECIPIENT_TEMPLATE"),
            imap_host=required("E2E_IMAP_HOST"),
            imap_port=integer_environment("E2E_IMAP_PORT", 993, 1, 65535),
            imap_username=required("E2E_IMAP_USERNAME"),
            imap_password=required("E2E_IMAP_PASSWORD"),
            imap_mailbox=os.getenv("E2E_IMAP_MAILBOX", "INBOX"),
            imap_starttls=boolean_environment("E2E_IMAP_STARTTLS", False),
            klyrow_database_url=required("KLYROW_E2E_DATABASE_URL"),
            klyrow_message_table=table,
            middleware_audit_url=required("MIDDLEWARE_E2E_AUDIT_URL"),
            middleware_audit_token=required("MIDDLEWARE_E2E_AUDIT_TOKEN"),
            request_timeout_seconds=integer_environment(
                "E2E_REQUEST_TIMEOUT_SECONDS", 20, 5, 120
            ),
            mailbox_timeout_seconds=integer_environment(
                "E2E_MAILBOX_TIMEOUT_SECONDS", 180, 30, 600
            ),
            expiry_lifespan_seconds=expiry_lifespan,
            expiry_grace_seconds=expiry_grace,
            report_path=report_path,
        )


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise AcceptanceError(f"required environment variable is missing: {name}")
    return value


def validated_sha(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise AcceptanceError("expected deployment SHA must be a full lowercase Git SHA")
    return value


def integer_environment(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise AcceptanceError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise AcceptanceError(f"{name} must be between {minimum} and {maximum}")
    return value


def boolean_environment(name: str, default: bool) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise AcceptanceError(f"{name} must be boolean")


def github_mask(value: str) -> None:
    if value and os.getenv("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{value}")


def random_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "!@#$%^&*()-_=+" for c in value)
        ):
            return value


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def recursive_sha_candidates(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {
                "sha",
                "git_sha",
                "gitsha",
                "commit",
                "commit_sha",
                "revision",
                "source_sha",
            } and isinstance(item, str):
                yield item.lower()
            yield from recursive_sha_candidates(item)
    elif isinstance(value, list):
        for item in value:
            yield from recursive_sha_candidates(item)


def verify_runtime_sha(url: str, expected_sha: str, timeout: int, label: str) -> None:
    response = requests.get(url, timeout=timeout, allow_redirects=False)
    if response.status_code != 200:
        raise AcceptanceError(f"{label} version endpoint returned {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise AcceptanceError(f"{label} version endpoint did not return JSON") from exc
    candidates = set(recursive_sha_candidates(body))
    if expected_sha not in candidates:
        raise AcceptanceError(f"{label} runtime SHA does not match the reviewed SHA")


def admin_token(config: Config) -> str:
    response = requests.post(
        f"{config.issuer}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": config.admin_client_id,
            "client_secret": config.admin_client_secret,
        },
        timeout=config.request_timeout_seconds,
    )
    if response.status_code != 200:
        raise AcceptanceError("fine-grained Keycloak E2E administrator authentication failed")
    token = response.json().get("access_token")
    if not isinstance(token, str) or not token:
        raise AcceptanceError("Keycloak admin token response is invalid")
    github_mask(token)
    return token


def admin_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_test_user(config: Config, token: str, username: str, email: str, password: str) -> str:
    endpoint = f"{config.issuer.rsplit('/realms/', 1)[0]}/admin/realms/{config.realm}/users"
    response = requests.post(
        endpoint,
        headers=admin_headers(token),
        json={
            "username": username,
            "email": email,
            "enabled": True,
            "emailVerified": True,
            "attributes": {"codestra_e2e": ["password-reset"]},
            "credentials": [
                {"type": "password", "value": password, "temporary": False}
            ],
        },
        timeout=config.request_timeout_seconds,
    )
    if response.status_code != 201:
        raise AcceptanceError(f"unable to create disposable Keycloak test user: {response.status_code}")
    location = response.headers.get("Location", "")
    user_id = location.rstrip("/").rsplit("/", 1)[-1]
    if not re.fullmatch(r"[0-9a-fA-F-]{16,64}", user_id):
        raise AcceptanceError("Keycloak did not return a valid disposable user identifier")
    return user_id


def delete_test_user(config: Config, token: str, user_id: str) -> None:
    endpoint = (
        f"{config.issuer.rsplit('/realms/', 1)[0]}/admin/realms/"
        f"{config.realm}/users/{user_id}"
    )
    response = requests.delete(
        endpoint, headers=admin_headers(token), timeout=config.request_timeout_seconds
    )
    if response.status_code not in {204, 404}:
        raise AcceptanceError(f"unable to delete disposable test user: {response.status_code}")


def send_short_lived_update_password_action(
    config: Config, token: str, user_id: str
) -> None:
    endpoint = (
        f"{config.issuer.rsplit('/realms/', 1)[0]}/admin/realms/{config.realm}/users/"
        f"{user_id}/execute-actions-email"
    )
    response = requests.put(
        endpoint,
        headers=admin_headers(token),
        params={
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "lifespan": config.expiry_lifespan_seconds,
        },
        json=["UPDATE_PASSWORD"],
        timeout=config.request_timeout_seconds,
    )
    if response.status_code != 204:
        raise AcceptanceError(
            f"unable to create short-lived UPDATE_PASSWORD action: {response.status_code}"
        )


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = __import__("base64").urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def authorization_url(config: Config, *, prompt: str | None = None) -> str:
    _verifier, challenge = pkce_pair()
    query = {
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "response_type": "code",
        "scope": "openid profile email",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": secrets.token_urlsafe(24),
        "nonce": secrets.token_urlsafe(24),
    }
    if prompt:
        query["prompt"] = prompt
    return f"{config.issuer}/protocol/openid-connect/auth?{urlencode(query)}"


def parse_form(response: requests.Response, required_field: str) -> tuple[str, dict[str, str]]:
    soup = BeautifulSoup(response.text, "html.parser")
    form = soup.find("form")
    if form is None:
        raise AcceptanceError(f"Keycloak page is missing a form containing {required_field}")
    names = {item.get("name") for item in form.find_all("input")}
    if required_field not in names:
        raise AcceptanceError(f"Keycloak form is missing required field: {required_field}")
    action = urljoin(response.url, form.get("action", ""))
    hidden: dict[str, str] = {}
    for item in form.find_all("input"):
        if item.get("type") == "hidden" and item.get("name"):
            hidden[str(item["name"])] = str(item.get("value", ""))
    return action, hidden


def follow_keycloak_redirects(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: int,
    data: dict[str, str] | None = None,
    issuer_host: str,
) -> tuple[requests.Response, str | None]:
    current_method = method
    current_url = url
    current_data = data
    for _ in range(16):
        response = session.request(
            current_method,
            current_url,
            data=current_data,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response, None
        location = response.headers.get("Location")
        if not location:
            raise AcceptanceError("Keycloak returned a redirect without Location")
        next_url = urljoin(response.url, location)
        if urlsplit(next_url).hostname != issuer_host:
            return response, next_url
        current_method = "GET"
        current_data = None
        current_url = next_url
    raise AcceptanceError("too many Keycloak redirects")


def create_authenticated_browser_session(
    config: Config, username: str, password: str
) -> requests.Session:
    session = requests.Session()
    response = session.get(
        authorization_url(config), timeout=config.request_timeout_seconds
    )
    if response.status_code != 200:
        raise AcceptanceError("Keycloak login page is unavailable")
    action, hidden = parse_form(response, "username")
    hidden.update({"username": username, "password": password, "credentialId": ""})
    _response, external = follow_keycloak_redirects(
        session,
        "POST",
        action,
        timeout=config.request_timeout_seconds,
        data=hidden,
        issuer_host=urlsplit(config.issuer).hostname or "",
    )
    if not external or "code" not in parse_qs(urlsplit(external).query):
        raise AcceptanceError("disposable Keycloak user could not establish an OIDC session")
    return session


def assert_old_session_invalidated(config: Config, old_session: requests.Session) -> None:
    _response, external = follow_keycloak_redirects(
        old_session,
        "GET",
        authorization_url(config, prompt="none"),
        timeout=config.request_timeout_seconds,
        issuer_host=urlsplit(config.issuer).hostname or "",
    )
    if not external:
        raise AcceptanceError("old browser session did not leave the Keycloak authorization flow")
    query = parse_qs(urlsplit(external).query)
    if "code" in query:
        raise AcceptanceError("pre-reset Keycloak session remains valid after password reset")
    if query.get("error", [""])[0] not in {"login_required", "interaction_required"}:
        raise AcceptanceError("old session invalidation did not return an OIDC login-required result")


def trigger_forgot_password(config: Config, email_address: str) -> datetime:
    session = requests.Session()
    login_page = session.get(
        authorization_url(config), timeout=config.request_timeout_seconds
    )
    if login_page.status_code != 200:
        raise AcceptanceError("Keycloak authorization page is unavailable")
    soup = BeautifulSoup(login_page.text, "html.parser")
    reset_anchor = next(
        (
            item
            for item in soup.find_all("a", href=True)
            if "reset-credentials" in str(item.get("href"))
        ),
        None,
    )
    if reset_anchor is None:
        raise AcceptanceError("Forgot Password is not enabled in the Keycloak login flow")
    reset_page = session.get(
        urljoin(login_page.url, str(reset_anchor["href"])),
        timeout=config.request_timeout_seconds,
    )
    action, hidden = parse_form(reset_page, "username")
    hidden["username"] = email_address
    submitted_at = datetime.now(timezone.utc)
    response = session.post(
        action,
        data=hidden,
        timeout=config.request_timeout_seconds,
        allow_redirects=True,
    )
    if response.status_code >= 500:
        raise AcceptanceError("Keycloak forgot-password submission failed")
    lowered = response.text.lower()
    if email_address.lower() in lowered:
        raise AcceptanceError("forgot-password response reflects account-identifying input")
    return submitted_at


def message_text(message: Message) -> str:
    chunks: list[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            if "attachment" in str(part.get("Content-Disposition", "")).lower():
                continue
            try:
                chunks.append(part.get_content())
            except Exception:
                payload = part.get_payload(decode=True) or b""
                chunks.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    else:
        try:
            chunks.append(message.get_content())
        except Exception:
            payload = message.get_payload(decode=True) or b""
            chunks.append(payload.decode(message.get_content_charset() or "utf-8", "replace"))
    return "\n".join(chunks)


def recipient_headers(message: Message) -> str:
    names = ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To")
    return "\n".join(str(message.get(name, "")) for name in names).lower()


def wait_for_reset_email(
    config: Config,
    recipient: str,
    not_before: datetime,
    excluded_message_ids: set[str],
) -> tuple[Message, str]:
    deadline = time.monotonic() + config.mailbox_timeout_seconds
    since = (not_before - timedelta(days=1)).strftime("%d-%b-%Y")
    while time.monotonic() < deadline:
        client: imaplib.IMAP4
        if config.imap_starttls:
            client = imaplib.IMAP4(config.imap_host, config.imap_port)
            client.starttls()
        else:
            client = imaplib.IMAP4_SSL(config.imap_host, config.imap_port)
        try:
            status, _ = client.login(config.imap_username, config.imap_password)
            if status != "OK":
                raise AcceptanceError("IMAP login failed")
            status, _ = client.select(config.imap_mailbox, readonly=True)
            if status != "OK":
                raise AcceptanceError("unable to select the controlled IMAP mailbox")
            status, data = client.uid("search", None, "SINCE", since)
            if status != "OK":
                raise AcceptanceError("IMAP search failed")
            uids = (data[0] or b"").split()
            for uid in reversed(uids[-100:]):
                status, fetched = client.uid("fetch", uid, "(RFC822)")
                if status != "OK" or not fetched:
                    continue
                raw = next(
                    (
                        item[1]
                        for item in fetched
                        if isinstance(item, tuple) and isinstance(item[1], bytes)
                    ),
                    None,
                )
                if raw is None:
                    continue
                message = BytesParser(policy=policy.default).parsebytes(raw)
                message_id = str(message.get("Message-ID", "")).strip()
                if not message_id or message_id in excluded_message_ids:
                    continue
                if recipient.lower() not in recipient_headers(message):
                    continue
                date_header = message.get("Date")
                if date_header:
                    try:
                        sent_at = parsedate_to_datetime(str(date_header))
                        if sent_at.tzinfo is None:
                            sent_at = sent_at.replace(tzinfo=timezone.utc)
                        if sent_at < not_before - timedelta(minutes=2):
                            continue
                    except (TypeError, ValueError, OverflowError):
                        pass
                body = html.unescape(message_text(message))
                match = ACTION_URL_PATTERN.search(body)
                if not match:
                    continue
                action_url = match.group(0).replace("&amp;", "&")
                parsed = urlsplit(action_url)
                issuer = urlsplit(config.issuer)
                if parsed.scheme != "https" or parsed.hostname != issuer.hostname:
                    raise AcceptanceError("reset message contains an action link on an unapproved host")
                github_mask(action_url)
                return message, action_url
        finally:
            try:
                client.logout()
            except Exception:
                pass
        time.sleep(5)
    raise AcceptanceError("password-recovery email was not received before timeout")


def reset_password_with_action_link(config: Config, action_url: str, new_password: str) -> None:
    session = requests.Session()
    response = session.get(action_url, timeout=config.request_timeout_seconds)
    if response.status_code >= 400:
        raise AcceptanceError("fresh password-reset action link is not usable")
    action, hidden = parse_form(response, "password-new")
    hidden.update({"password-new": new_password, "password-confirm": new_password})
    result = session.post(
        action,
        data=hidden,
        timeout=config.request_timeout_seconds,
        allow_redirects=True,
    )
    if result.status_code >= 500:
        raise AcceptanceError("Keycloak password update failed")
    soup = BeautifulSoup(result.text, "html.parser")
    if soup.find("input", {"name": "password-new"}) is not None:
        raise AcceptanceError("Keycloak returned the password form after reset submission")


def assert_action_link_rejected(config: Config, action_url: str, label: str) -> None:
    response = requests.Session().get(
        action_url, timeout=config.request_timeout_seconds, allow_redirects=True
    )
    soup = BeautifulSoup(response.text, "html.parser")
    if soup.find("input", {"name": "password-new"}) is not None:
        raise AcceptanceError(f"{label} action link remains usable")


def verify_klyrow_delivery(
    config: Config, recipient: str, message_id: str, not_before: datetime
) -> dict[str, Any]:
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise AcceptanceError("psycopg is required for Klyrow delivery evidence") from exc

    query = f"""
        SELECT id, stream, status, sandbox, provider_message_id, payload_json, created_at
          FROM {config.klyrow_message_table}
         WHERE lower(recipient) = lower(%s)
           AND created_at >= %s
         ORDER BY created_at DESC
         LIMIT 20
    """
    with psycopg.connect(config.klyrow_database_url, row_factory=dict_row) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, (recipient, not_before - timedelta(minutes=2)))
            rows = cursor.fetchall()
    matching: dict[str, Any] | None = None
    for row in rows:
        payload = row.get("payload_json")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except ValueError:
                payload = {}
        if isinstance(payload, dict) and payload.get("message_id") == message_id:
            matching = row
            break
    if matching is None:
        raise AcceptanceError("Klyrow has no durable SECURITY record for the received Message-ID")
    if str(matching.get("stream", "")).upper() != "SECURITY":
        raise AcceptanceError("Klyrow accepted the reset email outside the SECURITY stream")
    if matching.get("sandbox") not in {False, 0}:
        raise AcceptanceError("Klyrow reset email remained in sandbox")
    if str(matching.get("status", "")).upper() not in {"SENT", "DELIVERED"}:
        raise AcceptanceError("Klyrow/Postal delivery status is not SENT or DELIVERED")
    if not matching.get("provider_message_id"):
        raise AcceptanceError("Postal provider message identity is missing")
    return {
        "record_id_hash": sha256_text(str(matching["id"])),
        "status": str(matching["status"]).upper(),
        "stream": "SECURITY",
        "sandbox": False,
        "provider_message_id_hash": sha256_text(str(matching["provider_message_id"])),
    }


def verify_postal_received_headers(message: Message) -> None:
    marker = os.getenv("E2E_POSTAL_RECEIVED_MARKER", "postal").strip().lower()
    received = "\n".join(str(value) for value in message.get_all("Received", []))
    if not marker or marker not in received.lower():
        raise AcceptanceError("received email headers do not prove traversal through Postal")


def verify_middleware_secret_boundary(
    config: Config, user_id: str, started_at: datetime
) -> int:
    response = requests.get(
        config.middleware_audit_url,
        headers={"Authorization": f"Bearer {config.middleware_audit_token}"},
        params={
            "identity_subject": user_id,
            "since": started_at.isoformat(),
            "event_family": "identity.password",
        },
        timeout=config.request_timeout_seconds,
    )
    if response.status_code != 200:
        raise AcceptanceError(
            f"middleware sanitized-audit endpoint returned {response.status_code}"
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise AcceptanceError("middleware sanitized-audit endpoint returned invalid JSON") from exc
    events = body.get("events") if isinstance(body, dict) else body
    if not isinstance(events, list):
        raise AcceptanceError("middleware sanitized-audit response must contain an events array")
    serialized = json.dumps(events, sort_keys=True).lower()
    for marker in FORBIDDEN_MIDDLEWARE_MARKERS:
        if marker in serialized:
            raise AcceptanceError(
                f"middleware audit contains prohibited password-reset material: {marker}"
            )
    return len(events)


def recipient_for_run(template: str, run_id: str) -> str:
    if template.count("{run_id}") != 1:
        raise AcceptanceError("E2E_RECIPIENT_TEMPLATE must contain {run_id} exactly once")
    recipient = template.format(run_id=run_id)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", recipient):
        raise AcceptanceError("E2E_RECIPIENT_TEMPLATE produced an invalid email address")
    return recipient.lower()


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def run(config: Config) -> dict[str, Any]:
    run_id = os.getenv("GITHUB_RUN_ID", secrets.token_hex(8)).lower()
    run_id = re.sub(r"[^a-z0-9]", "", run_id)[-20:]
    username = f"codestra-reset-e2e-{run_id}"
    recipient = recipient_for_run(config.recipient_template, run_id)
    initial_password = random_password()
    reset_password = random_password()
    github_mask(initial_password)
    github_mask(reset_password)
    github_mask(config.admin_client_secret)
    github_mask(config.imap_password)
    github_mask(config.middleware_audit_token)
    github_mask(config.klyrow_database_url)

    started_at = datetime.now(timezone.utc)
    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at": started_at.isoformat(),
        "issuer": config.issuer,
        "client_id": config.client_id,
        "redirect_uri_hash": sha256_text(config.redirect_uri),
        "expected_keycloak_sha": config.expected_keycloak_sha,
        "expected_klyrow_sha": config.expected_klyrow_sha,
        "recipient_hash": sha256_text(recipient),
        "gates": {},
    }

    verify_runtime_sha(
        config.keycloak_version_url,
        config.expected_keycloak_sha,
        config.request_timeout_seconds,
        "Keycloak",
    )
    verify_runtime_sha(
        config.klyrow_version_url,
        config.expected_klyrow_sha,
        config.request_timeout_seconds,
        "Klyrow",
    )
    report["gates"]["runtime_sha_binding"] = "PASS"

    token = admin_token(config)
    user_id = ""
    seen_message_ids: set[str] = set()
    try:
        user_id = create_test_user(config, token, username, recipient, initial_password)
        report["disposable_user_id_hash"] = sha256_text(user_id)
        report["gates"]["disposable_user_created"] = "PASS"

        old_session = create_authenticated_browser_session(config, username, initial_password)
        report["gates"]["pre_reset_session_created"] = "PASS"

        submitted_at = trigger_forgot_password(config, recipient)
        report["gates"]["forgot_password_ui"] = "PASS"
        report["gates"]["keycloak_reset_action_generated"] = "PASS"

        first_message, first_action_url = wait_for_reset_email(
            config, recipient, submitted_at, seen_message_ids
        )
        first_message_id = str(first_message.get("Message-ID", "")).strip()
        seen_message_ids.add(first_message_id)
        verify_postal_received_headers(first_message)
        klyrow_evidence = verify_klyrow_delivery(
            config, recipient, first_message_id, submitted_at
        )
        report["klyrow_delivery"] = klyrow_evidence
        report["gates"]["keycloak_smtp_authentication"] = "PASS"
        report["gates"]["klyrow_security_acceptance"] = "PASS"
        report["gates"]["postal_sent"] = "PASS"
        report["gates"]["controlled_inbox_received"] = "PASS"

        reset_password_with_action_link(config, first_action_url, reset_password)
        report["gates"]["reset_link_first_use"] = "PASS"
        assert_action_link_rejected(config, first_action_url, "used")
        report["gates"]["reset_link_replay_rejected"] = "PASS"

        create_authenticated_browser_session(config, username, reset_password)
        report["gates"]["new_password_login"] = "PASS"
        assert_old_session_invalidated(config, old_session)
        report["gates"]["existing_sessions_invalidated"] = "PASS"

        expiry_requested_at = datetime.now(timezone.utc)
        send_short_lived_update_password_action(config, token, user_id)
        second_message, second_action_url = wait_for_reset_email(
            config, recipient, expiry_requested_at, seen_message_ids
        )
        second_message_id = str(second_message.get("Message-ID", "")).strip()
        seen_message_ids.add(second_message_id)
        verify_postal_received_headers(second_message)
        verify_klyrow_delivery(
            config, recipient, second_message_id, expiry_requested_at
        )
        time.sleep(config.expiry_lifespan_seconds + config.expiry_grace_seconds)
        assert_action_link_rejected(config, second_action_url, "expired")
        report["gates"]["reset_link_expiration_enforced"] = "PASS"

        middleware_events = verify_middleware_secret_boundary(config, user_id, started_at)
        report["middleware_event_count"] = middleware_events
        report["gates"]["middleware_receives_no_reset_secret"] = "PASS"
    finally:
        if user_id:
            delete_test_user(config, token, user_id)
            report["gates"]["disposable_user_deleted"] = "PASS"

    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report["result"] = "PASS"
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report",
        default="evidence/password-reset-e2e.json",
        help="credential-free JSON evidence path",
    )
    args = parser.parse_args()
    report_path = Path(args.report).resolve()
    try:
        config = Config.from_environment(report_path)
        report = run(config)
        write_report(report_path, report)
    except Exception as exc:
        failure = {
            "schema_version": 1,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "result": "FAIL",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        try:
            write_report(report_path, failure)
        except Exception:
            pass
        print(f"PASSWORD_RESET_E2E=FAIL error={type(exc).__name__}", file=sys.stderr)
        return 1
    print("PASSWORD_RESET_E2E=PASS")
    print(f"EVIDENCE_PATH={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
