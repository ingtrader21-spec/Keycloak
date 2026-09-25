#!/usr/bin/env python3
"""Fail-closed validation for Codestra machine identities and service contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config"
CONTRACTS = CONFIG / "contracts"
ENDPOINTS = CONFIG / "endpoints"

ISSUER = "https://auth.codestra.co/realms/codestra"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"

MACHINE_IDS = [
    "kong-gateway",
    "middleware-api",
    "middleware-worker",
    "codestra-ai",
    "codestra-communication",
    "codestra-marketing",
    "codestra-social",
    "sdk-intake",
    "alertmanager",
    "ai-provider-adapter",
    "marketing-provider-adapter",
    "odoo-integration",
    "n8n-automation",
    "n8n-crm-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
    "provisioning-service",
    "monitoring-readonly",
]

EXPECTED_SERVICES: dict[str, tuple[str, bool, str | None]] = {
    "kong-gateway": ("edge", True, "KONG_GATEWAY_BASE_URL"),
    "middleware-api": ("resource_server", True, "MIDDLEWARE_API_BASE_URL"),
    "middleware-worker": ("workload", False, None),
    "codestra-ai": ("application", False, None),
    "codestra-communication": ("application", False, None),
    "codestra-marketing": ("application", False, None),
    "codestra-social": ("application", False, None),
    "sdk-intake": ("workload", False, None),
    "alertmanager": ("monitoring_writer", False, None),
    "ai-provider-adapter": ("adapter", True, "AI_PROVIDER_ADAPTER_BASE_URL"),
    "marketing-provider-adapter": (
        "adapter",
        True,
        "MARKETING_PROVIDER_ADAPTER_BASE_URL",
    ),
    "odoo-integration": ("adapter", True, "ODOO_INTEGRATION_BASE_URL"),
    "n8n-automation": ("automation", True, "N8N_AUTOMATION_BASE_URL"),
    "n8n-crm-automation": ("automation_workload", False, None),
    "vicidial-adapter": ("adapter", True, "VICIDIAL_ADAPTER_BASE_URL"),
    "telnexa-gateway": ("provider_gateway", True, "TELNEXA_GATEWAY_BASE_URL"),
    "klyrow-gateway": ("provider_gateway", True, "KLYROW_GATEWAY_BASE_URL"),
    "kyqra-gateway": ("provider_gateway", True, "KYQRA_GATEWAY_BASE_URL"),
    "postly-adapter": ("adapter", True, "POSTLY_ADAPTER_BASE_URL"),
    "provisioning-service": ("workload", False, None),
    "monitoring-readonly": ("monitoring", False, None),
}

EXPECTED_GRANTS: dict[tuple[str, str], set[str]] = {
    ("kong-gateway", "middleware-api"): {
        "middleware.request.forward",
        "middleware.status.read",
    },
    ("middleware-worker", "middleware-api"): {
        "crm.handoff.read",
        "crm.handoff.reconcile",
        "crm.handoff.write",
        "delivery.retry",
        "dlq.replay",
        "inbox.process",
        "outbox.dispatch",
    },
    ("codestra-ai", "middleware-api"): {"ai.inference.request"},
    ("codestra-communication", "middleware-api"): {
        "communication.email.request",
        "communication.sms.request",
    },
    ("codestra-marketing", "middleware-api"): {"marketing.campaign.request"},
    ("codestra-social", "middleware-api"): {"social.publish.request"},
    ("sdk-intake", "middleware-api"): {"leads.write", "surveys.write"},
    ("alertmanager", "middleware-api"): {"alerts.write"},
    ("odoo-integration", "middleware-api"): {
        "campaign.engine.read",
        "campaign.suppressions.write",
        "leads.journey.read",
        "odoo.delivery.result.publish",
        "odoo.events.publish",
    },
    ("middleware-api", "odoo-integration"): {
        "odoo.activities.write",
        "odoo.leads.read",
        "odoo.leads.write",
    },
    ("middleware-api", "n8n-automation"): {
        "workflow.status.read",
        "workflow.trigger",
    },
    ("n8n-automation", "middleware-api"): {
        "middleware.request.forward",
        "middleware.status.read",
        "workflow.result.publish",
    },
    ("n8n-crm-automation", "middleware-api"): {
        "automation.approval.read",
        "automation.approval.request",
        "automation.capability.read",
        "automation.command.crm",
        "automation.command.read",
        "automation.job.claim",
        "automation.job.complete",
        "automation.job.fail",
        "automation.job.heartbeat",
        "automation.job.read",
        "automation.job.step.write",
        "workflow.result.publish",
    },
    ("vicidial-adapter", "middleware-api"): {
        "callbacks.update",
        "recordings.metadata.publish",
        "telephony.events.publish",
    },
    ("middleware-api", "vicidial-adapter"): {
        "callbacks.dispatch",
        "telephony.commands.write",
    },
    ("middleware-worker", "telnexa-gateway"): {"sms.send", "sms.status.read"},
    ("telnexa-gateway", "middleware-api"): {
        "campaign.delivery_events.publish",
        "sms.events.publish",
        "sms.inbound.publish",
    },
    ("middleware-worker", "klyrow-gateway"): {
        "email.send",
        "email.status.read",
    },
    ("klyrow-gateway", "middleware-api"): {
        "campaign.delivery_events.publish",
        "email.events.publish",
        "email.inbound.publish",
    },
    ("middleware-api", "kyqra-gateway"): {
        "crawler.jobs.read",
        "crawler.jobs.submit",
        "crawler.results.read",
    },
    ("kyqra-gateway", "middleware-api"): {
        "crawler.progress.publish",
        "crawler.results.publish",
    },
    ("middleware-worker", "postly-adapter"): {
        "social.publish",
        "social.status.read",
    },
    ("middleware-worker", "ai-provider-adapter"): {
        "ai.provider.dispatch",
        "ai.provider.status.read",
    },
    ("middleware-worker", "marketing-provider-adapter"): {
        "marketing.provider.dispatch",
        "marketing.provider.status.read",
    },
    ("postly-adapter", "middleware-api"): {"social.events.publish"},
    ("provisioning-service", "middleware-api"): {
        "identity.request",
        "integration.configure",
        "tenant.provision",
    },
    ("monitoring-readonly", "middleware-api"): {
        "health.read",
        "metrics.read",
    },
}

EXPECTED_PROHIBITED_TARGETS = {
    "n8n-automation": [
        "odoo-integration",
        "vicidial-adapter",
        "telnexa-gateway",
        "klyrow-gateway",
        "kyqra-gateway",
        "postly-adapter",
        "ai-provider-adapter",
        "marketing-provider-adapter",
    ]
}

EXPECTED_ADMIN_BOUNDARIES = {
    "provisioning-service": {
        "keycloakAdminApiAccess": False,
        "prohibitedRealmManagementRoles": [
            "realm-admin",
            "manage-realm",
            "manage-clients",
        ],
    }
}
TENANT_ATTRIBUTE_CLIENTS = frozenset({"telnexa-gateway"})
TENANT_CLAIM_NAMES = frozenset(
    {"tenant_id", "tenant_ids", "tenant-id", "tenant-ids", "tenant.id", "tenant"}
)
TENANT_ATTRIBUTE_MAPPER = {
    "name": "tenant-ids-from-service-account",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": False,
    "config": {
        "user.attribute": "tenant_ids",
        "claim.name": "tenant_ids",
        "jsonType.label": "String",
        "id.token.claim": "false",
        "access.token.claim": "true",
        "userinfo.token.claim": "false",
        "multivalued": "true",
    },
}

EXPECTED_REQUIRED_CLAIMS = ["iss", "sub", "aud", "azp", "iat", "exp", "jti", "scope"]

WEBHOOK_PRODUCERS = {
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
}

WEBHOOK_REQUIRED_HEADERS = {
    "Authorization",
    "Content-Type",
    "Idempotency-Key",
    "X-Codestra-Event-Id",
    "X-Codestra-Event-Type",
    "X-Codestra-Source",
    "X-Codestra-Tenant-Id",
    "X-Codestra-Timestamp",
    "X-Codestra-Signature",
    "X-Correlation-Id",
}

WEBHOOK_SIGNATURE_FIELDS = [
    "version",
    "method",
    "path",
    "timestamp",
    "eventId",
    "sourceClientId",
    "bodySha256",
]

SCOPE_RE = re.compile(r"^[a-z][a-z0-9_]*(?:[.-][a-z0-9_]+)+$")
EVENT_RE = re.compile(
    r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*(?:\.[a-z0-9]+(?:_[a-z0-9]+)*){2,}$"
)
BASE_URL_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*_BASE_URL$")
SECRET_KEY_RE = re.compile(
    r"(?:secret|password|private[_-]?key|access[_-]?token|refresh[_-]?token|credential)",
    re.IGNORECASE,
)


class ContractError(RuntimeError):
    """Raised when identity desired state weakens or drifts."""


def fail(message: str) -> None:
    raise ContractError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"{path}: unable to load JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: document root must be an object")
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        fail(f"{label}: expected keys {sorted(expected)}, found {sorted(actual)}")


def no_committed_secrets(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            here = (*path, str(key))
            if SECRET_KEY_RE.search(str(key)) and child not in ("", None, False, [], {}):
                fail(f"committed secret-bearing field: {'.'.join(here)}")
            no_committed_secrets(child, here)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            no_committed_secrets(child, (*path, str(index)))


def endpoint_contract(base_url: str) -> dict[str, str]:
    realm_url = f"{base_url}/realms/codestra"
    return {
        "publicUrl": base_url,
        "adminApiBaseUrl": base_url,
        "realm": "codestra",
        "adminAuthenticationRealm": "master",
        "issuer": realm_url,
        "discoveryUrl": f"{realm_url}/.well-known/openid-configuration",
        "authorizationEndpoint": f"{realm_url}/protocol/openid-connect/auth",
        "tokenEndpoint": f"{realm_url}/protocol/openid-connect/token",
        "userInfoEndpoint": f"{realm_url}/protocol/openid-connect/userinfo",
        "jwksUri": f"{realm_url}/protocol/openid-connect/certs",
        "introspectionEndpoint": f"{realm_url}/protocol/openid-connect/token/introspect",
        "logoutEndpoint": f"{realm_url}/protocol/openid-connect/logout",
        "adminRealmEndpoint": f"{base_url}/admin/realms/codestra",
    }


def validate_endpoint_contracts() -> None:
    expected = {
        "codestra.json": endpoint_contract("https://auth.codestra.co"),
        "codestra-staging.json": endpoint_contract("https://auth-staging.codestra.co"),
    }
    for filename, wanted in expected.items():
        actual = load_json(ENDPOINTS / filename)
        if actual != wanted:
            fail(f"{filename}: canonical endpoint contract drift")


def validate_machine_contract(machine: dict[str, Any]) -> None:
    require_exact_keys(
        machine,
        {
            "issuer",
            "grantType",
            "maximumAccessTokenLifetimeSeconds",
            "secretStorage",
            "crossServiceAudienceAssignments",
            "clients",
        },
        "machine-clients",
    )
    if machine["issuer"] != ISSUER:
        fail("machine-clients: issuer drift")
    if machine["grantType"] != "client_credentials":
        fail("machine-clients: grant type must be client_credentials")
    ttl = machine["maximumAccessTokenLifetimeSeconds"]
    if not isinstance(ttl, int) or not 1 <= ttl <= 300:
        fail("machine-clients: token lifetime must be 1..300 seconds")
    if machine["secretStorage"] != "external-secret-store-only":
        fail("machine-clients: credentials must remain outside Git")
    if machine["crossServiceAudienceAssignments"] != "separate-reviewed-access-contracts":
        fail("machine-clients: cross-service audience policy drift")

    clients = machine["clients"]
    if not isinstance(clients, list):
        fail("machine-clients: clients must be an array")
    ids = [item.get("clientId") for item in clients if isinstance(item, dict)]
    if ids != MACHINE_IDS or len(ids) != len(set(ids)):
        fail(f"machine-clients: membership/order drift: {ids}")

    expected_keys = {
        "clientId",
        "clientType",
        "serviceAccountsEnabled",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "audience",
        "scopes",
        "provisioningState",
    }
    for index, item in enumerate(clients):
        if not isinstance(item, dict):
            fail(f"machine-clients[{index}]: entry must be an object")
        require_exact_keys(item, expected_keys, f"machine-clients[{index}]")
        cid = item["clientId"]
        if item["clientType"] != "confidential":
            fail(f"{cid}: machine client must be confidential")
        if item["serviceAccountsEnabled"] is not True:
            fail(f"{cid}: service account must be enabled")
        for field in (
            "standardFlowEnabled",
            "implicitFlowEnabled",
            "directAccessGrantsEnabled",
        ):
            if item[field] is not False:
                fail(f"{cid}: prohibited OAuth flow enabled: {field}")
        if item["audience"] != cid:
            fail(f"{cid}: registry audience must equal clientId")
        if item["scopes"] != [f"{cid}.access"]:
            fail(f"{cid}: registry scope drift")
        if item["provisioningState"] != "managed-protected-apply":
            fail(f"{cid}: provisioning state drift")


def validate_access_matrix(access: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    require_exact_keys(
        access,
        {
            "schemaVersion",
            "issuer",
            "tokenEndpoint",
            "jwksUri",
            "tokenPolicy",
            "services",
            "grants",
            "prohibitedDirectTargets",
            "administrativeBoundaries",
        },
        "service-access-matrix",
    )
    if access["schemaVersion"] != 1 or access["issuer"] != ISSUER:
        fail("service-access-matrix: schema or issuer drift")
    if access["tokenEndpoint"] != TOKEN_ENDPOINT:
        fail("service-access-matrix: token endpoint drift")
    if access["jwksUri"] != JWKS_URI:
        fail("service-access-matrix: JWKS URI drift")

    policy = access["tokenPolicy"]
    if not isinstance(policy, dict):
        fail("service-access-matrix: tokenPolicy must be an object")
    require_exact_keys(
        policy,
        {
            "grantType",
            "maximumAccessTokenLifetimeSeconds",
            "refreshTokensAllowed",
            "fullScopeAllowed",
            "secretStorage",
            "requiredClaims",
        },
        "tokenPolicy",
    )
    if policy["grantType"] != "client_credentials":
        fail("tokenPolicy: grant type drift")
    ttl = policy["maximumAccessTokenLifetimeSeconds"]
    if not isinstance(ttl, int) or not 1 <= ttl <= 300:
        fail("tokenPolicy: token lifetime must be 1..300 seconds")
    if policy["refreshTokensAllowed"] is not False:
        fail("tokenPolicy: machine refresh tokens are prohibited")
    if policy["fullScopeAllowed"] is not False:
        fail("tokenPolicy: full-scope mode is prohibited")
    if policy["secretStorage"] != "external-secret-store-only":
        fail("tokenPolicy: credentials must remain outside Git")
    if policy["requiredClaims"] != EXPECTED_REQUIRED_CLAIMS:
        fail("tokenPolicy: required machine-token claims drift")

    services = access["services"]
    if not isinstance(services, list):
        fail("service-access-matrix: services must be an array")
    service_ids = [item.get("clientId") for item in services if isinstance(item, dict)]
    if service_ids != MACHINE_IDS or len(service_ids) != len(set(service_ids)):
        fail(f"service-access-matrix: service membership/order drift: {service_ids}")

    service_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(services):
        if not isinstance(raw, dict):
            fail(f"services[{index}]: entry must be an object")
        cid = raw.get("clientId")
        if cid not in EXPECTED_SERVICES:
            fail(f"services[{index}]: unknown clientId")
        kind, resource_server, base_env = EXPECTED_SERVICES[cid]
        expected_keys = {"clientId", "kind", "resourceServer", "audience"}
        if resource_server:
            expected_keys.add("baseUrlEnvironment")
        require_exact_keys(raw, expected_keys, f"services[{index}]")
        if raw["kind"] != kind:
            fail(f"{cid}: service kind drift")
        if raw["resourceServer"] is not resource_server:
            fail(f"{cid}: resource-server classification drift")
        if raw["audience"] != cid:
            fail(f"{cid}: service audience must equal clientId")
        if resource_server:
            if raw["baseUrlEnvironment"] != base_env:
                fail(f"{cid}: base URL environment drift")
            if not BASE_URL_ENV_RE.fullmatch(raw["baseUrlEnvironment"]):
                fail(f"{cid}: invalid base URL environment name")
        service_by_id[cid] = raw

    grants_raw = access["grants"]
    if not isinstance(grants_raw, list) or not grants_raw:
        fail("service-access-matrix: grants must be a non-empty array")
    grants: dict[tuple[str, str], set[str]] = {}
    for index, raw in enumerate(grants_raw):
        if not isinstance(raw, dict):
            fail(f"grants[{index}]: entry must be an object")
        require_exact_keys(
            raw,
            {"callerClientId", "targetClientId", "audience", "scopes"},
            f"grants[{index}]",
        )
        caller = raw["callerClientId"]
        target = raw["targetClientId"]
        if caller not in service_by_id or target not in service_by_id:
            fail(f"grants[{index}]: unknown caller or target")
        if caller == target:
            fail(f"grants[{index}]: self-grants are prohibited")
        if raw["audience"] != target:
            fail(f"grants[{index}]: audience must equal targetClientId")
        if service_by_id[target]["resourceServer"] is not True:
            fail(f"grants[{index}]: target is not a resource server")
        scopes = raw["scopes"]
        if (
            not isinstance(scopes, list)
            or not scopes
            or scopes != sorted(scopes)
            or len(scopes) != len(set(scopes))
            or "*" in scopes
            or not all(isinstance(scope, str) and SCOPE_RE.fullmatch(scope) for scope in scopes)
        ):
            fail(f"grants[{index}]: invalid scope set")
        key = (caller, target)
        if key in grants:
            fail(f"grants[{index}]: duplicate caller-target grant")
        grants[key] = set(scopes)

    if grants != EXPECTED_GRANTS:
        missing = sorted(set(EXPECTED_GRANTS) - set(grants))
        extra = sorted(set(grants) - set(EXPECTED_GRANTS))
        changed = sorted(
            key
            for key in set(grants) & set(EXPECTED_GRANTS)
            if grants[key] != EXPECTED_GRANTS[key]
        )
        fail(
            "service-access-matrix: exact grant authority drift "
            f"(missing={missing}, extra={extra}, changed={changed})"
        )

    if access["prohibitedDirectTargets"] != EXPECTED_PROHIBITED_TARGETS:
        fail("service-access-matrix: n8n prohibited-target boundary drift")
    if access["administrativeBoundaries"] != EXPECTED_ADMIN_BOUNDARIES:
        fail("service-access-matrix: provisioning-service admin boundary drift")

    return grants


def validate_client_document(
    client_id: str,
    document: dict[str, Any],
    scopes: set[str] | None = None,
) -> None:
    if document.get("clientId") != client_id:
        fail(f"{client_id}: clientId drift")
    if document.get("protocol") != "openid-connect":
        fail(f"{client_id}: protocol drift")
    if document.get("enabled") is not True:
        fail(f"{client_id}: client must be enabled")
    if document.get("publicClient") is not False:
        fail(f"{client_id}: machine client must not be public")
    if document.get("serviceAccountsEnabled") is not True:
        fail(f"{client_id}: service account must be enabled")
    if document.get("fullScopeAllowed") is not False:
        fail(f"{client_id}: full-scope mode is prohibited")
    for field in (
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "authorizationServicesEnabled",
    ):
        if document.get(field) is not False:
            fail(f"{client_id}: prohibited flow/service enabled: {field}")
    if document.get("redirectUris") != [] or document.get("webOrigins") != []:
        fail(f"{client_id}: browser redirect/origin is prohibited")

    attributes = document.get("attributes")
    if not isinstance(attributes, dict):
        fail(f"{client_id}: attributes must be an object")
    try:
        ttl = int(attributes.get("access.token.lifespan", "0"))
    except (TypeError, ValueError):
        fail(f"{client_id}: invalid token lifetime")
    if not 1 <= ttl <= 300:
        fail(f"{client_id}: token lifetime must be 1..300 seconds")
    if attributes.get("oauth2.device.authorization.grant.enabled") != "false":
        fail(f"{client_id}: OAuth device flow is prohibited")
    if attributes.get("oidc.ciba.grant.enabled") != "false":
        fail(f"{client_id}: CIBA is prohibited")

    no_committed_secrets(document)

    serialized = json.dumps(document, sort_keys=True)
    if re.search(r'"tenant[_-]?id"\s*:', serialized, re.IGNORECASE):
        fail(f"{client_id}: static tenant mapper is prohibited")

    mappers = document.get("protocolMappers", [])
    if not isinstance(mappers, list):
        fail(f"{client_id}: protocolMappers must be an array")
    tenant_mappers: list[dict[str, Any]] = []
    for mapper in mappers:
        if not isinstance(mapper, dict):
            fail(f"{client_id}: invalid mapper shape")
        config = mapper.get("config", {})
        if not isinstance(config, dict):
            fail(f"{client_id}: invalid mapper config")
        claim_name = str(config.get("claim.name", "")).strip().lower()
        if claim_name in TENANT_CLAIM_NAMES:
            tenant_mappers.append(mapper)

    if client_id in TENANT_ATTRIBUTE_CLIENTS:
        if tenant_mappers != [TENANT_ATTRIBUTE_MAPPER]:
            fail(
                f"{client_id}: tenant claim must come from the service-account "
                "tenant_ids attribute"
            )
    elif tenant_mappers:
        fail(f"{client_id}: static tenant mapper is prohibited")

    if scopes is None:
        return

    audience_mappers = [
        mapper
        for mapper in mappers
        if mapper.get("protocolMapper") == "oidc-audience-mapper"
    ]
    if (
        len(audience_mappers) != 1
        or audience_mappers[0].get("config", {}).get("included.custom.audience")
        != "middleware-api"
        or audience_mappers[0].get("config", {}).get("access.token.claim") != "true"
        or audience_mappers[0].get("config", {}).get("id.token.claim") != "false"
    ):
        fail(f"{client_id}: middleware audience mapper drift")

    scope_mappers = [
        mapper for mapper in mappers if mapper.get("name") == "reviewed-service-scopes"
    ]
    if len(scope_mappers) != 1:
        fail(f"{client_id}: reviewed scope mapper missing")
    config = scope_mappers[0].get("config", {})
    actual_scopes = set(str(config.get("claim.value", "")).split())
    if actual_scopes != scopes:
        fail(f"{client_id}: configured scope drift: {sorted(actual_scopes)}")
    if (
        scope_mappers[0].get("protocolMapper") != "oidc-hardcoded-claim-mapper"
        or config.get("claim.name") != "scope"
        or config.get("jsonType.label") != "String"
        or config.get("access.token.claim") != "true"
        or config.get("id.token.claim") != "false"
        or config.get("userinfo.token.claim") != "false"
        or config.get("access.tokenResponse.claim") != "false"
    ):
        fail(f"{client_id}: reviewed scope mapper configuration drift")


def validate_webhook_contract(
    webhooks: dict[str, Any],
    grants: dict[tuple[str, str], set[str]],
) -> None:
    require_exact_keys(
        webhooks,
        {
            "schemaVersion",
            "issuer",
            "consumerClientId",
            "consumerBaseUrlEnvironment",
            "security",
            "webhooks",
            "eventEnvelopeContract",
        },
        "webhook-contracts",
    )
    if webhooks["schemaVersion"] != 1 or webhooks["issuer"] != ISSUER:
        fail("webhook-contracts: schema or issuer drift")
    if webhooks["consumerClientId"] != "middleware-api":
        fail("webhook-contracts: middleware-api must remain the consumer")
    if webhooks["consumerBaseUrlEnvironment"] != "MIDDLEWARE_API_BASE_URL":
        fail("webhook-contracts: consumer base URL environment drift")
    if webhooks["eventEnvelopeContract"] != "codestra.event-envelope.v1":
        fail("webhook-contracts: event-envelope contract drift")

    security = webhooks["security"]
    if not isinstance(security, dict):
        fail("webhook-contracts: security policy must be an object")
    require_exact_keys(
        security,
        {
            "authorization",
            "signatureAlgorithm",
            "signatureVersion",
            "maximumClockSkewSeconds",
            "replayRetentionSeconds",
            "canonicalSignatureFields",
            "requiredHeaders",
            "contentType",
            "signatureHeaderFormat",
            "idempotencyKeySource",
        },
        "webhook security",
    )
    if security["authorization"] != "oidc_bearer":
        fail("webhook security: OIDC bearer authorization is required")
    if security["signatureAlgorithm"] != "hmac-sha256":
        fail("webhook security: HMAC-SHA256 is required")
    if security["signatureVersion"] != "v1":
        fail("webhook security: signature version drift")
    if security["maximumClockSkewSeconds"] != 300:
        fail("webhook security: maximum clock skew must be 300 seconds")
    replay = security["replayRetentionSeconds"]
    if not isinstance(replay, int) or replay < 86400:
        fail("webhook security: replay retention must be at least 24 hours")
    if security["canonicalSignatureFields"] != WEBHOOK_SIGNATURE_FIELDS:
        fail("webhook security: canonical signature fields drift")
    if set(security["requiredHeaders"]) != WEBHOOK_REQUIRED_HEADERS:
        fail("webhook security: required header set drift")
    if len(security["requiredHeaders"]) != len(WEBHOOK_REQUIRED_HEADERS):
        fail("webhook security: duplicate required headers")
    if security["contentType"] != "application/json":
        fail("webhook security: content type drift")
    if security["signatureHeaderFormat"] != "sha256=<lowercase-hex>":
        fail("webhook security: signature header format drift")
    if security["idempotencyKeySource"] != "X-Codestra-Event-Id":
        fail("webhook security: idempotency source drift")

    hooks = webhooks["webhooks"]
    if not isinstance(hooks, list) or not hooks:
        fail("webhook-contracts: webhooks must be a non-empty array")
    hook_ids: set[str] = set()
    hook_paths: set[str] = set()
    event_types: set[str] = set()
    producers: set[str] = set()

    expected_hook_keys = {
        "id",
        "producerClientId",
        "consumerClientId",
        "audience",
        "requiredScope",
        "path",
        "eventTypes",
        "delivery",
    }
    for index, hook in enumerate(hooks):
        if not isinstance(hook, dict):
            fail(f"webhooks[{index}]: entry must be an object")
        require_exact_keys(hook, expected_hook_keys, f"webhooks[{index}]")
        hook_id = hook["id"]
        if not isinstance(hook_id, str) or not hook_id or hook_id in hook_ids:
            fail(f"webhooks[{index}]: duplicate or invalid id")
        hook_ids.add(hook_id)

        producer = hook["producerClientId"]
        if producer not in MACHINE_IDS:
            fail(f"{hook_id}: unknown producer")
        if hook["consumerClientId"] != "middleware-api":
            fail(f"{hook_id}: consumer drift")
        if hook["audience"] != "middleware-api":
            fail(f"{hook_id}: audience drift")
        if hook["requiredScope"] not in grants.get((producer, "middleware-api"), set()):
            fail(f"{hook_id}: required scope is not granted to producer")

        path = hook["path"]
        if (
            not isinstance(path, str)
            or not path.startswith("/api/v1/")
            or "://" in path
            or path in hook_paths
        ):
            fail(f"{hook_id}: path must be unique, relative, and under /api/v1/")
        hook_paths.add(path)

        if hook["delivery"] != "at_least_once":
            fail(f"{hook_id}: delivery must be at_least_once")
        events = hook["eventTypes"]
        if not isinstance(events, list) or not events:
            fail(f"{hook_id}: eventTypes must be a non-empty array")
        for event in events:
            if (
                not isinstance(event, str)
                or not EVENT_RE.fullmatch(event)
                or event in event_types
            ):
                fail(f"{hook_id}: duplicate or invalid event type: {event!r}")
            event_types.add(event)
        producers.add(producer)

    if producers != WEBHOOK_PRODUCERS:
        fail(
            "webhook-contracts: producer coverage drift "
            f"(expected={sorted(WEBHOOK_PRODUCERS)}, actual={sorted(producers)})"
        )


def validate_policy_and_client_documents() -> None:
    managed = load_json(CONFIG / "policy" / "managed-clients.json").get("clients")
    creatable = load_json(CONFIG / "policy" / "creatable-clients.json").get("clients")
    if not isinstance(managed, list) or managed != creatable:
        fail("managed/creatable policy must match exactly")
    if len(managed) != len(set(managed)):
        fail("managed-client policy contains duplicates")

    client_documents: dict[str, dict[str, Any]] = {}
    for path in sorted((CONFIG / "clients").glob("*.json")):
        document = load_json(path)
        cid = document.get("clientId")
        if not isinstance(cid, str) or not cid:
            fail(f"{path}: missing clientId")
        if cid in client_documents:
            fail(f"duplicate client document: {cid}")
        client_documents[cid] = document

    if set(client_documents) != set(managed):
        fail("configured clients do not exactly match managed-client policy")

    exact_scopes = {
        "sdk-intake": {"leads.write", "surveys.write"},
        "alertmanager": {"alerts.write"},
    }
    for cid, scopes in exact_scopes.items():
        document = client_documents.get(cid)
        if document is None:
            fail(f"{cid}: client document is missing")
        validate_client_document(cid, document, scopes)
        allowlist = load_json(CONFIG / "export-allowlists" / f"{cid}.json")
        require_exact_keys(
            allowlist,
            {"clientId", "topLevelFields", "attributeFields"},
            f"{cid} export allowlist",
        )
        if allowlist["clientId"] != cid:
            fail(f"{cid}: export allowlist clientId drift")
        if set(allowlist["topLevelFields"]) != set(document):
            fail(f"{cid}: export allowlist top-level coverage drift")
        if set(allowlist["attributeFields"]) != set(document["attributes"]):
            fail(f"{cid}: export allowlist attribute coverage drift")
        if len(allowlist["topLevelFields"]) != len(set(allowlist["topLevelFields"])):
            fail(f"{cid}: duplicate top-level allowlist fields")
        if len(allowlist["attributeFields"]) != len(set(allowlist["attributeFields"])):
            fail(f"{cid}: duplicate attribute allowlist fields")

    for cid in ("kong-gateway", "n8n-automation"):
        document = client_documents.get(cid)
        if document is None:
            fail(f"{cid}: shared-gateway client document is missing")
        validate_client_document(cid, document)


def validate(
    machine: dict[str, Any] | None = None,
    access: dict[str, Any] | None = None,
    webhooks: dict[str, Any] | None = None,
) -> None:
    machine = machine or load_json(CONTRACTS / "machine-clients.json")
    access = access or load_json(CONTRACTS / "service-access-matrix.json")
    webhooks = webhooks or load_json(CONTRACTS / "webhook-contracts.json")

    validate_endpoint_contracts()
    validate_machine_contract(machine)
    grants = validate_access_matrix(access)
    validate_webhook_contract(webhooks, grants)
    validate_policy_and_client_documents()

    print(f"SERVICE_CLIENTS={len(access['services'])}")
    print(f"SERVICE_GRANTS={len(grants)}")
    print(f"WEBHOOK_CONTRACTS={len(webhooks['webhooks'])}")
    print("SDK_INTAKE_SCOPES=leads.write,surveys.write")
    print("ALERTMANAGER_SCOPES=alerts.write")
    print("STATIC_SHARED_TENANT_MAPPERS=0")
    print("ENDPOINT_CONTRACTS=PASS")
    print("MACHINE_IDENTITY_CONTRACT=PASS")
    print("SERVICE_ACCESS_POLICY=PASS")
    print("WEBHOOK_SECURITY_POLICY=PASS")
    print("ADMINISTRATIVE_BOUNDARIES=PASS")
    print("SERVICE_INTEGRATION_VALIDATION=PASS")


def main() -> int:
    try:
        validate()
    except ContractError as exc:
        print(f"SERVICE_INTEGRATION_ERROR={exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
