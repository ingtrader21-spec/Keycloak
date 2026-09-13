#!/usr/bin/env python3
"""Fail closed on any undeclared identity policy, including under python -O.

This source-only policy is intentionally explicit: adding clients, claims, roles
or permissions requires updating and reviewing the validator with the contract.
"""
import argparse
import json
from pathlib import Path

EXPECTED_POLICY = {'contract_version': '1.0',
 'realm': 'kyyow',
 'issuer': 'https://auth.kyyow.com/realms/kyyow',
 'status': 'prepared-not-applied',
 'identity_owner': 'appolon1908-hue/Keycloak',
 'tenant_model': {'organization_group_pattern': '/kyyow/enterprises/{tenant_id}',
                  'workspace_group_pattern': '/kyyow/enterprises/{tenant_id}/workspaces/{workspace_id}',
                  'access_token_claims': ['tenant_id', 'workspace_ids', 'roles'],
                  'id_token_claims': ['tenant_id', 'workspace_ids', 'roles'],
                  'single_tenant_per_session': True,
                  'tenant_claim_required': True},
 'realm_roles': ['organization-owner',
                 'administrator',
                 'data-engineer',
                 'researcher',
                 'sales-analyst',
                 'compliance-officer',
                 'developer',
                 'viewer',
                 'platform-superadmin'],
 'clients': [{'client_id': 'kyyow-portal',
              'type': 'public-browser',
              'authorization_code_flow': True,
              'pkce_method': 'S256',
              'implicit_flow': False,
              'direct_access_grants': False,
              'service_accounts': False,
              'redirect_uris': ['https://app.kyyow.com/auth/callback'],
              'web_origins': ['https://app.kyyow.com'],
              'audiences': ['kyyow-api']},
             {'client_id': 'kyyow-api-service',
              'type': 'confidential-service',
              'authorization_code_flow': False,
              'direct_access_grants': False,
              'service_accounts': True,
              'preferred_authentication': ['tls_client_auth', 'private_key_jwt'],
              'audiences': ['kyyow-api'],
              'scopes': ['search.read', 'datasets.read', 'datasets.write', 'exports.write']},
             {'client_id': 'kyyow-middleware-odoo',
              'type': 'confidential-service',
              'authorization_code_flow': False,
              'direct_access_grants': False,
              'service_accounts': True,
              'preferred_authentication': ['tls_client_auth', 'private_key_jwt'],
              'audiences': ['kyyow-middleware'],
              'scopes': ['odoo.kpi.write', 'odoo.incident.write']},
             {'client_id': 'kyyow-observability-readonly',
              'type': 'confidential-service',
              'authorization_code_flow': False,
              'direct_access_grants': False,
              'service_accounts': True,
              'preferred_authentication': ['tls_client_auth', 'private_key_jwt'],
              'audiences': ['kyyow-observability'],
              'scopes': ['metrics.read', 'logs.read', 'traces.read']}],
 'admin_boundary': {'admin_console_public_to_all_networks': False,
                    'mfa_required': True,
                    'platform_superadmin_separate_from_tenant_admin': True,
                    'service_accounts_cannot_receive_human_roles': True,
                    'break_glass_accounts_externally_governed': True},
 'token_policy': {'access_token_lifespan_seconds': 300,
                  'service_token_lifespan_seconds': 300,
                  'refresh_token_rotation': True,
                  'reuse_refresh_tokens': False,
                  'implicit_flow_enabled': False,
                  'password_grant_enabled': False},
 'security': {'browser_tokens_in_local_storage': False,
              'wildcard_redirect_uris': False,
              'wildcard_web_origins': False,
              'client_secrets_in_repository': False,
              'tenant_claim_derived_from_request_headers': False,
              'deployment_authorized': False}}


def validate(actual, expected=EXPECTED_POLICY, path="contract"):
    if type(actual) is not type(expected):
        raise ValueError(f"{path}: invalid type")
    if isinstance(expected, dict):
        if actual.keys() != expected.keys():
            raise ValueError(f"{path}: missing or unknown fields")
        for key, value in expected.items():
            validate(actual[key], value, f"{path}.{key}")
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise ValueError(f"{path}: invalid list length")
        for index, value in enumerate(expected):
            validate(actual[index], value, f"{path}[{index}]")
    elif path in {"contract.token_policy.access_token_lifespan_seconds",
                   "contract.token_policy.service_token_lifespan_seconds"}:
        if not 1 <= actual <= 300:
            raise ValueError(f"{path}: lifespan must be between 1 and 300 seconds")
    elif actual != expected:
        raise ValueError(f"{path}: unapproved policy value")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=Path(__file__).resolve().parents[1] / "contracts/kyyow-saas-identity-v1.json")
    args = parser.parse_args()
    try:
        validate(json.loads(args.contract.read_text()))
    except (ValueError, OSError) as error:
        raise SystemExit(f"KYYOW_IDENTITY_CONTRACT=FAIL: {error}") from error
    print("KYYOW_IDENTITY_CONTRACT=PASS")


if __name__ == "__main__":
    main()
