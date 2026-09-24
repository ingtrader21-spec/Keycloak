#!/usr/bin/env python3
"""Offline MCR contract certification; never a JWT verifier or live authorization API."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / 'contracts/mcr-identity-v1.json'
MATRIX_PATH = ROOT / 'config/certification/mcr-token-matrix.v1.json'
CONTRACT_SHA256 = '9e4ddd8296f4b9d299a3f86139e3dfa03c4f40f8c0ff9757953db2d0f6484534'
MATRIX_SHA256 = '6ae4ff89253da909779ef1cf204c94ca644895dbf547d4ceba71937753d73ebe'


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def validate_contract(contract):
    if digest(contract) != CONTRACT_SHA256:
        raise ValueError('unreviewed MCR policy change')
    for path, expected in contract['sourcePins'].items():
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != expected:
            raise ValueError(f'V3 source drift: {path}')


def strings(value):
    return (type(value) is list and all(type(v) is str and v.strip() == v and v
                                      for v in value) and len(set(value)) == len(value))


def evaluate(contract, fixture):
    """Evaluate synthetic evidence. All non-claim inputs are trusted verifier context.

    Do not expose this function to request JSON: signature, binding, grant and
    replay evidence must come from their respective runtime authorities.
    """
    validate_contract(contract)
    if type(fixture) is not dict:
        return ['shape']
    try:
        return _evaluate(contract, fixture)
    except (KeyError, TypeError, ValueError, AttributeError):
        return ['shape']


def _evaluate(contract, f):
    c = f['claims']
    if type(c) is not dict or any(key not in c for key in contract['requiredClaims']):
        return ['claims']
    failures = []
    def require(ok, boundary):
        if not ok:
            failures.append(boundary)
    op = contract['operations'][f['operation']]
    environment = f['environment']
    require(c['iss'] == contract['issuers'][environment], 'issuer')
    aud = c['aud']
    require(aud == contract['audience'] or
            (strings(aud) and aud == [contract['audience']]), 'audience')
    require(f['signatureVerified'] is True and f['algorithm'] == 'RS256', 'signature')
    require(c['typ'] == 'Bearer', 'token_type')
    for key in ('sub', 'azp', 'jti', 'tenant_id'):
        require(type(c[key]) is str and bool(c[key].strip()) and '*' not in c[key], key)
    require(type(f['expectedTenant']) is str and bool(f['expectedTenant'].strip())
            and c['tenant_id'] == f['expectedTenant'], 'tenant')
    now = f['now']
    require(all(type(v) is int for v in (now, c['iat'], c['exp'], c['nbf']))
            and c['nbf'] <= now and c['iat'] <= now < c['exp']
            and 0 < c['exp'] - c['iat'] <= 300, 'expiry')
    family = contract['aliases'].get(f['callerFamily'], f['callerFamily'])
    require(family == contract['callerFamily'], 'family')
    require(type(f['bindings']) is list, 'binding')
    matches = [b for b in f['bindings'] if type(b) is dict and b.get('azp') == c['azp']
               and b.get('environment') == environment and b.get('tenant') == c['tenant_id']]
    if len(matches) != 1:
        return sorted(set(failures + ['binding']))
    b = matches[0]
    require(b['reviewed'] is True and b['family'] == family and b['enabled'] is True, 'binding')
    require(c['azp'] not in contract['protectedClients'] and c['azp'] != family
            and c['azp'] not in contract['aliases'], 'azp')
    require(b['tenantBinding'] == 'reviewed-per-tenant', 'tenant')
    actor = b['actorKind']
    require(actor in op['actors'] and f['actorKind'] == actor, 'actor')
    scopes = c['scope'].split() if type(c['scope']) is str else []
    require(strings(scopes) and op['scope'] in scopes
            and set(scopes) <= set(b['scopes'])
            and set(scopes) <= set(contract['allowedScopes']), 'scope')
    roles = c['realm_access']['roles']
    require(strings(roles) and set(roles) <= set(b['roles'])
            and set(roles) <= {'platform-operator'}, 'role')
    require(op['role'] is None or op['role'] in roles, 'role')
    require(b['fullScopeAllowed'] is False and b['defaultPrivilegedScopes'] == []
            and b['implicitFlowEnabled'] is False
            and b['directAccessGrantsEnabled'] is False, 'client_policy')
    if actor == 'service':
        require(f['grant'] == {'type': 'client_credentials', 'pkce': False}
                and b['serviceAccountsEnabled'] is True and b['publicClient'] is False
                and b['standardFlowEnabled'] is False and b['refreshTokensEnabled'] is False,
                'service_account')
        require(c['sub'] == b['serviceAccountSubject'] and bool(b['serviceAccountSubject']), 'subject')
        require(not roles and 'platform.command.replay' not in scopes, 'service_privilege')
        require(c['azp'] not in ('kong-gateway', 'n8n-automation'), 'tenant')
    elif actor == 'user':
        require(f['grant'] == {'type': 'authorization_code', 'pkce': 'S256'}
                and b['standardFlowEnabled'] is True
                and b['serviceAccountsEnabled'] is False, 'human_grant')
        require(strings(c['amr']) and 'mfa' in c['amr'], 'mfa')
        require(type(c['auth_time']) is int and 0 <= now - c['auth_time'] <= 300, 'mfa_freshness')
    else:
        failures.append('actor')
    if f['operation'] == 'replay':
        require(f['operationTenant'] == c['tenant_id'], 'tenant')
        require(f['independentApprovalVerified'] is True, 'approval')
        require(f['replayReservation'] == 'reserved' and f['replayStoreHealthy'] is True,
                'replay')
    return sorted(set(failures))


def certify_matrix(contract, matrix):
    validate_contract(contract)
    if digest(matrix) != MATRIX_SHA256:
        raise ValueError('unreviewed or incomplete MCR matrix')
    counts = {'positiveCases': 0, 'negativeCases': 0}
    for case in matrix['cases']:
        fixture = copy.deepcopy(matrix['fixtures'][case['fixture']])
        for path, value in case.get('mutations', {}).items():
            parent = fixture
            parts = path.split('.')
            for key in parts[:-1]:
                parent = parent[int(key)] if isinstance(parent, list) else parent[key]
            parent[parts[-1]] = value
        failures = evaluate(contract, fixture)
        if (not failures) != (case['expect'] == 'ACCEPT'):
            raise ValueError(f"{case['id']}: unexpected verdict {failures}")
        if case['expect'] == 'REJECT' and case['mustFail'] not in failures:
            raise ValueError(f"{case['id']}: missing expected boundary {failures}")
        counts['positiveCases' if not failures else 'negativeCases'] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, default=CONTRACT_PATH)
    parser.add_argument('--matrix', type=Path, default=MATRIX_PATH)
    args = parser.parse_args()
    try:
        report = certify_matrix(load_json(args.contract), load_json(args.matrix))
    except (ValueError, OSError, TypeError) as error:
        print(f'MCR_IDENTITY_CONTRACT=FAIL: {error}')
        return 1
    print('MCR_IDENTITY_CONTRACT=PASS')
    print(json.dumps(report, sort_keys=True))
    print('KEYCLOAK_LIVE_APPLY=PROHIBITED')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
