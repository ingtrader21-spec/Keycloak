# Automated Production Gates

This repository is intended to support automated promotion without mandatory human pull-request approval, while preserving deterministic production safety gates.

## Merge policy
- Required approving reviews: 0.
- Required Code Owner reviews: off.
- Required status checks: on.
- Strict/up-to-date branch requirement: on.
- Conversation resolution: on.
- Force pushes and protected-branch deletion: blocked.
- Auto-merge: enabled.
- Administrator bypass is not part of the normal release path.

## Release policy
A merge does not authorize unsafe identity changes. Production promotion still requires source authority, immutable digest pinning, realm/client contract validation, security checks, rollback evidence, staging certification, and read-only production verification.

For server `65.109.65.169`, preserve issuer/JWKS, PKCE, audience, service-account, role/scope, tenant-claim, MFA/session, source SHA, digest, and rollback evidence. No auth bypass is permitted. SSH access controls must not be changed.
