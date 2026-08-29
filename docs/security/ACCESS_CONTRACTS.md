# Service access contracts

The authoritative authorization relationship is:

```text
callerClientId -> targetClientId/audience -> exact scopes
```

Only entries in `config/contracts/service-access-matrix.json` are allowed.
Absence is denial. The renderer converts each caller's grants into exact
audience and scope mappers, and validation rejects unknown services, duplicate
edges, self-grants, non-resource targets, wildcard scopes, unsorted scopes,
unreviewed n8n-to-provider access, provisioning realm administration, and
monitoring scopes other than `health.read` and `metrics.read`.

Authentication is not authorization. Kong and each resource server must still
validate the canonical issuer, its own audience, expiry, signature, caller
identity, and required scopes. Live positive and negative enforcement remains a
release-evidence requirement.
