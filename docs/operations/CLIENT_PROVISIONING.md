# Machine client provisioning

1. Review the caller/target/scopes entry and rendered overlay.
2. Generate a unique high-entropy credential outside Git.
3. Store it under that client's exact protected Environment secret name from
   `machine-secret-destinations.json`.
4. Run check from the exact merged `main` SHA.
5. Independently review every create/update and the plan SHA-256.
6. Run protected apply with the exact review artifact.
7. Deliver the same credential to only the named workload through its approved
   secret provider.
8. Obtain a five-minute Client Credentials token and inspect `iss`, `aud`,
   `azp`, `exp`, `jti`, and `scope`.
9. Verify the target accepts the authorized call and rejects wrong audience,
   missing scope, and unrelated clients.

Do not record the credential in evidence. Evidence records client ID, secret
provider reference, timestamps, plan/run IDs, and pass/fail only. A failed or
partial create follows the reviewed disable-first rollback process; automatic
deletion is prohibited.
