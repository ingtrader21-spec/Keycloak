# Token and session policy

The managed realm overlay defines:

| Control | Value |
| --- | ---: |
| Access token | 300 seconds maximum |
| Implicit-flow token | 0 seconds; implicit grants are prohibited |
| Refresh-token reuse | 0; rotation/revocation enabled |
| User-generated action token | 900 seconds |
| Administrator execute-actions token | 43,200 seconds |
| SSO idle / maximum | 1,800 / 28,800 seconds |
| Client session idle / maximum | 1,800 / 28,800 seconds |
| Offline idle / maximum | 2,592,000 / 7,776,000 seconds |

Machine clients use Client Credentials, receive no refresh token by policy, and
have a maximum five-minute access token. A client-specific exception requires a
reviewed contract change; it must not increase the realm default implicitly.

Applications and Kong must validate signature, canonical issuer, intended
audience, expiration, and required scopes. Possession of a valid token does not
grant cross-service access without an explicit caller-to-audience contract.
