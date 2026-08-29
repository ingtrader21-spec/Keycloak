# Browser client policy

Human-facing clients use Authorization Code with PKCE `S256`. They are public clients unless a separately reviewed server-side confidential-client design proves that a secret can be protected. Implicit flow and direct/password grants are disabled.

Every production redirect URI, post-logout redirect and web origin is an exact HTTPS value owned by the corresponding application. Wildcards, `+`, production localhost entries and origin reflection are forbidden. Browser clients receive only reviewed scopes and audiences, use the realm session/token policy, and must clear their application session during RP-initiated logout.

The domain registry and client-overlay validators reject wildcard or non-HTTPS redirect/origin values and require PKCE and disabled legacy grants. Contract tests cover the exact approved values; live release evidence must additionally prove an unregistered redirect is rejected. Secrets must never be embedded in browser code.
