# VICIdial call-lifecycle event identity contract

This source-only contract extends the existing `vicidial-adapter -> middleware-api`
webhook allowlist to the exact lifecycle event namespace emitted by the protected
VICIdial/Asterisk adapter. It does not add a client, scope, audience, realm role,
secret, credential, dialing permission, AMI command permission, Odoo permission,
or production activation.

```text
producer       = vicidial-adapter
consumer       = middleware-api
audience       = middleware-api
scope          = telephony.events.publish
path           = /api/v1/vicidial/events
delivery       = at_least_once
signature      = HMAC-SHA256 v1
machine token  = client_credentials, <= 300 seconds
```

The authoritative AMI lifecycle namespace is
`codestra.vicidial.call.lifecycle.*`. The allowlist is explicit rather than a
wildcard and covers created, offered, ringing, answered, connected, held,
resumed, transfer-started, transfer-completed, hangup, completed, failed, and
missed states. The existing canonical started, completed, and callback event
types remain for compatibility with the already published integration contract.

No event name grants call placement, originate, AMI command, ARI command,
carrier, campaign mutation, or production dialing authority. Middleware and
Odoo must pin and validate this exact event list before any staging projection
is enabled.
