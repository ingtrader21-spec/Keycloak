from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLIENTS = ROOT / "config" / "clients"
TENANT_MAPPER = {
    "user.attribute": "tenant_id",
    "claim.name": "tenant_id",
    "jsonType.label": "String",
    "id.token.claim": "false",
    "access.token.claim": "true",
    "userinfo.token.claim": "false",
    "multivalued": "false",
}


class TenantBoundServiceClientTests(unittest.TestCase):
    def test_middleware_command_callers_emit_service_account_tenant(self) -> None:
        for client_id in ("kong-gateway", "n8n-automation"):
            client = json.loads(
                (CLIENTS / f"{client_id}.json").read_text(encoding="utf-8")
            )
            mappers = {item["name"]: item for item in client["protocolMappers"]}
            mapper = mappers["tenant-id-from-service-account"]
            self.assertEqual(mapper["protocolMapper"], "oidc-usermodel-attribute-mapper")
            self.assertEqual(mapper["config"], TENANT_MAPPER)
            self.assertNotIn("tenant_id", json.dumps(client.get("attributes", {})))


if __name__ == "__main__":
    unittest.main()
