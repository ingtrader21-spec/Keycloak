"""Offline tests for scripts/certify_cross_repo_identity_parity.py.

Kong and Caddy fixtures are synthesized from the frozen route contract, so the
tests prove the comparison logic without reading sibling repositories.
"""

from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts import certify_cross_repo_identity_parity as parity


CONTRACT = parity.load_json(parity.EDGE_CONTRACT)
SEGMENT = "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"


def kong_fixture(contract: dict) -> dict:
    return {
        "contract": {"sha256": parity.contract_digest(contract)},
        "routes": [
            {
                "operation_id": r["operation_id"],
                "method": r["method"],
                "path": r["path"],
                "issuer": parity.PRODUCTION_ISSUER,
                "audience": r["audience"],
                "scope": r["scope"],
                "azp": r["calling_client"],
                "authentication": r["auth"],
            }
            for r in contract["routes"]
            if r["classification"] == "shared_edge"
        ],
    }


def caddy_fixture(contract: dict, extra: tuple[dict, ...] = ()) -> str:
    by_method: dict[str, list[str]] = {}
    for r in [*contract["routes"], *extra]:
        if r["classification"] == "shared_edge" or r in extra:
            parts = [SEGMENT if p.startswith("{") else re.escape(p) for p in r["path"].split("/")]
            by_method.setdefault(r["method"], []).append("/".join(parts))
    blocks = []
    for method, paths in sorted(by_method.items()):
        name = f"canonical_{method.lower()}"
        blocks.append(
            f"\t@{name} {{\n"
            f"\t\tmethod {method}\n"
            f"\t\tpath_regexp ^({'|'.join(paths)})$\n"
            f"\t}}\n"
            f"\thandle @{name} {{\n"
            f"\t\treverse_proxy {{$CADDY_KONG_UPSTREAM}} {{\n"
            f"\t\t}}\n"
            f"\t}}"
        )
    return "\n".join(blocks) + "\n"


class CrossRepoIdentityParityCertificationTests(unittest.TestCase):
    def run_certify(self, contract: dict, kong: dict, caddy: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mw.json").write_text(json.dumps(contract), encoding="utf-8")
            (root / "kong.json").write_text(json.dumps(kong), encoding="utf-8")
            (root / "api.caddy").write_text(caddy, encoding="utf-8")
            return parity.certify(root / "mw.json", root / "kong.json", root / "api.caddy")

    def test_aligned_surfaces_pass(self) -> None:
        report = self.run_certify(CONTRACT, kong_fixture(CONTRACT), caddy_fixture(CONTRACT))
        self.assertEqual(report["verdict"], "PASS", report["problems"])
        self.assertEqual(report["routeCount"], 117)
        self.assertEqual(report["sharedEdgeRoutes"], 105)

    def test_kong_missing_route_and_scope_drift_fail(self) -> None:
        kong = kong_fixture(CONTRACT)
        kong["routes"].pop()
        kong["routes"][0]["scope"] = "platform.command"
        report = self.run_certify(CONTRACT, kong, caddy_fixture(CONTRACT))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(any("missing from kong" in p for p in report["problems"]["kong"]))
        self.assertTrue(any(" scope:" in p for p in report["problems"]["kong"]))

    def test_caddy_routing_a_denied_route_fails(self) -> None:
        denied = next(r for r in CONTRACT["routes"] if r["classification"] == "denied")
        report = self.run_certify(CONTRACT, kong_fixture(CONTRACT), caddy_fixture(CONTRACT, (denied,)))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(any("caddy routes a denied route" in p for p in report["problems"]["caddy"]))

    def test_kong_wrong_issuer_fails(self) -> None:
        kong = kong_fixture(CONTRACT)
        kong["routes"][0]["issuer"] = "https://auth.staging.codestra.co/realms/codestra"
        report = self.run_certify(CONTRACT, kong, caddy_fixture(CONTRACT))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(
            [p for p in report["problems"]["kong"] if "kong issuer" in p],
            [f"('{kong['routes'][0]['method']}', '{kong['routes'][0]['path']}') kong issuer "
             "'https://auth.staging.codestra.co/realms/codestra'"],
        )

    def test_kong_exposing_non_shared_edge_routes_fails(self) -> None:
        for classification in ("private_only", "denied"):
            with self.subTest(classification=classification):
                extra = next(r for r in CONTRACT["routes"] if r["classification"] == classification)
                kong = kong_fixture(CONTRACT)
                kong["routes"].append({
                    "operation_id": extra["operation_id"],
                    "method": extra["method"],
                    "path": extra["path"],
                    "issuer": parity.PRODUCTION_ISSUER,
                    "audience": extra["audience"],
                    "scope": extra["scope"],
                    "azp": extra["calling_client"],
                    "authentication": extra["auth"],
                })
                report = self.run_certify(CONTRACT, kong, caddy_fixture(CONTRACT))
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(
                    f"kong exposes a non-shared_edge route: {parity.route_key(extra)}",
                    report["problems"]["kong"],
                )

    def test_kong_audience_and_azp_drift_fail(self) -> None:
        for kong_field, contract_field, drifted in (
            ("audience", "audience", "codestra-odoo"),
            ("azp", "calling_client", "codestra-agent-desktop"),
        ):
            with self.subTest(field=kong_field):
                kong = kong_fixture(CONTRACT)
                row = kong["routes"][0]
                original = row[kong_field]
                row[kong_field] = drifted
                report = self.run_certify(CONTRACT, kong, caddy_fixture(CONTRACT))
                self.assertEqual(report["verdict"], "FAIL")
                self.assertEqual(report["problems"]["kong"], [
                    f"{(row['method'], row['path'])} {contract_field}: "
                    f"middleware={original!r} kong={drifted!r}"
                ])

    def test_caddy_missing_a_shared_edge_route_fails(self) -> None:
        shared = [r for r in CONTRACT["routes"] if r["classification"] == "shared_edge"]
        missing = next(r for r in shared if "{" not in r["path"])
        routed = copy.deepcopy(CONTRACT)
        for r in routed["routes"]:
            if parity.route_key(r) == parity.route_key(missing):
                r["classification"] = "denied"
        report = self.run_certify(CONTRACT, kong_fixture(CONTRACT), caddy_fixture(routed))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["problems"]["caddy"], [
            f"shared_edge route not routed to kong by caddy: {parity.route_key(missing)}"
        ])

    def test_caddy_routing_a_private_only_route_fails(self) -> None:
        private = [r for r in CONTRACT["routes"] if r["classification"] == "private_only"]
        self.assertTrue(private)
        for route in private:
            with self.subTest(route=parity.route_key(route)):
                report = self.run_certify(
                    CONTRACT, kong_fixture(CONTRACT), caddy_fixture(CONTRACT, (route,))
                )
                self.assertEqual(report["verdict"], "FAIL")
                self.assertIn(
                    f"caddy routes a private_only route: {parity.route_key(route)}",
                    report["problems"]["caddy"],
                )

    def test_drifted_middleware_contract_fails_every_pin(self) -> None:
        drifted = copy.deepcopy(CONTRACT)
        drifted["routes"] = drifted["routes"][:-1]
        report = self.run_certify(drifted, kong_fixture(drifted), caddy_fixture(drifted))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(report["problems"]["keycloakEdgeContract"])
        self.assertTrue(report["problems"]["keycloakAccessAuthority"])


    def test_duplicate_kong_route_declaration_fails(self) -> None:
        kong = kong_fixture(CONTRACT)
        kong["routes"].append(copy.deepcopy(kong["routes"][0]))
        report = self.run_certify(CONTRACT, kong, caddy_fixture(CONTRACT))
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(
            any(
                "duplicate kong route declaration" in problem
                for problem in report["problems"]["kong"]
            )
        )

    def test_caddy_matcher_without_kong_handler_fails(self) -> None:
        caddy = caddy_fixture(CONTRACT).replace(
            "reverse_proxy {$CADDY_KONG_UPSTREAM}",
            "reverse_proxy {$CADDY_LEGACY_API_UPSTREAM}",
            1,
        )
        report = self.run_certify(CONTRACT, kong_fixture(CONTRACT), caddy)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertTrue(report["problems"]["caddy"])

    def test_parameterized_caddy_route_requires_multiple_values(self) -> None:
        route = next(
            row
            for row in CONTRACT["routes"]
            if row["classification"] == "shared_edge" and "{" in row["path"]
        )
        caddy = caddy_fixture(CONTRACT)
        method = route["method"].lower()
        block = re.search(
            rf"(@canonical_{method} \{{.*?path_regexp )(.*?)(\n\t\}})",
            caddy,
            flags=re.S,
        )
        self.assertIsNotNone(block)
        assert block is not None
        hardcoded = re.escape(parity.PATH_PARAMETER.sub("abc123", route["path"]))
        caddy = (
            caddy[: block.start(2)]
            + f"^({hardcoded})$"
            + caddy[block.end(2) :]
        )
        report = self.run_certify(CONTRACT, kong_fixture(CONTRACT), caddy)
        self.assertEqual(report["verdict"], "FAIL")
        self.assertIn(
            f"shared_edge route not routed to kong by caddy: {parity.route_key(route)}",
            report["problems"]["caddy"],
        )


if __name__ == "__main__":
    unittest.main()
