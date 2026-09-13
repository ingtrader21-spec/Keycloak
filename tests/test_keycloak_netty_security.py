from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


class KeycloakNettySecurityTests(unittest.TestCase):
    def test_image_contains_checksum_pinned_netty_security_fix(self) -> None:
        for artifact, checksum in (
            (
                "netty-handler",
                "d0e4c6ee4779f59f6ab2fb5d388e4f57147c82270164b37945764bb9bda96a44",
            ),
            (
                "netty-codec-http",
                "0535bb5a736472bef5c948d15eb273c4ab9f796656fc7c5d6b982ad92bddbd49",
            ),
        ):
            self.assertIn(f"io.netty.{artifact}-4.1.136.Final.jar", DOCKERFILE)
            self.assertIn(f"io.netty.{artifact}-4.1.137.Final.jar", DOCKERFILE)
            self.assertIn(f"ADD --checksum=sha256:{checksum}", DOCKERFILE)
            self.assertIn(
                f"{artifact}-4.1.137.Final.jar /opt/keycloak/lib/lib/main/"
                f"io.netty.{artifact}-4.1.136.Final.jar",
                DOCKERFILE,
            )
        self.assertIn("| sha256sum -c -", DOCKERFILE)
        self.assertEqual(DOCKERFILE.count("--chown=1000:0 --chmod=0644"), 2)
        self.assertIn(
            "rm -f /opt/keycloak/lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-*.jar",
            DOCKERFILE,
        )
        self.assertIn("-name 'com.microsoft.sqlserver.mssql-jdbc-*.jar'", DOCKERFILE)
