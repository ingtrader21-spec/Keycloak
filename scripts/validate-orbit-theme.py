#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "themes" / "codestra" / "login"
IDENTITY_THEME = ROOT / "themes" / "codestra-identity" / "login"


def main() -> None:
    manifest = json.loads((ROOT / "orbit" / "adoption-manifest.json").read_text())
    assert manifest["repository"] == "appolon1908-hue/Keycloak"
    assert manifest["domain"] == "auth.codestra.co"
    assert manifest["requirements"]["supportedTheme"] is True

    properties = (THEME / "theme.properties").read_text()
    assert "parent=keycloak.v2" in properties
    assert "styles=css/orbit.css" in properties

    identity_properties = (IDENTITY_THEME / "theme.properties").read_text()
    assert "parent=codestra" in identity_properties
    assert "locales=en,es,fr" in identity_properties

    realm = json.loads((ROOT / "config" / "realms" / "codestra.json").read_text())
    assert realm["loginTheme"] == "codestra-identity"

    css = (THEME / "resources" / "css" / "orbit.css").read_text()
    assert "prefers-reduced-motion" in css
    assert "javascript:" not in css.lower()
    for token in (
        "--codestra-bg: #0b0b0b",
        "--codestra-panel: #171717",
        "--codestra-text: #ffffff",
        "--codestra-muted: #a1a1aa",
        "--codestra-accent: #ffffff",
        "border-radius: 16px",
        "border-radius: 10px",
        "focus-visible",
    ):
        assert token in css, f"missing visual contract token: {token}"
    for retired in ("#07111f", "#0f1d2e", "#55d6be", "radial-gradient"):
        assert retired not in css, f"retired palette token remains: {retired}"

    for locale in ("en", "es", "fr"):
        messages = (THEME / "messages" / f"messages_{locale}.properties").read_text()
        assert "loginTitle=" in messages
        assert "doForgotPassword=" in messages

    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY themes /opt/keycloak/themes" in dockerfile
    assert dockerfile.index("COPY themes /opt/keycloak/themes") < dockerfile.index("kc.sh build")
    print("ORBIT_KEYCLOAK_THEME=PASS")


if __name__ == "__main__":
    main()
