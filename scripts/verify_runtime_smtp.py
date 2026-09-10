#!/usr/bin/env python3
"""Read-only verification of the active Keycloak container's private SMTP route."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]


class RuntimeSmtpError(ValueError):
    pass


def require(value, code):
    if not value:
        raise RuntimeSmtpError(code)


def command(arguments):
    try:
        result = subprocess.run(
            DOCKER + arguments, check=True, capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        # Compose errors may contain configuration. Never return raw output.
        raise RuntimeSmtpError("RUNTIME_INSPECTION_FAILED") from None
    require(len(result.stdout) <= 128 * 1024, "RUNTIME_RESPONSE_TOO_LARGE")
    return result.stdout


def verify(compose_file, env_file, hostname, address):
    for value in (compose_file, env_file):
        path = Path(value)
        require(bool(value) and path.is_absolute() and path.is_file() and not path.is_symlink(),
                "RUNTIME_PATH_INVALID")
    require(hostname == "mail.klyrow.com" and address == "10.40.0.4", "SMTP_CONTRACT_INVALID")
    compose = ["compose", "--env-file", env_file, "-f", compose_file]
    container_id = command(compose + ["ps", "-q", "keycloak"]).strip()
    require(bool(re.fullmatch(r"[0-9a-f]{64}", container_id)), "KEYCLOAK_CONTAINER_NOT_UNIQUE")
    try:
        containers = json.loads(command(["inspect", container_id]))
        require(isinstance(containers, list) and len(containers) == 1, "RUNTIME_INSPECT_INVALID")
        container = containers[0]
        require(container["Id"] == container_id and container["State"]["Running"] is True,
                "KEYCLOAK_NOT_RUNNING")
        labels = container["Config"]["Labels"]
        require(labels.get("com.docker.compose.service") == "keycloak"
                and compose_file in labels.get("com.docker.compose.project.config_files", "").split(","),
                "KEYCLOAK_RUNTIME_IDENTITY_MISMATCH")
        bindings = container["HostConfig"].get("ExtraHosts") or []
        matching = [entry.replace("=", ":", 1).partition(":")[2] for entry in bindings
                    if entry.replace("=", ":", 1).partition(":")[0] == hostname]
        require(matching == [address], "SMTP_PRIVATE_BINDING_MISSING")
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError):
        raise RuntimeSmtpError("RUNTIME_INSPECT_INVALID") from None
    hosts = command(["exec", container_id, "/bin/bash", "-c",
                     'while IFS= read -r line; do printf "%s\\n" "$line"; done < /etc/hosts'])
    addresses = []
    for line in hosts.splitlines():
        columns = line.partition("#")[0].split()
        if len(columns) > 1 and hostname in columns[1:]:
            addresses.append(columns[0])
    require(bool(addresses) and set(addresses) == {address}, "SMTP_ACTIVE_HOSTS_MISMATCH")
    require(command(compose + ["ps", "-q", "keycloak"]).strip() == container_id,
            "KEYCLOAK_CONTAINER_CHANGED")


def main():
    try:
        smtp = json.loads((ROOT / "config/email/keycloak-security-smtp.json").read_text())["smtp"]
        verify(os.environ.get("RUNTIME_COMPOSE_FILE", ""), os.environ.get("RUNTIME_ENV_FILE", ""),
               smtp["defaultHost"], smtp["privateAddress"])
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        print("RUNTIME_SMTP=CONFIGURATION_INVALID", file=sys.stderr)
        return 1
    except RuntimeSmtpError as error:
        print("RUNTIME_SMTP=" + str(error), file=sys.stderr)
        return 1
    print("RUNTIME_SMTP_PRIVATE_BINDING=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
