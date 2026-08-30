#!/usr/bin/env python3
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def build_server(state_file: Path) -> ThreadingHTTPServer:
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "MockKeycloak/3"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_json(self, status: int, value) -> None:
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/realms/master/protocol/openid-connect/token":
                self.send_json(200, {"access_token": "test-token", "expires_in": 60})
                return
            with lock:
                state = load(state_file)
                payload = self.read_json()
                if parsed.path == "/admin/realms/codestra/clients":
                    client_id = payload.get("clientId")
                    if not isinstance(client_id, str) or client_id in state["clients"] or "secret" in payload:
                        self.send_json(409, {"error": "client_exists_or_invalid"})
                        return
                    state["clients"][client_id] = {
                        "id": f"uuid-{client_id}",
                        "representation": payload,
                        "secret": f"mock-secret-{client_id}-0000000000",
                    }
                elif parsed.path == "/admin/realms/codestra/roles":
                    role_name = payload.get("name")
                    if not isinstance(role_name, str) or role_name in state["roles"]:
                        self.send_json(409, {"error": "role_exists_or_invalid"})
                        return
                    state["roles"][role_name] = {
                        "id": f"role-{role_name}",
                        "representation": payload,
                    }
                else:
                    self.send_json(404, {"error": "not_found"})
                    return
                write(state_file, state)
                self.send_response(201)
                self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            with lock:
                state = load(state_file)
                if parsed.path == "/admin/realms/codestra/clients":
                    client_id = (parse_qs(parsed.query).get("clientId") or [""])[0]
                    item = state["clients"].get(client_id)
                    self.send_json(200, [] if item is None else [{"id": item["id"], "clientId": client_id}])
                    return
                client_prefix = "/admin/realms/codestra/clients/"
                if parsed.path.startswith(client_prefix):
                    remainder = parsed.path.removeprefix(client_prefix)
                    is_secret = remainder.endswith("/client-secret")
                    client_uuid = unquote(remainder.removesuffix("/client-secret") if is_secret else remainder)
                    for client_id, item in state["clients"].items():
                        if item["id"] != client_uuid:
                            continue
                        if is_secret:
                            self.send_json(200, {"type": "secret", "value": item["secret"]})
                            return
                        representation = json.loads(json.dumps(item["representation"]))
                        representation["id"] = item["id"]
                        representation["secret"] = item["secret"]
                        for index, mapper in enumerate(representation.get("protocolMappers", [])):
                            mapper.setdefault("id", f"mapper-{client_id}-{index}")
                        self.send_json(200, representation)
                        return
                    self.send_json(404, {"error": "not_found"})
                    return
                role_prefix = "/admin/realms/codestra/roles/"
                if parsed.path.startswith(role_prefix):
                    role_name = unquote(parsed.path.removeprefix(role_prefix))
                    item = state["roles"].get(role_name)
                    if item is None:
                        self.send_json(404, {"error": "not_found"})
                        return
                    representation = json.loads(json.dumps(item["representation"]))
                    representation.update({"id": item["id"], "containerId": "codestra"})
                    self.send_json(200, representation)
                    return
            self.send_json(404, {"error": "not_found"})

        def do_PUT(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            payload = self.read_json()
            with lock:
                state = load(state_file)
                client_prefix = "/admin/realms/codestra/clients/"
                if parsed.path.startswith(client_prefix):
                    client_uuid = unquote(parsed.path.removeprefix(client_prefix))
                    for client_id, item in state["clients"].items():
                        if item["id"] == client_uuid:
                            payload.pop("id", None)
                            payload.pop("secret", None)
                            item["representation"] = payload
                            state["clients"][client_id] = item
                            write(state_file, state)
                            self.send_response(204)
                            self.end_headers()
                            return
                role_prefix = "/admin/realms/codestra/roles/"
                if parsed.path.startswith(role_prefix):
                    role_name = unquote(parsed.path.removeprefix(role_prefix))
                    item = state["roles"].get(role_name)
                    if item is not None:
                        payload.pop("id", None)
                        payload.pop("containerId", None)
                        item["representation"] = payload
                        state["roles"][role_name] = item
                        write(state_file, state)
                        self.send_response(204)
                        self.end_headers()
                        return
            self.send_json(404, {"error": "not_found"})

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)
