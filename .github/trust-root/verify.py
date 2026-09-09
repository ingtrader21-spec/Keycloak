#!/usr/bin/env python3
"""Read candidate Git objects as data; never import or execute candidate files.

A PASS is a source observation only. A separately administered GitHub App must
verify the trusted workflow/run identity and publish the required status.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = "appolon1908-hue/Keycloak"
ROOT_PREFIX = ".github/trust-root/"
WORKFLOW = ".github/workflows/trust-bootstrap.yml"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILES = 10000
MAX_BLOB = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024

class Rejected(Exception):
    pass

def require(value, message):
    if not value:
        raise Rejected(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def safe_path(path):
    require(isinstance(path, str) and bool(path), "invalid repository path")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in path), "control byte in repository path")
    require("\\" not in path and not path.startswith("/"), "unsafe repository path")
    parts = path.split("/")
    require(all(p not in {"", ".", "..", ".git"} for p in parts), "repository path escape")
    require(str(PurePosixPath(path)) == path, "noncanonical repository path")
    return path

def trusted_path(path):
    return path.startswith(ROOT_PREFIX) or path == WORKFLOW

def manifest(entries, read_blob):
    """Conservative full tracked-source snapshot, including all executable files.

    This is deliberately NOT a claim that dynamic execution has been resolved.
    The separate executable-closure review remains mandatory before approval.
    """
    require(isinstance(entries, list) and len(entries) <= MAX_FILES, "invalid source tree size")
    records = []
    seen = set()
    total = 0
    for entry in entries:
        require(isinstance(entry, dict), "invalid source tree entry")
        path = safe_path(entry.get("path"))
        require(path not in seen, "duplicate source path")
        seen.add(path)
        require(entry.get("type") == "blob" and entry.get("mode") in {"100644", "100755"},
                "symlinks, gitlinks and special files are forbidden")
        oid = entry.get("sha")
        require(isinstance(oid, str) and HEX40.fullmatch(oid), "invalid blob identity")
        content = read_blob(oid)
        require(isinstance(content, bytes) and len(content) <= MAX_BLOB, "invalid source blob size")
        total += len(content)
        require(total <= MAX_TOTAL, "source snapshot exceeds size limit")
        actual_oid = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        require(actual_oid == oid, "source blob identity mismatch")
        records.append({"path": path, "mode": entry["mode"], "sha256": hashlib.sha256(content).hexdigest()})
    records.sort(key=lambda item: item["path"])
    return {"schema_version": 1, "repository": REPOSITORY, "files": records}

def source_only(snapshot):
    return {**snapshot, "files": [r for r in snapshot["files"] if not trusted_path(r["path"])]}

def validate_snapshot(snapshot):
    require(isinstance(snapshot, dict) and set(snapshot) == {"schema_version", "repository", "files"},
            "invalid approved snapshot format")
    require(snapshot["schema_version"] == 1 and snapshot["repository"] == REPOSITORY,
            "approved snapshot identity mismatch")
    files = snapshot["files"]
    require(isinstance(files, list) and 0 < len(files) <= MAX_FILES, "invalid approved file list")
    paths = []
    for record in files:
        require(isinstance(record, dict) and set(record) == {"path", "mode", "sha256"}, "invalid file record")
        path = safe_path(record["path"])
        require(not trusted_path(path), "approved snapshot must exclude separately protected trust files")
        require(record["mode"] in {"100644", "100755"}, "invalid file mode")
        require(isinstance(record["sha256"], str) and HEX64.fullmatch(record["sha256"]), "invalid file digest")
        paths.append(path)
    require(paths == sorted(set(paths)), "approved paths must be unique and sorted")

def verify(policy, base, candidate, approved):
    require(policy.get("schema_version") == 1 and policy.get("repository") == REPOSITORY,
            "invalid trusted policy identity")
    require(policy.get("protected_branch") == "main", "trusted policy must bind main")
    base_root = [r for r in base["files"] if trusted_path(r["path"])]
    candidate_root = [r for r in candidate["files"] if trusted_path(r["path"])]
    require(base_root and candidate_root == base_root, "candidate changes trusted bootstrap files")
    app = policy.get("required_check_app_id")
    require(type(app) is int and app > 0, "dedicated required-check App is not configured")
    require(policy.get("required_check_context") == "keycloak-independent-source-authority",
            "required-check identity mismatch")
    approved_digest = policy.get("approved_manifest_sha256")
    require(isinstance(approved_digest, str) and HEX64.fullmatch(approved_digest),
            "no independently approved candidate snapshot")
    require(approved is not None, "approved manifest is missing from trusted base")
    validate_snapshot(approved)
    require(digest(approved) == approved_digest, "trusted approved manifest digest mismatch")
    require(source_only(candidate) == approved, "candidate source differs from independently approved snapshot")
    return {"source_observation": "PASS", "manifest_sha256": approved_digest,
            "required_check_app_id": app, "merge_authorized": False}

class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Rejected("GitHub API redirect rejected")

def api(path):
    require(path.startswith("repos/" + REPOSITORY + "/"), "API repository escape")
    token = os.environ.get("GH_TOKEN", "")
    require(token and not any(c in token for c in "\r\n"), "GitHub read credential missing or malformed")
    req = Request("https://api.github.com/" + path,
                  headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"},
                  method="GET")
    try:
        with build_opener(NoRedirects()).open(req, timeout=30) as response:
            data = response.read(2 * MAX_BLOB + 1)
        require(len(data) <= 2 * MAX_BLOB, "GitHub response exceeds size limit")
        return json.loads(data)
    except (HTTPError, URLError, OSError, ValueError):
        raise Rejected("GitHub read request failed") from None

def remote_snapshot(sha):
    require(HEX40.fullmatch(sha), "invalid candidate SHA")
    commit = api(f"repos/{REPOSITORY}/git/commits/{sha}")
    require(commit.get("sha") == sha, "candidate commit mismatch")
    tree_sha = commit.get("tree", {}).get("sha", "")
    require(HEX40.fullmatch(tree_sha), "invalid candidate tree SHA")
    tree = api(f"repos/{REPOSITORY}/git/trees/{tree_sha}?recursive=1")
    require(tree.get("truncated") is False and isinstance(tree.get("tree"), list), "incomplete candidate tree")
    def read(oid):
        blob = api(f"repos/{REPOSITORY}/git/blobs/{oid}")
        require(blob.get("sha") == oid and blob.get("encoding") == "base64", "invalid GitHub blob")
        try:
            return base64.b64decode("".join(blob["content"].split()), validate=True)
        except (ValueError, KeyError, TypeError):
            raise Rejected("invalid blob encoding") from None
    return manifest([e for e in tree["tree"] if e.get("type") != "tree"], read)

def local_snapshot(sha):
    require(HEX40.fullmatch(sha), "invalid local commit SHA")
    entries = []
    for record in subprocess.check_output(["git", "ls-tree", "-r", "-z", sha]).split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            entries.append({"path": path.decode("utf-8"), "mode": mode, "type": kind, "sha": oid})
    return manifest(entries, lambda oid: subprocess.check_output(["git", "cat-file", "blob", oid]))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot")
    args = parser.parse_args()
    if args.snapshot:
        print(canonical(source_only(local_snapshot(args.snapshot))).decode())
        return 0
    result = {"schema_version": 1, "source_observation": "BLOCKED", "merge_authorized": False}
    try:
        require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "unexpected repository")
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        require(os.environ.get("GITHUB_EVENT_NAME") == "pull_request_target", "trusted base event required")
        pr = event["pull_request"]
        base_sha = pr["base"]["sha"]
        head_sha = pr["head"]["sha"]
        require(HEX40.fullmatch(base_sha) and HEX40.fullmatch(head_sha), "invalid event source SHA")
        require(pr["base"]["ref"] == "main" and pr["base"]["repo"]["full_name"] == REPOSITORY,
                "unexpected base identity")
        require(pr["head"]["repo"]["full_name"] == REPOSITORY, "fork candidates are not authorized")
        checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        require(checkout == base_sha, "trusted checkout must equal event protected base")
        live_main = api(f"repos/{REPOSITORY}/branches/main")
        require(live_main.get("protected") is True and live_main.get("commit", {}).get("sha") == base_sha,
                "protected main changed or is not protected")
        live_pr = api(f"repos/{REPOSITORY}/pulls/{int(event['number'])}")
        require(live_pr.get("state") == "open" and live_pr.get("head", {}).get("sha") == head_sha,
                "candidate head changed or PR is not open")
        policy = json.loads(Path(ROOT_PREFIX + "policy.json").read_text())
        approved_path = Path(ROOT_PREFIX + "approved-source.json")
        approved = json.loads(approved_path.read_text()) if approved_path.is_file() else None
        result.update({"base_sha": base_sha, "head_sha": head_sha, "repository": REPOSITORY})
        # An unconfigured bootstrap blocks before reading the candidate tree.
        require(type(policy.get("required_check_app_id")) is int and policy["required_check_app_id"] > 0,
                "dedicated required-check App is not configured")
        require(approved is not None, "no independently approved candidate snapshot")
        result.update(verify(policy, local_snapshot(base_sha), remote_snapshot(head_sha), approved))
        require(api(f"repos/{REPOSITORY}/branches/main")["commit"]["sha"] == base_sha,
                "protected main changed during verification")
        require(api(f"repos/{REPOSITORY}/pulls/{int(event['number'])}")["head"]["sha"] == head_sha,
                "candidate changed during verification")
    except (Rejected, KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError) as error:
        result["source_observation"] = "BLOCKED"
        result["reason"] = str(error) if isinstance(error, Rejected) else "invalid trusted verification inputs"
    Path(os.environ["RUNNER_TEMP"], "keycloak-trust-observation.json").write_bytes(canonical(result) + b"\n")
    print("TRUSTED_SOURCE_OBSERVATION=" + result["source_observation"])
    print("MERGE_AUTHORIZED=NO")
    return 0 if result["source_observation"] == "PASS" else 1

if __name__ == "__main__":
    sys.exit(main())
