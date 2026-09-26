from __future__ import annotations
import hashlib,json,sys,time
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"scripts"))
from keycloak_execution_store import EvidenceStore,EvidenceStoreError
from keycloak_recovery_controller import RecoveryController
from keycloak_event_redaction import redact_event
from keycloak_observability import normalize_events,metrics,ObservabilityError
from keycloak_environment_promotion import promotion_plan

def test_store_atomic_duplicate_and_corruption(tmp_path):
    s=EvidenceStore(tmp_path,retention=10); s.put("executions","a",{"status":"ok"})
    assert s.get("executions","a")["payload"]["status"]=="ok"
    with pytest.raises(EvidenceStoreError,match="duplicate"): s.put("executions","a",{})
    p=tmp_path/"executions"/"a.json"; p.write_text('{"bad":true}')
    with pytest.raises(EvidenceStoreError,match="corrupt"): s.get("executions","a")

def test_recovery_valid_stale_invalid_and_missing(tmp_path,monkeypatch):
    b=tmp_path/"b"; r=tmp_path/"r"; b.mkdir(); r.mkdir()
    ctl=RecoveryController(b,r); assert ctl.status()["state"]=="UNKNOWN"
    f=b/"backup.sql.gpg"; f.write_bytes(b"safe")
    Path(str(f)+".sha256").write_text(hashlib.sha256(b"safe").hexdigest()+"  backup.sql.gpg\\n")
    (r/"restore.json").write_text(json.dumps({"isolated":True,"success":True}))
    assert ctl.status()["state"]=="HEALTHY"
    Path(str(f)+".sha256").write_text("0"*64+"  backup.sql.gpg\\n")
    assert ctl.status()["state"]=="INVALID"

def test_event_redaction_and_metrics():
    e={"event_id":"1","event_type":"LOGIN_ERROR","timestamp":1,"realm":"codestra","client_id":"x","access_token":"NO","password":"NO","authorization":"NO"}
    clean=redact_event(e); assert "access_token" not in clean and "password" not in clean
    assert metrics([clean])["authentication_failures"]==1
    with pytest.raises(ObservabilityError): normalize_events([clean],limit=501)

def test_promotion_blocks_testsyn_and_is_deterministic():
    desired={"sourceSha256":"abc","clients":[],"stagedClients":[{"authorityGroup":"TEST_SYN","client":{"clientId":"test-syn-a","redirectUris":[],"webOrigins":[]}}]}
    req={"promotionId":"p1","sourceAuthorityGroup":"TEST_SYN","targetEnvironment":"production","targetIssuer":"https://auth.codestra.co/realms/codestra","targetMapping":{"test-syn-a":"a"}}
    a=promotion_plan(desired,req); b=promotion_plan(desired,req)
    assert a["promotionStatus"]=="BLOCK" and "test_syn_production_forbidden" in a["blockers"] and a["packetSha256"]==b["packetSha256"]

def test_promotion_requires_mapping():
    desired={"clients":[],"stagedClients":[{"authorityGroup":"stage","client":{"clientId":"a"}}]}
    assert promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"stage","targetEnvironment":"staging"})["promotionStatus"]=="BLOCK"


def test_reconciliation_delete_only_for_explicit_managed_inventory():
    from keycloak_reconciliation import plan
    desired={"clients":[]}
    live={"clients":[{"id":"1","clientId":"managed"},{"id":"2","clientId":"foreign"}]}
    actions={a["resource_id"]:a for a in plan(desired,live,managed_inventory={"clients":["managed"]})["actions"]}
    assert actions["managed"]["kind"]=="DELETE" and actions["managed"]["managed"] is True
    assert actions["foreign"]["kind"]=="KEEP" and actions["foreign"]["managed"] is False

def test_readback_mismatch_is_detected():
    from keycloak_reconciliation import verify_readback
    desired={"realm":{"enabled":True},"clients":[]}
    live={"realm":{"enabled":False},"clients":[]}
    assert verify_readback(desired,live)["equal"] is False

def test_partial_failure_journals_completed_actions():
    from keycloak_reconciliation import apply_plan
    class API:
        def create_client(self,p): raise RuntimeError("boom")
    desired={"clients":[{"clientId":"x","enabled":True}]}; live={"clients":[]}
    p={"environment":"test","actions":[{"kind":"CREATE","resource_type":"client","resource_id":"x","managed":True}]}
    out=apply_plan(p,desired,live,API(),enabled=True,environment="test")
    assert out["status"]=="PARTIAL_FAILURE" and out["applied"] is False

def test_api_recovery_promotion_and_oversize(tmp_path):
    import http.client,threading
    from http.server import ThreadingHTTPServer
    from keycloak_control_api import Handler,Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def desired(self): return {"sourceSha256":"x","clients":[],"stagedClients":[]}
        def recovery(self): return RecoveryController(tmp_path/"backups",tmp_path/"restores")
    class T(Handler): service=Local()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
    try:
        c=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        c.request("GET","/platform/v1/keycloak/recovery/status"); r=c.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["recovery"]["state"]=="UNKNOWN"
        payload=json.dumps({"promotionId":"p1","sourceAuthorityGroup":"missing","targetEnvironment":"staging","targetMapping":{"x":"y"}})
        c.request("POST","/platform/v1/keycloak/promotion/plan",body=payload,headers={"Content-Type":"application/json"}); r=c.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["promotion"]["promotionStatus"]=="BLOCK"
        c.request("POST","/platform/v1/keycloak/promotion/plan",body=b"x",headers={"Content-Length":"70000"}); r=c.getresponse(); body=json.loads(r.read()); assert r.status==413 and body["error"]["code"]=="request_too_large"
    finally:
        server.shutdown(); server.server_close()


def test_store_rejects_nested_secret_material(tmp_path):
    s=EvidenceStore(tmp_path)
    with pytest.raises(EvidenceStoreError,match="secret_material_forbidden"):
        s.put("executions","secret",{"nested":{"access_token":"do-not-store"}})

def test_promotion_collision_blocks_policy_mismatch():
    desired={"sourceSha256":"x","clients":[{"clientId":"target","redirectUris":["https://prod/cb"],"webOrigins":["https://prod"],"serviceAccountsEnabled":False}],"stagedClients":[{"authorityGroup":"stage","client":{"clientId":"source","redirectUris":["https://stage/cb"],"webOrigins":["https://stage"],"serviceAccountsEnabled":False}}]}
    req={"promotionId":"p2","sourceAuthorityGroup":"stage","targetEnvironment":"production","targetIssuer":"https://auth.codestra.co/realms/codestra","targetMapping":{"source":"target"}}
    out=promotion_plan(desired,req)
    assert out["promotionStatus"]=="BLOCK" and "protected_client_collision:target" in out["blockers"]


def test_api_rejects_bad_observability_limit(tmp_path):
    import http.client,threading
    from http.server import ThreadingHTTPServer
    from keycloak_control_api import Handler,Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def events(self,limit=100): return []
    class T(Handler): service=Local()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        c=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        for value in ("nope","0","501"):
            c.request("GET",f"/platform/v1/keycloak/observability/events?limit={value}")
            r=c.getresponse(); body=json.loads(r.read())
            assert r.status==400 and body["error"]["code"]=="invalid_query"
    finally:
        server.shutdown(); server.server_close()

def test_dry_run_persists_evidence(tmp_path):
    from keycloak_control_api import Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def drift(self): return {"planSha256":"p","desiredSha256":"d","liveSha256":"l","actions":[]}
    s=Local(); rec=s.dry_run("idem")
    evidence=s.evidence(rec["executionId"])
    assert evidence["payload"]["idempotencyKey"]=="idem" and evidence["sha256"]
