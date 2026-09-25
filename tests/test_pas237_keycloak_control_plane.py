from __future__ import annotations
import copy,http.client,json,sys,threading
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from keycloak_identity_compiler import IdentityModelError,compile_identity,validate_client,write_output
from keycloak_reconciliation import apply_plan,plan
from keycloak_control_api import Handler,Service

def test_compiler_is_deterministic_and_complete():
    first=compile_identity(); second=compile_identity()
    assert first==second
    assert first["schema"]=="codestra.keycloak.identity-authority.v1"
    assert len(first["clients"])>=30
    assert first["sourceSha256"]==second["sourceSha256"]

def test_generated_identity_matches_check():
    write_output(False); write_output(True)

def test_wildcard_redirect_rejected():
    c={"clientId":"x","redirectUris":["https://x.example/*"],"webOrigins":[],"directAccessGrantsEnabled":False,
       "serviceAccountsEnabled":False,"publicClient":True,"standardFlowEnabled":True,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="unsafe_redirect"): validate_client(c)

def test_direct_grant_rejected():
    c={"clientId":"x","redirectUris":[],"webOrigins":[],"directAccessGrantsEnabled":True,
       "serviceAccountsEnabled":True,"publicClient":False,"standardFlowEnabled":False,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="direct_grants_forbidden"): validate_client(c)

def test_service_client_redirect_rejected():
    c={"clientId":"x","redirectUris":["https://x.example/cb"],"webOrigins":[],"directAccessGrantsEnabled":False,
       "serviceAccountsEnabled":True,"publicClient":False,"standardFlowEnabled":False,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="service_client_redirects_forbidden"): validate_client(c)

def test_plan_create_update_keep_and_preserve_unmanaged():
    desired={"clients":[{"clientId":"a","enabled":True},{"clientId":"b","enabled":True},{"clientId":"c","enabled":True}]}
    live={"clients":[{"id":"1","clientId":"a","enabled":True},{"id":"2","clientId":"b","enabled":False},{"id":"9","clientId":"unmanaged","enabled":True}]}
    kinds={(a["resource_id"],a["kind"]) for a in plan(desired,live)["actions"]}
    assert ("a","KEEP") in kinds
    assert ("b","UPDATE") in kinds
    assert ("c","CREATE") in kinds
    assert ("unmanaged","KEEP") in kinds

class FakeAPI:
    def __init__(self): self.calls=[]
    def create_client(self,p): self.calls.append(("create",p["clientId"]))
    def update_client(self,i,p): self.calls.append(("update",i,p["clientId"]))

def test_apply_disabled_by_default():
    p={"actions":[]}
    with pytest.raises(RuntimeError,match="apply_disabled"): apply_plan(p,{"clients":[]},{"clients":[]},FakeAPI())

def test_apply_executes_only_managed_create_update_keep():
    desired={"clients":[{"clientId":"a","enabled":True},{"clientId":"b","enabled":True}]}
    live={"clients":[{"id":"2","clientId":"b","enabled":False}]}
    p=plan(desired,live); api=FakeAPI()
    out=apply_plan(p,desired,live,api,enabled=True)
    assert out["applied"] is True
    assert ("create","a") in api.calls
    assert any(c[0]=="update" and c[1]=="2" for c in api.calls)

def test_control_api_health_and_apply_denial():
    class T(Handler): service=Service()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        conn.request("GET","/platform/v1/keycloak/health",headers={"X-Correlation-ID":"abc"})
        r=conn.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["applyEnabled"] is False and r.getheader("X-Correlation-ID")=="abc"
        conn.request("POST","/platform/v1/keycloak/reconcile/apply")
        r=conn.getresponse(); body=json.loads(r.read()); assert r.status==403 and body["error"]["code"]=="apply_disabled"
    finally:
        server.shutdown(); server.server_close()

def test_control_api_refuses_public_bind_source():
    src=(ROOT/"scripts"/"keycloak_control_api.py").read_text()
    assert 'a.host not in {"127.0.0.1","::1","localhost"}' in src


def test_admin_adapter_rejects_unsafe_http_url():
    from keycloak_admin_api import KeycloakAdminAPI, KeycloakAdminError
    with pytest.raises(KeycloakAdminError, match="admin API must use HTTPS or loopback"):
        KeycloakAdminAPI("http://keycloak.internal","codestra","token")


def test_dry_run_execution_has_readback(monkeypatch):
    class LocalService(Service):
        def live(self):
            return {"clients": [], "realm": {}, "clientScopes": [], "realmRoles": []}
    service=LocalService()
    record=service.dry_run()
    assert record["mode"]=="DRY_RUN"
    assert record["mutationPerformed"] is False
    assert service.execution(record["executionId"])["executionId"]==record["executionId"]


def test_missing_execution_is_404_error():
    from keycloak_admin_api import KeycloakAdminError
    service=Service()
    with pytest.raises(KeycloakAdminError) as exc:
        service.execution("missing")
    assert exc.value.code=="execution_not_found"
    assert exc.value.status==404
