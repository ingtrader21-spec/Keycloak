#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, threading, uuid
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from keycloak_admin_api import KeycloakAdminAPI,KeycloakAdminError
from keycloak_identity_compiler import compile_identity,write_output
from keycloak_reconciliation import plan,apply_plan,verify_readback,rollback_plan,digest
from keycloak_execution_store import EvidenceStore,EvidenceStoreError
from keycloak_recovery_controller import RecoveryController
from keycloak_observability import normalize_events,metrics as event_metrics,status as observability_status,ObservabilityError
from keycloak_environment_promotion import POLICY as PROMOTION_POLICY,promotion_plan

HOST="127.0.0.1"
PORT=8785

class Service:
    def __init__(self,store=None):
        root=Path(os.environ.get("KEYCLOAK_CONTROL_EVIDENCE_DIR","/tmp/codestra-keycloak-control"))
        self.store=store or EvidenceStore(root)
        self._lock=threading.Lock()

    def desired(self): return compile_identity()
    def _api(self):
        base=os.environ.get("KEYCLOAK_ADMIN_BASE_URL",""); token=os.environ.get("KEYCLOAK_ADMIN_BEARER","")
        if not base or not token: raise KeycloakAdminError("admin_not_configured","admin readback is not configured")
        return KeycloakAdminAPI(base,"codestra",token)
    def live(self):
        api=self._api()
        clients=api.clients()
        mappings=[]
        desired_ids={x.get("clientId") for x in self.desired().get("scopeMappings",[])}
        for client in clients:
            if client.get("clientId") not in desired_ids or not client.get("id"): continue
            roles=api.client_realm_role_mappings(str(client["id"]))
            mappings.append({"clientId":client["clientId"],"fullScopeAllowed":bool(client.get("fullScopeAllowed",False)),"realmRoles":sorted(r.get("name") for r in roles if r.get("name")),"crossFamilyRolesAllowed":False})
        return {"realm":api.realm_state(),"clients":clients,"clientScopes":api.client_scopes(),"realmRoles":api.realm_roles(),"scopeMappings":mappings,"requiredActions":api.required_actions()}
    def drift(self): return plan(self.desired(),self.live(),environment=os.environ.get("KEYCLOAK_ENVIRONMENT","unknown"))
    def compile(self): return {"compiled":True,"identity":write_output(False)}
    def validate(self):
        d=compile_identity(); return {"valid":True,"clients":len(d["clients"]),"scopes":len(d["clientScopes"])}

    def dry_run(self,idempotency_key=None):
        result=self.drift(); key=idempotency_key or result["planSha256"]
        record={"executionId":str(uuid.uuid4()),"idempotencyKey":key,"mode":"DRY_RUN","status":"COMPLETED","mutationPerformed":False,"desiredStateDigest":result["desiredSha256"],"preStateDigest":result["liveSha256"],"resultDigest":digest(result),"plan":result}
        self.store.put("executions",record["executionId"],record); return record

    def apply(self,idempotency_key):
        if os.environ.get("KEYCLOAK_MUTATION_ENABLED","").lower()!="true": raise KeycloakAdminError("apply_disabled","live apply is disabled by default",403)
        if not idempotency_key: raise KeycloakAdminError("idempotency_key_required","X-Idempotency-Key is required",400)
        for row in self.store.list("executions"):
            old=row["payload"]
            if old.get("idempotencyKey")==idempotency_key and old.get("mode")=="APPLY": return old
        desired=self.desired(); pre=self.live(); p=plan(desired,pre,environment=os.environ.get("KEYCLOAK_ENVIRONMENT","unknown"))
        execution_id=str(uuid.uuid4()); outcome=apply_plan(p,desired,pre,self._api(),enabled=True,allow_delete=os.environ.get("KEYCLOAK_DELETE_ENABLED","").lower()=="true",environment=os.environ.get("KEYCLOAK_ENVIRONMENT","unknown"))
        post=self.live(); readback=verify_readback(desired,post)
        status="COMPLETED" if outcome.get("applied") and readback["equal"] else ("READBACK_MISMATCH" if outcome.get("applied") else "PARTIAL_FAILURE")
        record={"executionId":execution_id,"idempotencyKey":idempotency_key,"mode":"APPLY","status":status,"mutationPerformed":bool(outcome.get("journal")),"desiredStateDigest":p["desiredSha256"],"preStateDigest":p["liveSha256"],"resultDigest":digest(post),"plan":p,"actionJournal":outcome.get("journal",[]),"readback":readback,"preState":pre,"rollbackStatus":"NOT_RUN"}
        self.store.put("executions",execution_id,record); return record

    def rollback(self,execution_id):
        original=self.execution(execution_id)
        if original.get("mode")!="APPLY" or not original.get("preState"): raise KeycloakAdminError("rollback_not_available","rollback evidence is not available",409)
        if os.environ.get("KEYCLOAK_MUTATION_ENABLED","").lower()!="true": raise KeycloakAdminError("apply_disabled","live apply is disabled by default",403)
        current=self.live(); pre=original["preState"]; p=rollback_plan(pre,current,environment=os.environ.get("KEYCLOAK_ENVIRONMENT","unknown"))
        outcome=apply_plan(p,pre,current,self._api(),enabled=True,allow_delete=True,environment=os.environ.get("KEYCLOAK_ENVIRONMENT","unknown"))
        after=self.live(); check=verify_readback(pre,after)
        record={"executionId":str(uuid.uuid4()),"mode":"ROLLBACK","sourceExecutionId":execution_id,"status":"COMPLETED" if outcome.get("applied") and check["equal"] else "ROLLBACK_FAILED","actionJournal":outcome.get("journal",[]),"readback":check}
        self.store.put("rollbacks",record["executionId"],record); return record

    def execution(self,execution_id):
        try: return self.store.get("executions",execution_id)["payload"]
        except EvidenceStoreError as exc:
            raise KeycloakAdminError("execution_not_found","reconciliation execution not found",404) from exc
    def evidence(self,execution_id): return self.store.get("executions",execution_id)

    def recovery(self):
        return RecoveryController(os.environ.get("KEYCLOAK_BACKUP_DIR","/var/backups/keycloak"),os.environ.get("KEYCLOAK_RESTORE_EVIDENCE_DIR","/var/lib/keycloak/recovery-evidence"))
    def recovery_validate(self):
        result=self.recovery().validate(); rid=str(uuid.uuid4()); self.store.put("recovery",rid,result); return {"validationId":rid,**result}

    def observability_status(self): return observability_status(self.desired(),self.live())
    def events(self,limit=100):
        api=self._api(); raw=api.events(max_results=limit)
        return normalize_events([{"event_id":e.get("id"),"timestamp":e.get("time"),"event_type":e.get("type"),"outcome":"ERROR" if str(e.get("type","")).endswith("_ERROR") else "SUCCESS","realm":"codestra","client_id":e.get("clientId"),"subject_ref":e.get("userId")} for e in raw],limit=limit)
    def metrics(self,limit=100):
        events=self.events(limit); st=self.observability_status(); return event_metrics(events,configuration_drift=st["configurationDrift"])

    def promotion(self,body):
        result=promotion_plan(self.desired(),body); self.store.put("promotions",result["promotionId"],result); return result
    def promotion_get(self,pid):
        try:return self.store.get("promotions",pid)["payload"]
        except EvidenceStoreError as exc: raise KeycloakAdminError("promotion_not_found","promotion plan not found",404) from exc
    def health(self): return {"service":"keycloak-control-api","status":"ok","applyEnabled":os.environ.get("KEYCLOAK_MUTATION_ENABLED","").lower()=="true"}

class Handler(BaseHTTPRequestHandler):
    service=Service()

    def log_message(self,*_):
        return

    def rid(self):
        return (self.headers.get("X-Correlation-ID") or str(uuid.uuid4()))[:128]

    def send_json(self,status:int,body:dict,rid:str):
        raw=json.dumps(body,sort_keys=True,separators=(",",":")).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Correlation-ID",rid)
        self.send_header("X-Content-Type-Options","nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def body(self,max_bytes=65536):
        length=int(self.headers.get("Content-Length") or "0")
        if length<0 or length>max_bytes: raise KeycloakAdminError("request_too_large","request body exceeds limit",413)
        if not length:return {}
        try:value=json.loads(self.rfile.read(length))
        except Exception as exc: raise KeycloakAdminError("invalid_json","request body must be valid JSON",400) from exc
        if not isinstance(value,dict): raise KeycloakAdminError("invalid_request","request body must be an object",400)
        return value

    def bounded_int(self,query,name,default,minimum,maximum):
        raw=query.get(name,[str(default)])[0]
        try:value=int(raw)
        except (TypeError,ValueError) as exc: raise KeycloakAdminError("invalid_query",f"{name} must be an integer",400) from exc
        if value<minimum or value>maximum: raise KeycloakAdminError("invalid_query",f"{name} must be between {minimum} and {maximum}",400)
        return value

    def runfn(self,fn):
        rid=self.rid()
        try:
            result=fn()
        except KeycloakAdminError as exc:
            status=exc.status if exc.status and 400 <= exc.status < 600 else 503
            return self.send_json(status,{"ok":False,"error":{"code":exc.code,"message":str(exc)}},rid)
        except Exception:
            return self.send_json(500,{"ok":False,"error":{"code":"internal_error","message":"control operation failed"}},rid)
        self.send_json(200,{"ok":True,**result},rid)

    def do_GET(self):
        u=urlsplit(self.path); p=u.path; q=parse_qs(u.query)
        if p=="/platform/v1/keycloak/desired-state": return self.runfn(lambda:{"desired":self.service.desired()})
        if p=="/platform/v1/keycloak/drift": return self.runfn(lambda:{"plan":self.service.drift()})
        if p=="/platform/v1/keycloak/recovery/status": return self.runfn(lambda:{"recovery":self.service.recovery().status()})
        if p=="/platform/v1/keycloak/recovery/backups": return self.runfn(lambda:{"backups":self.service.recovery().backups()})
        if p=="/platform/v1/keycloak/recovery/restores": return self.runfn(lambda:{"restores":self.service.recovery().restores()})
        if p=="/platform/v1/keycloak/observability/status": return self.runfn(lambda:{"observability":self.service.observability_status()})
        if p=="/platform/v1/keycloak/observability/events":
            return self.runfn(lambda:{"events":self.service.events(self.bounded_int(q,"limit",100,1,500))})
        if p=="/platform/v1/keycloak/observability/metrics": return self.runfn(lambda:{"metrics":self.service.metrics()})
        if p=="/platform/v1/keycloak/promotion/policy": return self.runfn(lambda:{"policy":PROMOTION_POLICY})
        if p.startswith("/platform/v1/keycloak/promotion/plans/"): return self.runfn(lambda:{"promotion":self.service.promotion_get(p.rsplit("/",1)[-1])})
        if p.startswith("/platform/v1/keycloak/reconcile/executions/"):
            evidence=p.endswith("/evidence"); eid=p.split("/reconcile/executions/",1)[1].split("/",1)[0]
            return self.runfn(lambda:{"evidence":self.service.evidence(eid)} if evidence else {"execution":self.service.execution(eid)})
        if p in {"/platform/v1/keycloak/health","/health"}: return self.runfn(self.service.health)
        self.send_json(404,{"ok":False,"error":{"code":"not_found","message":"route not found"}},self.rid())

    def do_POST(self):
        p=urlsplit(self.path).path
        if p=="/platform/v1/keycloak/compile": return self.runfn(self.service.compile)
        if p=="/platform/v1/keycloak/validate": return self.runfn(self.service.validate)
        if p=="/platform/v1/keycloak/reconcile/dry-run": return self.runfn(lambda:{"execution":self.service.dry_run(self.headers.get("X-Idempotency-Key"))})
        if p=="/platform/v1/keycloak/reconcile/apply": return self.runfn(lambda:{"execution":self.service.apply(self.headers.get("X-Idempotency-Key"))})
        if p=="/platform/v1/keycloak/reconcile/rollback": return self.runfn(lambda:{"rollback":self.service.rollback(str(self.body().get("executionId") or ""))})
        if p=="/platform/v1/keycloak/recovery/validate": return self.runfn(lambda:{"validation":self.service.recovery_validate()})
        if p=="/platform/v1/keycloak/promotion/plan": return self.runfn(lambda:{"promotion":self.service.promotion(self.body())})
        self.send_json(404,{"ok":False,"error":{"code":"not_found","message":"route not found"}},self.rid())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--host",default=HOST)
    ap.add_argument("--port",type=int,default=PORT)
    a=ap.parse_args()
    if a.host not in {"127.0.0.1","::1","localhost"}:
        raise SystemExit("refusing non-loopback bind")
    ThreadingHTTPServer((a.host,a.port),Handler).serve_forever()

if __name__=="__main__":
    main()
