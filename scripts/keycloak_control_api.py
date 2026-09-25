#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, threading, uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from keycloak_admin_api import KeycloakAdminAPI,KeycloakAdminError
from keycloak_identity_compiler import compile_identity,write_output
from keycloak_reconciliation import plan

HOST="127.0.0.1"
PORT=8785

class Service:
    def __init__(self):
        self._lock=threading.Lock()
        self._executions={}

    def desired(self):
        return compile_identity()

    def live(self):
        base=os.environ.get("KEYCLOAK_ADMIN_BASE_URL","")
        token=os.environ.get("KEYCLOAK_ADMIN_BEARER","")
        if not base or not token:
            raise KeycloakAdminError("admin_not_configured","admin readback is not configured")
        api=KeycloakAdminAPI(base,"codestra",token)
        return {
            "realm":api.realm_state(),
            "clients":api.clients(),
            "clientScopes":api.client_scopes(),
            "realmRoles":api.realm_roles(),
        }

    def drift(self):
        return plan(self.desired(),self.live())

    def compile(self):
        return {"compiled":True,"identity":write_output(False)}

    def validate(self):
        desired=compile_identity()
        return {"valid":True,"clients":len(desired["clients"]),"scopes":len(desired["clientScopes"])}

    def dry_run(self):
        execution_id=str(uuid.uuid4())
        result=self.drift()
        record={
            "executionId":execution_id,
            "mode":"DRY_RUN",
            "status":"COMPLETED",
            "mutationPerformed":False,
            "plan":result,
        }
        with self._lock:
            self._executions[execution_id]=record
        return record

    def execution(self,execution_id):
        with self._lock:
            value=self._executions.get(execution_id)
        if value is None:
            raise KeycloakAdminError("execution_not_found","reconciliation execution not found",404)
        return value

    def health(self):
        return {"service":"keycloak-control-api","status":"ok","applyEnabled":False}

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
        p=self.path.split("?",1)[0]
        if p=="/platform/v1/keycloak/desired-state":
            return self.runfn(lambda:{"desired":self.service.desired()})
        if p=="/platform/v1/keycloak/drift":
            return self.runfn(lambda:{"plan":self.service.drift()})
        if p.startswith("/platform/v1/keycloak/reconcile/executions/"):
            execution_id=p.rsplit("/",1)[-1]
            return self.runfn(lambda:{"execution":self.service.execution(execution_id)})
        if p=="/platform/v1/keycloak/health" or p=="/health":
            return self.runfn(self.service.health)
        self.send_json(404,{"ok":False,"error":{"code":"not_found","message":"route not found"}},self.rid())

    def do_POST(self):
        p=self.path.split("?",1)[0]
        if p=="/platform/v1/keycloak/compile":
            return self.runfn(self.service.compile)
        if p=="/platform/v1/keycloak/validate":
            return self.runfn(self.service.validate)
        if p=="/platform/v1/keycloak/reconcile/dry-run":
            return self.runfn(lambda:{"execution":self.service.dry_run()})
        if p=="/platform/v1/keycloak/reconcile/apply":
            return self.send_json(403,{"ok":False,"error":{"code":"apply_disabled","message":"live apply is disabled by default"}},self.rid())
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
