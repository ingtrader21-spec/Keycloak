#!/usr/bin/env python3
from __future__ import annotations
import json, urllib.error, urllib.parse, urllib.request
from typing import Any

class KeycloakAdminError(RuntimeError):
    def __init__(self,code:str,message:str,status:int|None=None):
        super().__init__(message); self.code=code; self.status=status

class KeycloakAdminAPI:
    def __init__(self,base_url:str,realm:str,bearer:str,timeout:float=10.0):
        self.base_url=base_url.rstrip("/"); self.realm=realm; self._bearer=bearer; self.timeout=timeout
        if not self.base_url.startswith(("https://","http://127.0.0.1","http://localhost")):
            raise KeycloakAdminError("unsafe_admin_url","admin API must use HTTPS or loopback")

    def _url(self,suffix:str)->str:
        return f"{self.base_url}/admin/realms/{urllib.parse.quote(self.realm)}{suffix}"

    def request(self,method:str,suffix:str,body:dict[str,Any]|None=None,expected:set[int]|None=None)->Any:
        data=None if body is None else json.dumps(body,separators=(",",":")).encode()
        headers={"Authorization":f"Bearer {self._bearer}","Accept":"application/json"}
        if data is not None: headers["Content-Type"]="application/json"
        req=urllib.request.Request(self._url(suffix),data=data,headers=headers,method=method)
        try:
            with urllib.request.urlopen(req,timeout=self.timeout) as resp:
                status=resp.status; raw=resp.read()
        except urllib.error.HTTPError as exc:
            raise KeycloakAdminError("admin_http_error",f"Keycloak Admin API returned HTTP {exc.code}",exc.code) from exc
        except OSError as exc:
            raise KeycloakAdminError("admin_transport_error","Keycloak Admin API transport failed") from exc
        if expected and status not in expected: raise KeycloakAdminError("unexpected_status",f"unexpected HTTP {status}",status)
        if not raw: return None
        try: return json.loads(raw)
        except json.JSONDecodeError as exc: raise KeycloakAdminError("invalid_json","Keycloak Admin API returned invalid JSON",status) from exc

    def realm_state(self)->dict[str,Any]: return self.request("GET","") or {}
    def clients(self)->list[dict[str,Any]]: return self.request("GET","/clients?max=1000") or []
    def client_scopes(self)->list[dict[str,Any]]: return self.request("GET","/client-scopes") or []
    def realm_roles(self)->list[dict[str,Any]]: return self.request("GET","/roles") or []
    def create_client(self,payload:dict[str,Any])->None: self.request("POST","/clients",payload,{201})
    def update_client(self,internal_id:str,payload:dict[str,Any])->None:
        self.request("PUT",f"/clients/{urllib.parse.quote(internal_id)}",payload,{204})
    def delete_client(self,internal_id:str)->None:
        self.request("DELETE",f"/clients/{urllib.parse.quote(internal_id)}",expected={204})
