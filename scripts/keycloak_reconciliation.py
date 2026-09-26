#!/usr/bin/env python3
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Any
from keycloak_identity_compiler import canonical

CLIENT_FIELDS=("clientId","name","description","enabled","protocol","publicClient","bearerOnly","consentRequired","standardFlowEnabled","implicitFlowEnabled","directAccessGrantsEnabled","serviceAccountsEnabled","authorizationServicesEnabled","frontchannelLogout","fullScopeAllowed","rootUrl","baseUrl","redirectUris","webOrigins","defaultClientScopes","optionalClientScopes","attributes","protocolMappers")
REALM_FIELDS=("enabled","sslRequired","verifyEmail","resetPasswordAllowed","bruteForceProtected","accessTokenLifespan")
SCOPE_FIELDS=("name","description","protocol","attributes","protocolMappers")
ROLE_FIELDS=("name","description","composite","attributes")
ACTION_FIELDS=("alias","name","enabled","defaultAction","priority","config")
RESOURCE_ORDER=("realm","client_scope","realm_role","client","required_action")

@dataclass(frozen=True)
class Action:
    kind:str; resource_type:str; resource_id:str; reason:str; managed:bool=True

def digest(value:Any)->str: return hashlib.sha256(canonical(value).encode()).hexdigest()
def projection(value:dict[str,Any],fields)->dict[str,Any]: return {k:value.get(k) for k in fields}
def _index(rows:list[dict[str,Any]],key:str)->dict[str,dict[str,Any]]: return {str(r.get(key)):r for r in rows if r.get(key)}

def normalize_state(state:dict[str,Any])->dict[str,Any]:
    realm=projection(state.get("realm") or {},REALM_FIELDS)
    return {"realm":realm,"clients":[projection(x,CLIENT_FIELDS) for x in state.get("clients",[])],"clientScopes":[projection(x,SCOPE_FIELDS) for x in state.get("clientScopes",[])],"realmRoles":[projection(x,ROLE_FIELDS) for x in state.get("realmRoles",[])],"requiredActions":[projection(x,ACTION_FIELDS) for x in state.get("requiredActions",[])]}

def _plan_collection(actions:list[Action],rtype:str,desired_rows:list[dict[str,Any]],live_rows:list[dict[str,Any]],key:str,fields,managed_ids:set[str]|None=None):
    d=_index(desired_rows,key); l=_index(live_rows,key)
    for rid in sorted(d):
        if rid not in l: actions.append(Action("CREATE",rtype,rid,"missing_live"))
        elif canonical(projection(d[rid],fields))!=canonical(projection(l[rid],fields)): actions.append(Action("UPDATE",rtype,rid,"managed_fields_drift"))
        else: actions.append(Action("KEEP",rtype,rid,"in_sync"))
    for rid in sorted(set(l)-set(d)):
        if managed_ids is not None and rid in managed_ids: actions.append(Action("DELETE",rtype,rid,"managed_resource_removed"))
        else: actions.append(Action("KEEP",rtype,rid,"unmanaged_live_resource",False))

def plan(desired:dict[str,Any],live:dict[str,Any],*,managed_inventory:dict[str,list[str]]|None=None,environment:str="unknown")->dict[str,Any]:
    actions:list[Action]=[]; managed_inventory=managed_inventory or {}
    if canonical(projection(desired.get("realm") or {},REALM_FIELDS))!=canonical(projection(live.get("realm") or {},REALM_FIELDS)):
        actions.append(Action("UPDATE","realm",str((desired.get("realm") or {}).get("realm") or "codestra"),"managed_fields_drift"))
    else: actions.append(Action("KEEP","realm",str((desired.get("realm") or {}).get("realm") or "codestra"),"in_sync"))
    _plan_collection(actions,"client_scope",desired.get("clientScopes",[]),live.get("clientScopes",[]),"name",SCOPE_FIELDS,set(managed_inventory.get("clientScopes",[])))
    _plan_collection(actions,"realm_role",desired.get("realmRoles",[]),live.get("realmRoles",[]),"name",ROLE_FIELDS,set(managed_inventory.get("realmRoles",[])))
    _plan_collection(actions,"client",desired.get("clients",[]),live.get("clients",[]),"clientId",CLIENT_FIELDS,set(managed_inventory.get("clients",[])))
    if desired.get("requiredActions") is not None:
        _plan_collection(actions,"required_action",desired.get("requiredActions",[]),live.get("requiredActions",[]),"alias",ACTION_FIELDS,set())
    actions.sort(key=lambda a:(RESOURCE_ORDER.index(a.resource_type),a.resource_id,a.kind))
    payload={"schema":"codestra.keycloak.reconciliation-plan.v2","environment":environment,"desiredSha256":digest(normalize_state(desired)),"liveSha256":digest(normalize_state(live)),"actions":[a.__dict__ for a in actions],"mutationEnabled":False}
    payload["planSha256"]=digest(payload); return payload

def _rows(state,key): return _index(state.get(key,[]),"clientId" if key=="clients" else ("alias" if key=="requiredActions" else "name"))

def apply_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],api,*,enabled:bool=False,allow_delete:bool=False,environment:str|None=None)->dict[str,Any]:
    if not enabled: raise RuntimeError("apply_disabled")
    if environment is not None and plan_doc.get("environment") not in {environment,"unknown"}: raise RuntimeError("environment_mismatch")
    maps={k:_rows(desired,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    live_maps={k:_rows(live,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    journal=[]
    try:
        for action in plan_doc["actions"]:
            kind=action["kind"]; rt=action["resource_type"]; rid=action["resource_id"]
            if kind=="KEEP": journal.append({"kind":kind,"resourceType":rt,"resourceId":rid}); continue
            if kind=="DELETE" and (not allow_delete or not action.get("managed",False)): raise RuntimeError(f"delete_not_authorized:{rt}:{rid}")
            if rt=="realm":
                if kind!="UPDATE": raise RuntimeError("unsupported_realm_action")
                api.update_realm(projection(desired["realm"],REALM_FIELDS))
            elif rt=="client":
                d=maps["clients"].get(rid); cur=live_maps["clients"].get(rid)
                if kind=="CREATE": api.create_client(d)
                elif kind=="UPDATE":
                    internal=str((cur or {}).get("id") or "")
                    if not internal: raise RuntimeError(f"missing_internal_id:{rid}")
                    merged=dict(cur); merged.update(projection(d,CLIENT_FIELDS)); api.update_client(internal,merged)
                elif kind=="DELETE":
                    internal=str((cur or {}).get("id") or "")
                    if not internal: raise RuntimeError(f"missing_internal_id:{rid}")
                    api.delete_client(internal)
            elif rt=="client_scope":
                d=maps["clientScopes"].get(rid); cur=live_maps["clientScopes"].get(rid)
                if kind=="CREATE": api.create_client_scope(d)
                elif kind=="UPDATE": api.update_client_scope(str((cur or {}).get("id") or ""),d)
                elif kind=="DELETE": api.delete_client_scope(str((cur or {}).get("id") or ""))
            elif rt=="realm_role":
                d=maps["realmRoles"].get(rid)
                if kind=="CREATE": api.create_realm_role(d)
                elif kind=="UPDATE": api.update_realm_role(rid,d)
                elif kind=="DELETE": api.delete_realm_role(rid)
            elif rt=="required_action":
                if kind!="UPDATE": raise RuntimeError(f"unsupported_required_action:{kind}")
                api.update_required_action(rid,maps["requiredActions"][rid])
            else: raise RuntimeError(f"unsupported_resource:{rt}")
            journal.append({"kind":kind,"resourceType":rt,"resourceId":rid})
    except Exception as exc:
        return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"PARTIAL_FAILURE","journal":journal,"error":str(exc)}
    return {"schema":"codestra.keycloak.reconciliation-execution.v2","journal":journal,"applied":True,"status":"APPLIED"}

def verify_readback(desired:dict[str,Any],live_after:dict[str,Any])->dict[str,Any]:
    expected=normalize_state(desired); actual=normalize_state(live_after)
    return {"equal":canonical(expected)==canonical(actual),"desiredDigest":digest(expected),"liveDigest":digest(actual)}

def rollback_plan(pre_state:dict[str,Any],current_state:dict[str,Any],*,environment:str="unknown")->dict[str,Any]:
    return plan(pre_state,current_state,managed_inventory={"clients":[x.get("clientId") for x in current_state.get("clients",[]) if x.get("clientId")],"clientScopes":[x.get("name") for x in current_state.get("clientScopes",[]) if x.get("name")],"realmRoles":[x.get("name") for x in current_state.get("realmRoles",[]) if x.get("name")]},environment=environment)
