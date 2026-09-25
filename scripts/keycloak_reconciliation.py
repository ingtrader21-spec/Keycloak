#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from typing import Any
from keycloak_identity_compiler import canonical

MANAGED_CLIENT_FIELDS=(
 "clientId","name","description","enabled","protocol","publicClient","bearerOnly","consentRequired",
 "standardFlowEnabled","implicitFlowEnabled","directAccessGrantsEnabled","serviceAccountsEnabled",
 "authorizationServicesEnabled","frontchannelLogout","fullScopeAllowed","rootUrl","baseUrl","redirectUris",
 "webOrigins","defaultClientScopes","optionalClientScopes","attributes","protocolMappers"
)

@dataclass(frozen=True)
class Action:
    kind:str; resource_type:str; resource_id:str; reason:str

def projection(value:dict[str,Any],fields=MANAGED_CLIENT_FIELDS)->dict[str,Any]:
    return {k:value.get(k) for k in fields if k in value or k in fields}

def plan(desired:dict[str,Any],live:dict[str,Any])->dict[str,Any]:
    actions:list[Action]=[]
    desired_clients={c["clientId"]:c for c in desired.get("clients",[])}
    live_clients={c.get("clientId"):c for c in live.get("clients",[]) if c.get("clientId")}
    for cid in sorted(desired_clients):
        if cid not in live_clients: actions.append(Action("CREATE","client",cid,"missing_live"))
        elif canonical(projection(desired_clients[cid]))!=canonical(projection(live_clients[cid])):
            actions.append(Action("UPDATE","client",cid,"managed_fields_drift"))
        else: actions.append(Action("KEEP","client",cid,"in_sync"))
    for cid in sorted(set(live_clients)-set(desired_clients)):
        actions.append(Action("KEEP","client",cid,"unmanaged_live_resource"))
    payload={"schema":"codestra.keycloak.reconciliation-plan.v1",
             "desiredSha256":hashlib.sha256(canonical(desired).encode()).hexdigest(),
             "actions":[a.__dict__ for a in actions],
             "mutationEnabled":False}
    payload["planSha256"]=hashlib.sha256(canonical(payload).encode()).hexdigest()
    return payload

def apply_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],api,*,enabled:bool=False)->dict[str,Any]:
    if not enabled: raise RuntimeError("apply_disabled")
    desired_clients={c["clientId"]:c for c in desired.get("clients",[])}
    live_clients={c.get("clientId"):c for c in live.get("clients",[]) if c.get("clientId")}
    journal=[]
    for action in plan_doc["actions"]:
        kind=action["kind"]; cid=action["resource_id"]
        if kind=="CREATE":
            api.create_client(desired_clients[cid]); journal.append({"kind":kind,"clientId":cid})
        elif kind=="UPDATE":
            current=live_clients[cid]; internal=str(current.get("id") or "")
            if not internal: raise RuntimeError(f"missing_internal_id:{cid}")
            merged=dict(current); merged.update(projection(desired_clients[cid]))
            api.update_client(internal,merged); journal.append({"kind":kind,"clientId":cid})
        elif kind=="KEEP": journal.append({"kind":kind,"clientId":cid})
        else: raise RuntimeError(f"unsupported_action:{kind}")
    return {"schema":"codestra.keycloak.reconciliation-execution.v1","journal":journal,"applied":True}
