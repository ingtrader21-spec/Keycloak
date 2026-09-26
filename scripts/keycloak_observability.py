#!/usr/bin/env python3
from __future__ import annotations
import hashlib
from typing import Any
from keycloak_event_redaction import redact_event
from keycloak_identity_compiler import canonical
EVENT_TYPES={"LOGIN","LOGIN_ERROR","LOGOUT","TOKEN_ERROR","RESET_PASSWORD","RESET_PASSWORD_ERROR","UPDATE_PASSWORD","ADMIN_CHANGE","ACCOUNT_LOCKOUT"}
class ObservabilityError(RuntimeError): pass
def normalize_events(events:list[dict[str,Any]],*,limit:int=100)->list[dict[str,Any]]:
    if not isinstance(limit,int) or limit<1 or limit>500: raise ObservabilityError("invalid_event_limit")
    out=[]
    for raw in events[:limit]:
        if not isinstance(raw,dict): raise ObservabilityError("malformed_event")
        event=redact_event(raw)
        if event.get("event_type") in EVENT_TYPES: out.append(event)
    return out
def metrics(events:list[dict[str,Any]],*,configuration_drift:bool=False,readback_failures:int=0)->dict[str,int]:
    counts={"authentication_failures":0,"token_failures":0,"account_lockouts":0,"password_resets":0,"admin_changes":0,"configuration_drift":int(configuration_drift),"keycloak_readback_failures":max(0,int(readback_failures))}
    for e in normalize_events(events,limit=min(max(len(events),1),500)):
        t=e.get("event_type")
        if t=="LOGIN_ERROR": counts["authentication_failures"]+=1
        elif t=="TOKEN_ERROR": counts["token_failures"]+=1
        elif t=="ACCOUNT_LOCKOUT": counts["account_lockouts"]+=1
        elif t in {"RESET_PASSWORD","UPDATE_PASSWORD"}: counts["password_resets"]+=1
        elif t=="ADMIN_CHANGE": counts["admin_changes"]+=1
    return counts
def status(desired:dict[str,Any],live:dict[str,Any])->dict[str,Any]:
    d=hashlib.sha256(canonical(desired).encode()).hexdigest(); l=hashlib.sha256(canonical(live).encode()).hexdigest()
    return {"realm":str((live.get("realm") or {}).get("realm") or desired.get("realm",{}).get("realm") or ""),"desiredStateDigest":d,"liveConfigurationDigest":l,"configurationDrift":d!=l,"eventsEnabled":bool((live.get("realm") or {}).get("eventsEnabled",False))}
