#!/usr/bin/env python3
from __future__ import annotations
from typing import Any
FORBIDDEN={"password","access_token","accesstoken","refresh_token","refreshtoken","id_token","idtoken","authorization","cookie","cookies","client_secret","clientsecret","reset_token","resettoken","otp","smtp","credential","credentials","request","raw"}
ALLOWED={"event_id","timestamp","event_type","outcome","realm","client_id","correlation_id","subject_ref"}
def redact_event(event:dict[str,Any])->dict[str,Any]:
    out={}
    for key,value in event.items():
        norm=key.lower().replace("-","_")
        if norm in FORBIDDEN or any(x in norm for x in ("password","token","secret","credential","authorization","cookie","otp")): continue
        if norm in ALLOWED and isinstance(value,(str,int,float,bool,type(None))): out[norm]=value
    return out
