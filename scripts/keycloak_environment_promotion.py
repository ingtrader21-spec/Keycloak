#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, uuid
from typing import Any
from keycloak_identity_compiler import canonical
POLICY={"schema":"codestra.keycloak.promotion-policy.v1","testSynProductionBlocked":True,"explicitTargetMappingRequired":True,"weakenProductionPolicyBlocked":True}
COMPARE=("redirectUris","webOrigins","defaultClientScopes","optionalClientScopes","protocolMappers","serviceAccountsEnabled","publicClient","directAccessGrantsEnabled")
def _sha(v:Any)->str: return hashlib.sha256(canonical(v).encode()).hexdigest()
def promotion_plan(desired:dict[str,Any],request:dict[str,Any],protected:dict[str,Any]|None=None)->dict[str,Any]:
    source=str(request.get("sourceAuthorityGroup") or ""); target=str(request.get("targetEnvironment") or "")
    mapping=request.get("targetMapping")
    blockers=[]; candidates=[]
    if source.lower().replace("_","-") in {"test-syn","testsyn"} and target=="production": blockers.append("test_syn_production_forbidden")
    if not isinstance(mapping,dict) or not mapping: blockers.append("explicit_target_mapping_required")
    staged=[x for x in desired.get("stagedClients",[]) if x.get("authorityGroup")==source]
    if not staged: blockers.append("source_authority_group_not_found")
    protected_by={c.get("clientId"):c for c in (protected or desired).get("clients",[]) if c.get("clientId")}
    for item in staged:
        c=item["client"]; src=c["clientId"]; target_id=(mapping or {}).get(src)
        if not target_id: blockers.append(f"missing_mapping:{src}"); continue
        target_c=protected_by.get(target_id); changes=[]
        if target_c:
            for field in COMPARE:
                if canonical(c.get(field))!=canonical(target_c.get(field)): changes.append(field)
            if changes: blockers.append(f"protected_client_collision:{target_id}")
        candidates.append({"sourceClientId":src,"targetClientId":target_id,"requiredChanges":changes})
    packet={"schema":"codestra.keycloak.promotion-plan.v1","promotionId":str(request.get("promotionId") or uuid.uuid4()),"sourceAuthorityGroup":source,"sourceDesiredStateSha":desired.get("sourceSha256") or _sha(desired),"targetEnvironment":target,"targetIssuer":request.get("targetIssuer"),"candidateResources":candidates,"blockers":sorted(set(blockers))}
    packet["promotionStatus"]="BLOCK" if blockers else "PROMOTE"
    stable={k:v for k,v in packet.items() if k not in {"promotionId","packetSha256"}}
    packet["packetSha256"]=_sha(stable)
    return packet
