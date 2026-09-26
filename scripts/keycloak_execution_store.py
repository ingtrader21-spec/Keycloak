#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, tempfile, threading
from pathlib import Path
from typing import Any
from keycloak_identity_compiler import canonical

class EvidenceStoreError(RuntimeError): pass
SECRET_KEYS={"password","access_token","refresh_token","id_token","authorization","cookie","client_secret","secret","reset_token","otp","credential","credentials"}
def _assert_secret_free(value:Any,path:str="root")->None:
    if isinstance(value,dict):
        for k,v in value.items():
            n=str(k).lower().replace("-","_")
            if n in SECRET_KEYS or any(x in n for x in ("password","token","secret","credential","authorization","cookie","otp")):
                if v not in (None,"",False,[],{}): raise EvidenceStoreError(f"secret_material_forbidden:{path}.{k}")
            _assert_secret_free(v,f"{path}.{k}")
    elif isinstance(value,list):
        for i,v in enumerate(value): _assert_secret_free(v,f"{path}[{i}]")


class EvidenceStore:
    def __init__(self, root:Path|str, *, retention:int=200):
        self.root=Path(root); self.retention=max(10,min(int(retention),5000)); self._lock=threading.RLock()
        self.root.mkdir(parents=True,exist_ok=True)

    @staticmethod
    def _digest(payload:Any)->str:
        return hashlib.sha256(canonical(payload).encode()).hexdigest()

    @staticmethod
    def _safe_id(value:str)->str:
        if not value or len(value)>128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._" for c in value):
            raise EvidenceStoreError("invalid_record_id")
        return value

    def _path(self,kind:str,record_id:str)->Path:
        self._safe_id(kind); self._safe_id(record_id)
        d=self.root/kind; d.mkdir(parents=True,exist_ok=True)
        return d/(record_id+".json")

    def put(self,kind:str,record_id:str,payload:dict[str,Any],*,replace:bool=False)->dict[str,Any]:
        path=self._path(kind,record_id)
        _assert_secret_free(payload)
        body={"schema":"codestra.keycloak.evidence-envelope.v1","kind":kind,"recordId":record_id,"payload":payload}
        body["sha256"]=self._digest(body)
        raw=(json.dumps(body,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
        with self._lock:
            if path.exists() and not replace: raise EvidenceStoreError("duplicate_record")
            fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
            try:
                with os.fdopen(fd,"wb") as fh: fh.write(raw); fh.flush(); os.fsync(fh.fileno())
                os.replace(tmp,path)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
            self._prune(path.parent)
        return body

    def get(self,kind:str,record_id:str)->dict[str,Any]:
        path=self._path(kind,record_id)
        if not path.exists(): raise EvidenceStoreError("record_not_found")
        try: body=json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc: raise EvidenceStoreError("corrupt_record") from exc
        digest=body.pop("sha256",None); actual=self._digest(body); body["sha256"]=digest
        if not digest or digest!=actual: raise EvidenceStoreError("corrupt_record")
        return body

    def list(self,kind:str)->list[dict[str,Any]]:
        d=self.root/self._safe_id(kind)
        if not d.exists(): return []
        out=[]
        for path in sorted(d.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)[:self.retention]:
            out.append(self.get(kind,path.stem))
        return out

    def _prune(self,d:Path)->None:
        rows=sorted(d.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)
        for path in rows[self.retention:]: path.unlink(missing_ok=True)
