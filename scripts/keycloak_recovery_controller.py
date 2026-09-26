#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, time
from pathlib import Path
from typing import Any

DEFAULT_POLICY={"schema":"codestra.keycloak.recovery-policy.v1","maximumBackupAgeSeconds":86400,"maximumRestoreRehearsalAgeSeconds":604800,"checksumRequired":True,"encryptionRequired":True,"isolatedRestoreRequired":True,"minimumRequiredEvidence":["backup","checksum","encrypted","restoreRehearsal"]}

class RecoveryController:
    def __init__(self,backup_dir:Path|str,evidence_dir:Path|str,policy:dict[str,Any]|None=None):
        self.backup_dir=Path(backup_dir); self.evidence_dir=Path(evidence_dir); self.policy=dict(DEFAULT_POLICY if policy is None else policy)

    def backups(self)->list[dict[str,Any]]:
        if not self.backup_dir.exists(): return []
        rows=[]
        for p in sorted(self.backup_dir.glob("*"),key=lambda x:x.stat().st_mtime,reverse=True):
            if not p.is_file() or p.name.endswith(".sha256"): continue
            checksum=Path(str(p)+".sha256"); encrypted=p.suffix in {".gpg",".age",".enc"}
            integrity=None
            if checksum.exists():
                try:
                    expected=checksum.read_text(encoding="utf-8").split()[0].lower()
                    actual=hashlib.sha256(p.read_bytes()).hexdigest(); integrity=expected==actual
                except Exception: integrity=False
            rows.append({"name":p.name,"createdAt":int(p.stat().st_mtime),"ageSeconds":max(0,int(time.time()-p.stat().st_mtime)),"encrypted":encrypted,"checksumPresent":checksum.exists(),"integrityValid":integrity})
        return rows

    def restores(self)->list[dict[str,Any]]:
        if not self.evidence_dir.exists(): return []
        out=[]
        for p in sorted(self.evidence_dir.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True):
            try: value=json.loads(p.read_text(encoding="utf-8"))
            except Exception: value={"valid":False,"error":"corrupt_evidence"}
            out.append({"name":p.name,"createdAt":int(p.stat().st_mtime),"ageSeconds":max(0,int(time.time()-p.stat().st_mtime)),"evidence":value})
        return out

    def status(self)->dict[str,Any]:
        backups=self.backups(); restores=self.restores()
        if not backups: return {"state":"UNKNOWN","reason":"missing_backup"}
        b=backups[0]
        if self.policy["encryptionRequired"] and not b["encrypted"]: return {"state":"INVALID","reason":"backup_not_encrypted","latestBackup":b}
        if self.policy["checksumRequired"] and (not b["checksumPresent"] or b["integrityValid"] is not True): return {"state":"INVALID","reason":"backup_integrity_failed","latestBackup":b}
        if b["ageSeconds"]>self.policy["maximumBackupAgeSeconds"]: return {"state":"STALE","reason":"backup_stale","latestBackup":b}
        if self.policy["isolatedRestoreRequired"]:
            if not restores: return {"state":"UNKNOWN","reason":"missing_restore_rehearsal","latestBackup":b}
            r=restores[0]
            if not r["evidence"].get("isolated") or not r["evidence"].get("success"): return {"state":"INVALID","reason":"restore_rehearsal_invalid","latestBackup":b,"latestRestore":r}
            if r["ageSeconds"]>self.policy["maximumRestoreRehearsalAgeSeconds"]: return {"state":"STALE","reason":"restore_rehearsal_stale","latestBackup":b,"latestRestore":r}
        return {"state":"HEALTHY","reason":"policy_satisfied","latestBackup":b,"latestRestore":restores[0] if restores else None}

    def validate(self)->dict[str,Any]:
        return {"policy":self.policy,"status":self.status(),"backupsChecked":len(self.backups()),"restoresChecked":len(self.restores())}
