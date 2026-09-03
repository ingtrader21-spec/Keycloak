#!/usr/bin/env python3
"""Update plan-gate expectations for the two newly governed clients."""
from pathlib import Path

path = Path("scripts/test-plan-gate.sh")
source = path.read_text(encoding="utf-8")
replacements = {
    '[[ "$(jq -er \'.driftCount\' "$plan_dir/plan.json")" -eq 29 ]]':
        '[[ "$(jq -er \'.driftCount\' "$plan_dir/plan.json")" -eq 31 ]]',
    '[[ "$(jq -er \'.createCount\' "$plan_dir/plan.json")" -eq 28 ]]':
        '[[ "$(jq -er \'.createCount\' "$plan_dir/plan.json")" -eq 30 ]]',
    '[[ "$(jq -er \'.absentCreatableClientCount\' "$rollback_dir/rollback-metadata.json")" -eq 28 ]]':
        '[[ "$(jq -er \'.absentCreatableClientCount\' "$rollback_dir/rollback-metadata.json")" -eq 30 ]]',
    'for client_id in klyrow-portal moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra; do':
        'for client_id in klyrow-portal moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager; do',
    'for client_id in moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra; do':
        'for client_id in moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager; do',
}
for old, new in replacements.items():
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"PLAN_GATE_PATCH_DRIFT={old[:48]!r}:count={count}")
    source = source.replace(old, new, 1)
path.write_text(source, encoding="utf-8")
print("PLATFORM_IDENTITY_PLAN_GATE_RECONCILIATION=PASS")
