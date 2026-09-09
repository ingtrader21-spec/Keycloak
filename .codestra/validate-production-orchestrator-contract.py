#!/usr/bin/env python3
"""Fail-closed validation for the repository-owned production contract."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / ".codestra/production-orchestrator-contract.v1.json"
INTENT_PATH = ROOT / ".github/workflows/manual-release-intent.yml"
RELEASE_VALIDATOR_PATH = ROOT / ".codestra/validate-release-intent.py"
SCHEMA = "codestra.production-orchestrator-contract.v1"
PHASES = ["plan", "staging", "canary", "production"]
SAFETY_KEYS = {
    "external_effects_default",
    "live_email_delivery",
    "live_sms_delivery",
    "live_pstn_dialing",
    "odoo_write",
    "n8n_external_delivery",
    "live_trading",
    "payment_execution",
}
ALLOWED_ACTIONS = {
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
}
RUNTIME_TOOLS = {
    "ansible-playbook",
    "docker",
    "helm",
    "kubectl",
    "podman",
    "scp",
    "ssh",
    "terraform",
    "tofu",
}
SHELL_INTERPRETERS = {"bash", "dash", "eval", "ksh", "sh", "zsh"}
SCRIPT_INTERPRETERS = {"node", "perl", "php", "python", "python3", "ruby"}
SHELL_WRAPPERS = {
    "!",
    "builtin",
    "command",
    "env",
    "exec",
    "nohup",
    "sudo",
    "time",
    "timeout",
}
KUBECTL_MUTATIONS = {
    "annotate",
    "apply",
    "autoscale",
    "cordon",
    "cp",
    "create",
    "delete",
    "drain",
    "exec",
    "expose",
    "label",
    "patch",
    "replace",
    "rollout",
    "run",
    "scale",
    "set",
    "taint",
    "uncordon",
}
HELM_MUTATIONS = {"install", "rollback", "uninstall", "upgrade"}
TERRAFORM_MUTATIONS = {"apply", "destroy", "import", "taint", "untaint"}
CONTAINER_MUTATIONS = {"down", "kill", "rm", "start", "stop", "restart", "up"}
HTTP_MUTATION_FLAGS = {
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "--data-urlencode",
    "--form",
    "--form-string",
    "--json",
    "--upload-file",
    "-d",
}
HTTP_MUTATION_METHODS = {"delete", "patch", "post", "put"}
NETWORK_MUTATION_METHODS = {
    "delete",
    "patch",
    "post",
    "put",
    "send",
    "send_message",
    "sendall",
    "sendmail",
}
NETWORK_CLIENT_HINTS = {
    "aiohttp",
    "api",
    "api_client",
    "client",
    "connection",
    "http",
    "http_client",
    "httpx",
    "requests",
    "session",
    "smtp",
    "smtplib",
    "sock",
    "socket",
    "urllib3",
}
DATABASE_MUTATION_METHODS = {
    "add",
    "bulk_insert_mappings",
    "bulk_save_objects",
    "commit",
    "create",
    "delete",
    "executemany",
    "flush",
    "insert",
    "save",
    "update",
    "upsert",
}
DATABASE_CLIENT_HINTS = {
    "conn",
    "connection",
    "cursor",
    "database",
    "db",
    "engine",
    "session",
}
SCRIPT_SUFFIXES = {".bash", ".cjs", ".js", ".mjs", ".php", ".pl", ".py", ".rb", ".sh"}
SQL_MUTATION = re.compile(
    r"\b(?:alter|create|delete|drop|grant|insert|merge|revoke|truncate|update)\b",
    re.IGNORECASE,
)
MUTATING_ACTION_MARKERS = {
    "ansible",
    "cloudformation",
    "deploy",
    "helm",
    "kubectl",
    "kubernetes",
    "scp",
    "ssh",
    "terraform",
}
SAFE_NATIVE_ACTION_PREFIXES = {
    "actions/attest-build-provenance@",
    "actions/attest@",
    "actions/cache@",
    "actions/checkout@",
    "actions/download-artifact@",
    "actions/setup-node@",
    "actions/setup-python@",
    "actions/upload-artifact@",
    "anchore/sbom-action@",
    "anchore/scan-action@",
    "aquasecurity/setup-trivy@",
    "aquasecurity/trivy-action@",
    "docker/build-push-action@",
    "docker/login-action@",
    "docker/setup-buildx-action@",
    "github/codeql-action/",
    "gitleaks/gitleaks-action@",
    "pnpm/action-setup@",
    "pypa/gh-action-pip-audit@",
    "sigstore/cosign-installer@",
}
EXPECTED_IDENTITIES: dict[str, tuple[int, str, bool, bool]] = {
    "appolon1908-hue/Infustruction-repo": (1350724865, "infrastructure", True, True),
    "appolon1908-hue/Keycloak": (1347523366, "identity", True, False),
    "appolon1908-hue/Middleware-": (1347559071, "canonical-middleware", False, False),
    "appolon1908-hue/codestra": (1319808791, "application", True, False),
    "appolon1908-hue/beyvra-backend": (1319831182, "application", True, False),
    "appolon1908-hue/backend2": (1319903950, "application", True, False),
    "appolon1908-hue/beyvra-frontend": (1320246591, "application", True, False),
    "appolon1908-hue/scrapper": (1329513537, "migration-evidence", False, False),
    "appolon1908-hue/Breero.com": (1331354808, "application", True, False),
    "appolon1908-hue/Moneybee-Backend": (1343760409, "application", True, False),
    "appolon1908-hue/Telnexa-web": (1346958528, "application", True, False),
    "appolon1908-hue/codestra-production-platform": (1314230781, "controller", False, False),
}
EXPECTED_ARTIFACT_POLICIES: dict[
    str, tuple[tuple[str, ...], bool, bool, bool, str | None, str | None]
] = {
    "appolon1908-hue/Infustruction-repo": ((), False, False, False, None, None),
    "appolon1908-hue/Keycloak": ((), False, False, False, None, None),
    "appolon1908-hue/Middleware-": (
        ("ghcr.io/appolon1908-hue/codestra-middleware",),
        True,
        True,
        True,
        "cosign",
        "oci",
    ),
    "appolon1908-hue/codestra": (
        ("ghcr.io/appolon1908-hue/codestra",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-backend": (
        (
            "ghcr.io/appolon1908-hue/beyvra-backend",
            "ghcr.io/appolon1908-hue/beyvra-backend-edge",
        ),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/backend2": (
        ("ghcr.io/appolon1908-hue/backend2",),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/beyvra-frontend": (
        ("ghcr.io/appolon1908-hue/beyvra-frontend",),
        True,
        True,
        False,
        "github",
        "oci",
    ),
    "appolon1908-hue/scrapper": ((), False, False, False, None, None),
    "appolon1908-hue/Breero.com": (
        (
            "ghcr.io/appolon1908-hue/breero-api",
            "ghcr.io/appolon1908-hue/breero-frontend",
            "ghcr.io/appolon1908-hue/breero-partner",
            "ghcr.io/appolon1908-hue/breero-ops",
            "ghcr.io/appolon1908-hue/breero-admin",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Moneybee-Backend": (
        (
            "ghcr.io/appolon1908-hue/moneybee-api",
            "ghcr.io/appolon1908-hue/moneybee-worker",
            "ghcr.io/appolon1908-hue/moneybee-migrate",
        ),
        True,
        True,
        False,
        "github",
        "github",
    ),
    "appolon1908-hue/Telnexa-web": (
        ("ghcr.io/appolon1908-hue/telnexa-web",),
        True,
        True,
        False,
        "github",
        "github",
    ),
}
APPROVED_COMPLEX_SCRIPT_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Keycloak": {
        "scripts/ci/audit_keycloak_pull_requests.py": "fa0c559a3dccfd4ced2a73ebcb2e1858724dcdba654fe84198045a6abbfc358b",
        "scripts/review-plan.sh": "65fe10f82d6fdb51ebca45e0453d5288baf05fa78ddce8754946e702432b50c4",
        "scripts/runtime-preflight.sh": "67bff10567f1c9763794f17d378f1dc3785e18569bda7432d0003d872239a052",
        "scripts/runner-systemd-preflight.sh": "d49eec2b037067dbede30aac8b49328025189e6a8883b0b4314ce613a7bd37be",
        "scripts/test-backup-contract.sh": "48ac288ce0e2eb29f220b5e701ef6a11a5a6cfe3eb058c89ac74b505d3c62d62",
        "scripts/test-ephemeral-docker-auth.sh": (
            "44ed657edf1d82b7aa1d2508d75955ae"
            "30b71399c30055db198e2ea8a62ca277"
        ),
        "scripts/test-plan-gate.sh": "a1998a4a92a2535aea09f35c5de369f0675ab4276e86ab92a42f908590c0ca6d",
        "scripts/test-runtime-preflight.sh": "e4fae06b294f0385d6006d35107463eaa65ec1099fae45ef032dffa1d3f65471",
        "scripts/validate-governance.sh": "cefd59aaba1446e9aa0d8b0fc5370eab90f1d629422a0be25fad675515440c80",
        "scripts/validate-workflows.py": (
            "06b7f5eec4e36d51d9575decf70ce0a2"
            "12767b563bc0fbdb1b61fa46ae7fc321"
        ),
        "scripts/validate.sh": "770f873d978b072dc86d5b8bec1c958f3a02d67b69bdda27f8cc77a3da6ee3d8",
    },
    "appolon1908-hue/Middleware-": {
        "scripts/apply_portfolio_release_reviewer_access.py": (
            "f9ba7034692118c427555fab41b1b6e14"
            "a8698a761eb18ef6c957e1fb386c27a"
        ),
        "scripts/apply_repository_governance.py": "14b93e6b4935a5ffec7a826de68f670e96f539caec1f34335c8accc4869897c7",
        "scripts/integration_ci.sh": "8d9327fd9ad51d6ba7243d051336f623a4f75d60c60e69fd012e65f598b12d4a",
        "scripts/validate_middleware_authority_convergence.py": (
            "23679aee112625c778d7607187ea505c"
            "a2f9f0983411143728d785d011298ae4"
        ),
        "scripts/nats_integration_ci.sh": "88d843c665cece68e0fb56a931c295ee10490446cad7b64d9f5356c1cbf7263d",
        "scripts/project_ci.sh": "12a529ea96f39baec5f1eeb287209dc9db355e5dca000cbbfd7494303501b2ae",
        "scripts/release_manifest.py": "67d438833554baa448eabb34188ef3028d6e37088084be0a201e602282175d25",
        "scripts/run_ci.sh": "64d7c92279dd442144c7e1f74c3e48f0ab5d5db105238a534dcf8ccd99e93138",
        "scripts/synthetic_acceptance_ci.sh": "087dac2c5371f2013fa0a8dd22ed4024409ab5015231fb8801c75cf3203e3a8a",
        "scripts/temporal_integration_ci.sh": "76a682cc1f5b15a0a3eb15a029d87206238dfe4a262eaf5fa2c79403f147d4d6",
        "services/connector-runtime/scripts/test_postgres.sh": "b9b31391d7a04aa8b3362e182a43f880e46f9e85b4d2f5c3c66cb9a9fe88f867",
        "tests/integration/campaign_extension_concurrency.py": "252b945c5779a0a8519d3dc2225b1cf495d4995cd42089d3c24c401297475377",
        "tests/integration/campaign_identity_concurrency.py": "234d97cf48cf29f0ec26bd4cfd48f61d031f46e1250cee477088abb7a190be76",
    },
    "appolon1908-hue/codestra": {
        "scripts/deploy/read-only-runtime-discovery.sh": "14cd8ce2653da1e284da480408ba071fd989279ba889a22d0b1f21ec887e1d13",
        "scripts/ci/check-runtime-discovery.mjs": "a0ccd39eb918093ba7715c9fc40fc9facaef6feef95210c46e9fead61323708f",
        "scripts/ci/test-runtime-discovery-fixture.sh": "a7b6557ed6dc927f6dc78a45440c3cf8deda6a2410a3bf94c70231be3bda751d",
        "scripts/ci/test-runtime-discovery-host-proxy.sh": "c934ec0ff3aa97a08940c0475139edfa155fb839b43017a5a881ffde480ac9e9",
    },
    "appolon1908-hue/beyvra-frontend": {
        "client-portal/scripts/audit-gate.mjs": (
            "8f50a0920735449fe65aa988cf2f4f290"
            "aa744362bbc848830992da7752e2fd6"
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        "FX/release-init-prod.sh": "cef5fadd788f5ae5c9ba28a857bfe516e47b671e36aafcf3817b4c20b9e5115b",
        "operations/verify_release_identity.py": "8aadfc14fa376ba46483216c6323d589d4603c71d42f5a77c29286edb5b5cf0a",
        "scripts/certify_staging_api.py": (
            "a154c1bcd011c42442263d06b530e243"
            "901ec8487c6b34f032e53810f12a5a30"
        ),
    },
    "appolon1908-hue/scrapper": {
        "apps/operations-dashboard/test/api-client.test.mjs": (
            "430b330930d546cdc5270b6d3ffe10955"
            "0e9e725d646e737a54c2654d92b7646"
        ),
        "scripts/validate-gateway.sh": "d0c9888cc7bde27682a32d00fcb00d55d0ff6fc3ad711650cb6647f9dfccdc2a",
        "scripts/validate-deployment-scaffolding.sh": "03db69454e0ea0f62923ab43307ce95ab08c3586d3eb455f53552b65e052cfb9",
        "scripts/validate-workflow-policy.rb": "5cfa66e2126849121a263e0d651b5885ae0535156fb45c47a3ec5f1ca8f587c0",
        "scripts/verify-release-context.sh": "7f1799aed294208d9ad3d86d7f6d246ebf9293ab75fd8df8c16a076f86f9e7ba",
    },
    "appolon1908-hue/Breero.com": {
        "apps/api/scripts/check_schema_drift.py": "746760dea22319cd64c486a08b82ebbccee1dc256566fa6b24cee7f02ff68b47",
        "scripts/ci/test-classify-quality-scope.sh": "0365cd71d85e00facf1a64c2f11734e413430af75e4cf39e0e52971d13d5c473",
        "scripts/ci/test-validate-breero-scope.sh": "ea29de36868e28ff82e3ec151f896aed388d2421f5907151c4c13480dae20bf8",
        "scripts/ci/validate-breero-scope.sh": "f8ffb8a3953c56d7d6722938825bfb33fced802ba162f4cefd3d12be8ffb9a1e",
    },
    "appolon1908-hue/Moneybee-Backend": {
        "ops/stage-bank-credential-references.py": (
            "ea78c91ccc0d779260b13ccead92ca31"
            "16b5b0ac5f3ede028e86a8aa197e3cca"
        ),
        "ops/verify-compose-contract.py": "5b9c78f82de3784af3d68945be43abadbbe3eab7e73f3edf0f27ef7042e7e674",
        "scripts/smoke_api.py": (
            "62b60fa9fb0331d5227b51b9b2c542d"
            "4ec96da9f683a5f678a60d5f27996c692"
        ),
    },
    "appolon1908-hue/Telnexa-web": {
        "deployment/scripts/validate-compliance.sh": "a29fa2c3586332016ec468a710487bca7e5362244c6feec63ae1bde47f4f0f75",
        "scripts/smoke-local.mjs": "13d7f9fcd9bdcc1ac598018a0ca2aab3b3478c08d845b3d0f366b533e4142313",
        "scripts/validate-compliance.mjs": "cd174eebb976c8995545ceb07cd761e53ff1a54ac30c2a4b015bbd92a0768306",
        "tests/contracts/compliance.test.mjs": "1278421b46f690974e087af11fc989eecef21ad605f9707d8da81180391b0478",
    },
}
APPROVED_COMPLEX_SCRIPT_DEPENDENCY_SCAN: dict[str, frozenset[str]] = {
    "appolon1908-hue/Keycloak": frozenset(
        {"scripts/review-plan.sh", "scripts/validate.sh"}
    ),
    "appolon1908-hue/Middleware-": frozenset({"scripts/run_ci.sh"}),
    "appolon1908-hue/codestra": frozenset(
        {
            "scripts/ci/test-runtime-discovery-fixture.sh",
            "scripts/ci/test-runtime-discovery-host-proxy.sh",
        }
    ),
}
APPROVED_CONTROL_PLANE_WORKFLOW_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Middleware-": {
        ".github/workflows/exact-main-production-release.yml": (
            "d172f545ce3200d9d82eb991887a0f1d"
            "642a8dd11e5c472331fed9af8055f8d3"
        ),
        ".github/workflows/lead-automation-n8n-source-v1.yml": (
            "6b0cb7126987c14757bd1f48667bf81d"
            "50caaed769389cb30fc725766ea6bed6"
        ),
        ".github/workflows/middleware-ci.yml": (
            "385d1f652556de076cb26a480351ab6b"
            "b2c5f1d6200b9e7beae06add8ee75d42"
        ),
        ".github/workflows/python-quality-baseline.yml": (
            "cb89cb69636dc79a6a03e5df98abeb798"
            "6a823e30c2d52b1d03980dddac58cca"
        ),
        ".github/workflows/required-ci.yml": "5b135f1eec36d3baa8d605ecddf3d37aa1fbfa7bd9d58e61ba58a5324a087d5e",
        ".github/workflows/production-route-contract.yml": (
            "21595e66413a34de195d914405373b84"
            "2c8f631d053973910e6b78f63c269c7c"
        ),
        ".github/workflows/release-component-ci.yml": (
            "d3d6d5dd03cc9c8b2d0630ef6e1b9f"
            "df31ff2da8175d2a63e881696b25b0ee63"
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/ci.yml": "f10b269e0faf54b23582ca1ee9700de6f2ec9f5481f6b2be20e40b9f6d428945",
    },
    "appolon1908-hue/beyvra-frontend": {
        ".github/workflows/ci.yml": "8dfd828f1c50f774d34d22008cc8e5eb3ce4961165b388e058fd3cab6130e2e5",
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/ci.yml": "31d81c5be094a1510bc821ef4359bba591630d2273662f5de0683205d908c60d",
        ".github/workflows/dashboard-ci.yml": (
            "1f4c4add5bae50bc11fc2c7693c9a7ed"
            "e79f89300da81b9f7a6904d30462dac7"
        ),
        ".github/workflows/release-readiness.yml": (
            "22fb9e9447770c5b463b028d9ef6195d"
            "f53fbc99b2e8a467ba11e7a2b58b167b"
        ),
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/quality.yml": "68f066200e3f656c63ecabc1dcb9551d9c669eb5b3f6e5d70ab4f1960bc67043",
    },
    "appolon1908-hue/Moneybee-Backend": {
        ".github/workflows/ci.yml": (
            "0bed241476483a0ac38e0fc8bb2b06a2"
            "3b076645a6b0b355cf0420fcf4d2f451"
        ),
        ".github/workflows/release-backend-images.yml": (
            "0341c65102bb37d5a41d3b0456a20221"
            "d2ce8645af483fdea5283eb8105dddd9"
        ),
        ".github/workflows/secure-ci.yml": (
            "6ab4ebf30e47aee65ba3e1d7106ddd0c"
            "6feea546a57ebd289cf4fcfed9106e00"
        ),
    },
}
APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256: dict[str, dict[str, str]] = {
    "appolon1908-hue/Middleware-": {
        ".github/workflows/connector-runtime-api-ci.yml": "917ab06febf30f0d81146fc147794dace9510f7bb0a6fb903dd69b2244d4e1d0",
        ".github/workflows/connector-storage-ci.yml": "eada698e8756b76431a43f8d54d1aa192b9d964bca9a5e76d90476f35135bc7a",
        ".github/workflows/lead-automation-v1.yml": "9cdf5b9ce21f528bb8d0cb29b170586d212f5dfeb0e4ad237bb531a41bd89274",
        ".github/workflows/odoo-calling-contract.yml": "a186063edd3d780a5f813090b7364edb9af23e3dba845dc49c476e62acd44fd9",
    },
    "appolon1908-hue/beyvra-backend": {
        ".github/workflows/email-boundary-ci.yml": "13ec97e8fb3cf77dcea400c2c8d4d5f089a567852ebcfa7f8efc581efa6f1fd6",
    },
    "appolon1908-hue/scrapper": {
        ".github/workflows/ci.yml": "31d81c5be094a1510bc821ef4359bba591630d2273662f5de0683205d908c60d",
        ".github/workflows/release-readiness.yml": "22fb9e9447770c5b463b028d9ef6195df53fbc99b2e8a467ba11e7a2b58b167b",
    },
    "appolon1908-hue/Breero.com": {
        ".github/workflows/backend-production.yml": "6451590fa0b6a6dff14a4b8682396f270545e1f4788a7c44b1b8ba16408cdf24",
    },
}
APPROVED_UNRESOLVED_SCRIPT_TARGETS: dict[str, frozenset[str]] = {
    # Nuxt emits this checked-build output before the CI smoke-test step.
    # Repository-owned and working-directory-relative scripts are resolved and
    # inspected below; no deployment script belongs in this exception list.
    "appolon1908-hue/Telnexa-web": frozenset({".output/server/index.mjs"}),
}
APPROVED_READ_ONLY_SCRIPT_INVOCATIONS: dict[
    str, dict[str, tuple[str, frozenset[tuple[str, ...]]]]
] = {
    "appolon1908-hue/Middleware-": {
        "scripts/audit_release_endpoints.py": (
            "636088666d9e0f605325073b7e06596192cc20247207ae1f0e4531ca4cbf8628",
            frozenset({()}),
        ),
        "scripts/apply_integration_main_release_authorities.py": (
            "95b9c27abd309b1efe579672fdb8b89feaed55e8e9334c50913b2e422ad771a7",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_integration_main_release_authorities_v2.py": (
            "b5f74be0edf783bd258c6321caaf63759e8beee0b0f305d34f25c932830366c2",
            frozenset({("--mode", "validate")}),
        ),
        "scripts/apply_production_reviewer_access.py": (
            "305d52658d39cc45335676c6f3d0d780b246b8c4c9b727c68ed705b30f99da22",
            frozenset({("--mode", "validate")}),
        ),
    },
    "appolon1908-hue/beyvra-backend": {
        "operations/one_click_readonly_release.py": (
            "66f853c64b440615179cddb3a67ad027017fec0d17d5ed56178ec5b2ce9173ba",
            frozenset({("--self-test",)}),
        ),
    },
}
REQUIRED_NATIVE_WORKFLOWS: dict[str, dict[str, str]] = {
    "appolon1908-hue/Infustruction-repo": {
        "runtime_certification": ".github/workflows/staging-readonly-certification.yml",
    },
    "appolon1908-hue/Keycloak": {
        "plan_apply": ".github/workflows/deploy.yml",
        "drift_review": ".github/workflows/drift-review.yml",
    },
    "appolon1908-hue/Middleware-": {
        "signed_release": ".github/workflows/release.yml",
        "runtime_certification": ".github/workflows/production-runtime-certification.yml",
    },
    "appolon1908-hue/codestra": {
        "build_deploy": ".github/workflows/deploy.yml",
    },
}
ALLOWED_RELEASE_VALIDATOR_COMMAND_PREFIXES = {
    ("cosign", "verify"),
    ("cosign", "verify-attestation"),
    ("docker", "buildx", "imagetools", "inspect"),
    ("docker", "login"),
    ("gh", "attestation", "verify"),
    ("git", "rev-parse"),
    ("git", "status"),
}
FORBIDDEN_RELEASE_VALIDATOR_IMPORTS = {
    "fabric",
    "httpx",
    "paramiko",
    "requests",
    "socket",
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_mapping(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(message)
    return value


def require_string_list(value: object, message: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ContractError(message)
    if nonempty and not value:
        raise ContractError(message)
    if not all(isinstance(item, str) and item for item in value):
        raise ContractError(message)
    return [item for item in value if isinstance(item, str)]


def load_contract() -> dict[str, Any]:
    require(CONTRACT_PATH.is_file() and not CONTRACT_PATH.is_symlink(), "contract is missing or unsafe")
    value = json.loads(
        CONTRACT_PATH.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
    )
    require(isinstance(value, dict), "contract must be a JSON object")
    return value


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mappings."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        require(key not in result, "workflow contains a duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


@dataclass(frozen=True)
class WorkflowJob:
    data: dict[str, Any]
    raw: str
    working_directory: str | None
    shell: str | None


def default_working_directory(value: dict[str, Any], path: str) -> str | None:
    defaults = value.get("defaults")
    if defaults is None:
        return None
    require(isinstance(defaults, dict), f"workflow defaults are invalid: {path}")
    run = defaults.get("run")
    if run is None:
        return None
    require(isinstance(run, dict), f"workflow run defaults are invalid: {path}")
    working_directory = run.get("working-directory")
    require(
        working_directory is None
        or isinstance(working_directory, str)
        and bool(working_directory),
        f"workflow working-directory is invalid: {path}",
    )
    return working_directory


def default_shell(value: dict[str, Any], path: str) -> str | None:
    defaults = value.get("defaults")
    if defaults is None:
        return None
    require(isinstance(defaults, dict), f"workflow defaults are invalid: {path}")
    run = defaults.get("run")
    if run is None:
        return None
    require(isinstance(run, dict), f"workflow run defaults are invalid: {path}")
    shell = run.get("shell")
    require(
        shell is None or isinstance(shell, str) and bool(shell),
        f"workflow shell is invalid: {path}",
    )
    return shell


def workflow_jobs(workflow: str, path: str) -> dict[str, WorkflowJob]:
    """Parse GitHub Actions jobs with YAML semantics and source spans."""

    try:
        document = yaml.load(workflow, Loader=UniqueKeyLoader)
        root = yaml.compose(workflow, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ContractError(f"workflow is not valid YAML: {path}") from exc
    require(isinstance(document, dict), f"workflow is not a mapping: {path}")
    workflow_working_directory = default_working_directory(document, path)
    workflow_shell = default_shell(document, path)
    jobs_value = document.get("jobs")
    require(isinstance(jobs_value, dict) and bool(jobs_value), f"workflow has no jobs: {path}")
    require(isinstance(root, yaml.nodes.MappingNode), f"workflow root is invalid: {path}")
    jobs_node: yaml.nodes.MappingNode | None = None
    for key_node, value_node in root.value:
        if isinstance(key_node, yaml.nodes.ScalarNode) and key_node.value == "jobs":
            require(isinstance(value_node, yaml.nodes.MappingNode), f"workflow jobs are invalid: {path}")
            jobs_node = value_node
            break
    if jobs_node is None:
        raise ContractError(f"workflow jobs source is missing: {path}")
    lines = workflow.splitlines()
    result: dict[str, WorkflowJob] = {}
    for key_node, value_node in jobs_node.value:
        require(isinstance(key_node, yaml.nodes.ScalarNode), f"workflow job name is invalid: {path}")
        name = key_node.value
        data = jobs_value.get(name)
        require(isinstance(data, dict), f"workflow job is not a mapping: {path}:{name}")
        raw = "\n".join(lines[key_node.start_mark.line : value_node.end_mark.line]) + "\n"
        job_working_directory = default_working_directory(data, path)
        job_shell = default_shell(data, path)
        result[name] = WorkflowJob(
            data=data,
            raw=raw,
            working_directory=job_working_directory or workflow_working_directory,
            shell=job_shell or workflow_shell,
        )
    require(set(result) == set(jobs_value), f"workflow job source mismatch: {path}")
    return result


def workflow_steps(job: WorkflowJob, path: str) -> list[dict[str, Any]]:
    value = job.data.get("steps")
    if value is None:
        return []
    require(isinstance(value, list), f"job steps are invalid: {path}")
    steps: list[dict[str, Any]] = []
    for item in value:
        require(isinstance(item, dict), f"workflow step is not a mapping: {path}")
        for key in ("env", "with"):
            require(
                key not in item or isinstance(item[key], dict),
                f"workflow step {key} is invalid: {path}",
            )
        steps.append(item)
    return steps


def step_working_directory(
    job: WorkflowJob,
    step: dict[str, Any],
    path: str,
) -> Path:
    value = step.get("working-directory", job.working_directory)
    if value is None:
        return ROOT
    require(
        isinstance(value, str)
        and bool(value)
        and "${{" not in value
        and "$" not in value,
        f"workflow working-directory is dynamic or invalid: {path}",
    )
    candidate = ROOT / value
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise ContractError(
            f"workflow working-directory is missing or unsafe: {path}"
        ) from exc
    require(
        resolved.is_dir() and not resolved.is_symlink(),
        f"workflow working-directory is unsafe: {path}",
    )
    return resolved


def shell_tokens(script: str) -> list[str]:
    try:
        lexer = shlex.shlex(
            script.replace("\\\n", " "),
            posix=True,
            punctuation_chars="|&;()\n",
        )
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        # Bash command substitutions and heredocs are richer than POSIX shlex.
        # A conservative token fallback keeps known runtime tools visible rather
        # than treating an unsupported shell construct as safe.
        return re.findall(r"[A-Za-z0-9_./@${}:+-]+", script)


def executable_name(token: str) -> str:
    return token.strip("$(){}[]").rsplit("/", 1)[-1]


def command_token_has_dynamic_executable(token: str) -> bool:
    """Reject expansion in the executable leaf, while allowing fixed path leaves."""

    return "$" in token.rsplit("/", 1)[-1]


def absolute_executable_is_unproved(token: str) -> bool:
    return Path(token).is_absolute() and not token.startswith(("/bin/", "/usr/bin/"))


def shell_command_bindings(
    tokens: list[str],
    before_index: int | None = None,
) -> dict[str, str]:
    """Return assignments that are effective before a command token.

    Only assignment words in command position establish bindings. Arguments
    such as ``echo tool=echo`` are not assignments, and later assignments must
    not retroactively change an earlier variable executable.
    """

    bindings: dict[str, str] = {}
    expect_command = True
    control = {"coproc", "do", "elif", "else", "if", "then", "until", "while"}
    separators = {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}
    for index, token in enumerate(tokens):
        if before_index is not None and index >= before_index:
            break
        if token in separators:
            expect_command = True
            continue
        if token in control:
            expect_command = True
            continue
        if not expect_command:
            continue
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)=(.+)", token, re.DOTALL)
        if match is not None:
            bindings[match.group(1)] = match.group(2)
            continue
        expect_command = False
    return bindings


def resolved_command_token(token: str, bindings: dict[str, str]) -> str:
    match = re.fullmatch(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))", token)
    if match is None:
        return token
    return bindings.get(match.group(1) or match.group(2), token)


def shell_command_substitutions(script: str) -> tuple[list[str], str] | None:
    """Return ``$()`` bodies and shell with those bodies safely elided."""

    def substitution_end(start: int) -> int | None:
        depth = 1
        quote: str | None = None
        escaped = False
        comment = False
        at_word_start = True
        index = start
        while index < len(script):
            character = script[index]
            if comment:
                if character == "\n":
                    comment = False
                    at_word_start = True
                index += 1
                continue
            if escaped:
                escaped = False
                at_word_start = False
                index += 1
                continue
            if character == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if quote == "'":
                if character == "'":
                    quote = None
                index += 1
                continue
            if character == "'" and quote is None:
                quote = "'"
                at_word_start = False
            elif character == '"':
                quote = None if quote == '"' else '"'
                at_word_start = False
            elif character == "#" and quote is None and at_word_start:
                comment = True
            elif character == "`":
                return None
            elif character == "$" and index + 1 < len(script) and script[index + 1] == "(":
                if index + 2 >= len(script) or script[index + 2] != "(":
                    depth += 1
                    index += 1
                at_word_start = False
            elif quote is None and character == "(":
                depth += 1
                at_word_start = True
            elif quote is None and character == ")":
                depth -= 1
                if depth == 0:
                    return index
                at_word_start = False
            elif quote is None and (character.isspace() or character in ";|&{}"):
                at_word_start = True
            else:
                at_word_start = False
            index += 1
        return None

    payloads: list[str] = []
    sanitized: list[str] = []
    previous_end = 0
    quote: str | None = None
    escaped = False
    comment = False
    at_word_start = True
    index = 0
    while index < len(script):
        character = script[index]
        if comment:
            if character == "\n":
                comment = False
                at_word_start = True
            index += 1
            continue
        if escaped:
            escaped = False
            at_word_start = False
            index += 1
            continue
        if character == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if character == "'" and quote is None:
            quote = "'"
            at_word_start = False
        elif character == '"':
            quote = None if quote == '"' else '"'
            at_word_start = False
        elif character == "#" and quote is None and at_word_start:
            comment = True
        elif character == "`":
            return None
        elif character == "$" and index + 1 < len(script) and script[index + 1] == "(":
            if index + 2 < len(script) and script[index + 2] == "(":
                at_word_start = False
            else:
                end = substitution_end(index + 2)
                if end is None:
                    return None
                payloads.append(script[index + 2 : end])
                sanitized.extend((script[previous_end:index], "SUBSTITUTION"))
                previous_end = end + 1
                index = end
                at_word_start = False
        elif quote is None and (character.isspace() or character in ";|&(){}"):
            at_word_start = True
        else:
            at_word_start = False
        index += 1
    sanitized.append(script[previous_end:])
    return payloads, "".join(sanitized)


def command_indexes(tokens: list[str]) -> list[int]:
    indexes: list[int] = []
    expect_command = True
    control = {"coproc", "do", "elif", "else", "if", "then", "until", "while"}
    separators = {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}
    skip_through = -1
    for index, token in enumerate(tokens):
        if index <= skip_through:
            continue
        if token == "[[" and expect_command:
            try:
                skip_through = tokens.index("]]", index + 1)
            except ValueError:
                indexes.append(index)
                expect_command = False
            continue
        if token in separators:
            expect_command = True
            continue
        if token in control:
            expect_command = True
            continue
        if not expect_command:
            continue
        if token in {"[", "[["}:
            terminator = "]" if token == "[" else "]]"
            try:
                skip_through = tokens.index(terminator, index + 1)
            except ValueError:
                indexes.append(index)
                expect_command = False
                continue
            expect_command = False
            continue
        if executable_name(token) in SHELL_WRAPPERS:
            resolved = wrapped_executable_index(tokens, index)
            if resolved is None:
                expect_command = False
                continue
            indexes.append(resolved)
            skip_through = resolved
            expect_command = False
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
            continue
        indexes.append(index)
        expect_command = False
    return indexes


def wrapped_executable_index(tokens: list[str], start: int) -> int | None:
    """Resolve common shell wrappers without treating their options as commands."""

    no_value_options = {
        "!": set(),
        "command": {"--"},
        "env": {"--", "--ignore-environment", "--null", "-0", "-i"},
        "exec": {"--", "-c", "-l"},
        "nohup": set(),
        "sudo": {
            "--",
            "--preserve-env",
            "-E",
            "-H",
            "-K",
            "-S",
            "-b",
            "-k",
            "-n",
        },
        "time": {"--", "-a", "-p", "-v"},
    }
    value_options = {
        "env": {"--chdir", "--split-string", "--unset", "-c", "-s", "-u"},
        "exec": {"-a"},
        "sudo": {
            "--chdir",
            "--chroot",
            "--close-from",
            "--command-timeout",
            "--group",
            "--host",
            "--prompt",
            "--user",
            "-c",
            "-g",
            "-p",
            "-r",
            "-t",
            "-u",
        },
        "time": {"--format", "--output", "-f", "-o"},
    }
    index = start
    while index < len(tokens):
        wrapper = executable_name(tokens[index])
        if wrapper not in no_value_options:
            return index
        index += 1
        if wrapper == "command" and index < len(tokens) and tokens[index] in {"-v", "-V"}:
            return None
        while index < len(tokens):
            token = tokens[index]
            lower = token.lower()
            option_key = lower if token.startswith("--") else token
            if token in {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}:
                return None
            if wrapper == "env" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                index += 1
                continue
            if option_key in no_value_options[wrapper]:
                index += 1
                continue
            if wrapper == "sudo" and lower.startswith("--preserve-env="):
                index += 1
                continue
            if option_key in value_options.get(wrapper, set()):
                index += 2
                continue
            if any(
                lower.startswith(f"{option}=")
                for option in value_options.get(wrapper, set())
                if option.startswith("--")
            ):
                index += 1
                continue
            if token.startswith("-"):
                # Unknown wrapper options are ambiguous, so classify the
                # wrapper itself as unsafe rather than skipping a payload.
                return start
            break
    return None


def raw_command_arguments(tokens: list[str], index: int) -> list[str]:
    separators = {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}
    arguments: list[str] = []
    for token in tokens[index + 1 :]:
        if token in separators:
            break
        arguments.append(token)
    return arguments


def command_arguments(tokens: list[str], index: int) -> list[str]:
    return [executable_name(token) for token in raw_command_arguments(tokens, index)]


def command_consumes_pipeline(tokens: list[str], index: int) -> bool:
    return index > 0 and tokens[index - 1] == "|"


def runtime_cli_operation_is_dynamic(name: str, arguments: list[str]) -> bool:
    """Fail closed only when a runtime CLI's operation token is unresolved."""

    value_options = {
        "helm": {"--kube-apiserver", "--kube-context", "--kube-token", "--namespace", "-n"},
        "kubectl": {"--context", "--kubeconfig", "--namespace", "--server", "--token", "-n", "-s"},
        "terraform": {"-chdir"},
        "tofu": {"-chdir"},
    }.get(name, set())
    skip_value = False
    for token in arguments:
        if skip_value:
            skip_value = False
            continue
        lower = token.lower()
        option = lower.split("=", 1)[0]
        if option in value_options:
            skip_value = "=" not in token
            continue
        if token.startswith("-"):
            continue
        return "$" in token or "${{" in token
    return False


def xargs_payload(arguments: list[str]) -> str | None:
    """Return a statically delimited xargs command, or fail closed with None."""

    value_options = {
        "--arg-file",
        "--delimiter",
        "--max-args",
        "--max-chars",
        "--max-lines",
        "--max-procs",
        "--process-slot-var",
        "--replace",
        "-a",
        "-d",
        "-i",
        "-l",
        "-n",
        "-p",
        "-s",
    }
    no_value_options = {
        "--exit",
        "--no-run-if-empty",
        "--null",
        "--open-tty",
        "--show-limits",
        "--verbose",
        "-0",
        "-r",
        "-t",
        "-x",
    }
    index = 0
    while index < len(arguments):
        token = arguments[index]
        lower = token.lower()
        if token == "SUBSTITUTION" or "$" in token:
            # Expansions can move the option/command boundary or synthesize a
            # replacement option after static parsing.
            return None
        if (
            lower in {"--replace", "-i"}
            or lower.startswith("--replace=")
            or token.startswith("-I")
        ):
            # Replacement input can become the executable itself, so no
            # static payload remains to prove read-only.
            return None
        if lower in no_value_options:
            index += 1
            continue
        if lower in value_options:
            if index + 1 >= len(arguments):
                return None
            index += 2
            continue
        if any(
            lower.startswith(f"{option}=")
            for option in value_options
            if option.startswith("--")
        ):
            index += 1
            continue
        if token.startswith("-"):
            return None
        payload_tokens = arguments[index:]
        payload_name = executable_name(payload_tokens[0])
        if payload_name in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
            inline = interpreter_payload(payload_tokens, 0)
            if inline == "" or (
                inline is None
                and interpreter_script_target(payload_tokens, 0) is None
            ):
                # xargs appends stdin items after the fixed arguments. For
                # inline interpreters or an interpreter without a fixed script,
                # that input becomes executable code or a script path.
                return None
        return " ".join(payload_tokens)
    # With no explicit command, xargs invokes echo and cannot launch a hidden
    # repository/runtime executable.
    return ""


def interpreter_payload(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name == "eval":
        return tokens[index + 1] if index + 1 < len(tokens) else ""
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    payload_options = {
        "node": {"--eval", "-e"},
        "perl": {"-e"},
        "php": {"-r"},
        "python": {"-c"},
        "python3": {"-c"},
        "ruby": {"-e"},
    }.get(name, {"-c"})
    for option_index in range(index + 1, len(tokens)):
        if tokens[option_index] in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        token = tokens[option_index]
        if token in payload_options:
            return tokens[option_index + 1] if option_index + 1 < len(tokens) else ""
        for option in payload_options:
            if option.startswith("--") and token.startswith(f"{option}="):
                return token.split("=", 1)[1]
            if len(option) == 2 and token.startswith(option) and len(token) > 2:
                return token[len(option) :].removeprefix("=")
    return None


def interpreter_script_target(tokens: list[str], index: int) -> str | None:
    name = executable_name(tokens[index])
    if name not in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
        return None
    shellcheck_only = False
    skip_option_value = False
    for token in tokens[index + 1 :]:
        if token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        if skip_option_value:
            skip_option_value = False
            continue
        if (
            token == "-m"
            or token == "-"
            or token.startswith("<<")
            or token == "-c"
            or token == "-e" and name in {"node", "perl", "ruby"}
            or token == "--eval" and name == "node"
            or token == "-r" and name == "php"
        ):
            return None
        if token == "-n" and name in SHELL_INTERPRETERS:
            shellcheck_only = True
            continue
        if name == "node" and token in {"--check", "-c"}:
            shellcheck_only = True
            continue
        if token in {"-o", "--option"}:
            skip_option_value = True
            continue
        if token.startswith("-"):
            if name in SHELL_INTERPRETERS and "o" in token[1:]:
                skip_option_value = True
            continue
        if "=" in token and not token.startswith(("./", "../")):
            continue
        return None if shellcheck_only else token
    return None


def python_source_has_runtime_mutation(source: str) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return True
    aliases: dict[str, str] = {}
    command_bindings: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    command_bindings.setdefault(target.id, []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                command_bindings.setdefault(node.target.id, []).append(node.value)

    def qualified_name(node: ast.expr, seen: frozenset[str] = frozenset()) -> str:
        if isinstance(node, ast.Name):
            if node.id in command_bindings and node.id not in seen:
                resolved = {
                    qualified_name(value, seen | {node.id})
                    for value in command_bindings[node.id]
                }
                resolved.discard("")
                if not resolved:
                    return ""
                risky = sorted(
                    value
                    for value in resolved
                    if value == "getattr"
                    or value.startswith(("os.", "subprocess."))
                    or set(re.split(r"[^a-z0-9_]+", value.lower()))
                    & (NETWORK_CLIENT_HINTS | DATABASE_CLIENT_HINTS)
                )
                return risky[0] if risky else sorted(resolved)[0]
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = qualified_name(node.value, seen)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            constructor = qualified_name(node.func, seen)
            hints = set(re.split(r"[^a-z0-9_]+", constructor.lower()))
            if hints & (NETWORK_CLIENT_HINTS | DATABASE_CLIENT_HINTS):
                return constructor
            return ""
        return ""

    runtime_modules = {
        "aiosmtplib",
        "ansible",
        "azure",
        "boto3",
        "botocore",
        "digitalocean",
        "docker",
        "fabric",
        "kubernetes",
        "paramiko",
        "smtplib",
    }
    if any(
        value.split(".", 1)[0] in runtime_modules
        or value == "google.cloud"
        or value.startswith("google.cloud.")
        for value in aliases.values()
    ):
        return True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Call):
            return True
        qualified = qualified_name(node.func)
        if qualified in {
            "__import__",
            "builtins.__import__",
            "builtins.compile",
            "builtins.eval",
            "builtins.exec",
            "builtins.getattr",
            "builtins.setattr",
            "compile",
            "eval",
            "exec",
            "getattr",
            "importlib.import_module",
            "setattr",
        }:
            # Dynamic imports, code execution, and attribute lookup can hide a
            # process or network primitive from the qualified-name analysis.
            return True
        method = qualified.rsplit(".", 1)[-1].lower()
        receiver = qualified.rsplit(".", 1)[0].lower()
        receiver_hints = set(re.split(r"[^a-z0-9_]+", receiver))
        network_receiver = bool(receiver_hints & NETWORK_CLIENT_HINTS)
        database_receiver = bool(receiver_hints & DATABASE_CLIENT_HINTS)
        if method in NETWORK_MUTATION_METHODS and network_receiver:
            return True
        if method in DATABASE_MUTATION_METHODS and database_receiver:
            return True
        if method == "request" and network_receiver:
            http_method: str | None = None
            if node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str):
                    http_method = value.lower()
            for keyword in node.keywords:
                if keyword.arg == "method" and isinstance(keyword.value, ast.Constant):
                    value = keyword.value.value
                    if isinstance(value, str):
                        http_method = value.lower()
            if http_method is None or http_method in HTTP_MUTATION_METHODS:
                return True
        if method == "execute" and database_receiver:
            if not node.args:
                return True
            statement = node.args[0]
            if not (
                isinstance(statement, ast.Constant)
                and isinstance(statement.value, str)
                and SQL_MUTATION.search(statement.value) is None
            ):
                return True
        if qualified == "urllib.request.Request":
            if len(node.args) >= 2:
                return True
            for keyword in node.keywords:
                if keyword.arg == "data":
                    return True
                if keyword.arg == "method":
                    if not (
                        isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                        and keyword.value.value.lower() in {"get", "head"}
                    ):
                        return True
        if qualified == "urllib.request.urlopen":
            if len(node.args) >= 2:
                return True
            for keyword in node.keywords:
                if keyword.arg == "data":
                    return True
        if (
            qualified in {"os.system", "os.popen"}
            or qualified.startswith("os.exec")
            or qualified.startswith("os.spawn")
            or qualified in {"os.posix_spawn", "os.posix_spawnp"}
            or qualified.startswith("subprocess.")
        ):
            # os.exec* and os.spawn* have multiple incompatible argument
            # layouts. They replace or launch a process, so reject them
            # conservatively instead of risking a skipped executable argument.
            if qualified.startswith(("os.exec", "os.spawn")) or qualified in {
                "os.posix_spawn",
                "os.posix_spawnp",
            }:
                return True
            if not node.args:
                return True
            argument = node.args[0]
            if isinstance(argument, ast.Name) and argument.id in command_bindings:
                bindings = command_bindings[argument.id]
                if len(bindings) != 1:
                    return True
                argument = bindings[0]
            command = ""
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                command = argument.value
            elif isinstance(argument, (ast.List, ast.Tuple)):
                if not argument.elts:
                    return True
                first = argument.elts[0]
                if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
                    return True
                values = [
                    item.value
                    for item in argument.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                executable = executable_name(first.value)
                if executable in {"ansible-playbook", "scp", "ssh"}:
                    return True
                if executable in {"helm", "kubectl", "terraform", "tofu"} and len(values) != len(argument.elts):
                    return True
                command = " ".join(values)
            else:
                return True
            if contains_runtime_mutation(command):
                return True
    return False


def javascript_source_has_runtime_mutation(source: str) -> bool:
    lower = source.lower()

    def call_arguments(open_index: int) -> str | None:
        depth = 0
        quote: str | None = None
        escaped = False
        for index in range(open_index, len(source)):
            character = source[index]
            if escaped:
                escaped = False
                continue
            if character == "\\" and quote is not None:
                escaped = True
                continue
            if quote is not None:
                if character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
                continue
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    return source[open_index + 1 : index]
        return None

    def split_top_level(arguments: str) -> list[str] | None:
        parts: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        escaped = False
        for index, character in enumerate(arguments):
            if escaped:
                escaped = False
                continue
            if character == "\\" and quote is not None:
                escaped = True
                continue
            if quote is not None:
                if character == quote:
                    quote = None
                continue
            if character in {"'", '"', "`"}:
                quote = character
                continue
            if character in "([{":
                depth += 1
            elif character in ")]}":
                depth -= 1
                if depth < 0:
                    return None
            elif character == "," and depth == 0:
                parts.append(arguments[start:index].strip())
                start = index + 1
        if quote is not None or depth != 0:
            return None
        parts.append(arguments[start:].strip())
        return parts

    if any(
        marker in lower
        for marker in (
            "node:child_process",
            "require('child_process')",
            'require("child_process")',
            "from 'child_process'",
            'from "child_process"',
        )
    ):
        # Destructuring and ordinary assignments can rename every launcher;
        # without a JavaScript AST, child-process access is not provably safe.
        return True
    for match in re.finditer(r"\bfetch\b", lower):
        open_index = match.end()
        while open_index < len(source) and source[open_index].isspace():
            open_index += 1
        if open_index >= len(source) or source[open_index] != "(":
            # Passing or assigning fetch hides the eventual method and call.
            return True
        arguments = call_arguments(open_index)
        if arguments is None:
            return True
        parts = split_top_level(arguments)
        if parts is None or not parts or len(parts) > 2:
            return True
        if len(parts) == 2:
            options = parts[1].strip()
            if not (options.startswith("{") and options.endswith("}")):
                # An identifier or computed expression can conceal POST data.
                return True
            lowered_options = options.lower()
            if re.search(r"\bbody\s*:", lowered_options):
                return True
            method = re.search(r"\bmethod\s*:", lowered_options)
            if method is not None and re.match(
                r"\s*['\"](?:get|head)['\"]",
                lowered_options[method.end() :],
            ) is None:
                return True
    # Module imports can rename or construct clients in arbitrary ways. Until
    # those bindings are parsed, networking imports cannot prove read-only use.
    if re.search(
        r"(?:\bfrom\s*|\b(?:require|import)\s*\(\s*|\bimport\s*)"
        r"['\"](?:axios|got|superagent|undici|node-fetch|cross-fetch|"
        r"(?:node:)?(?:http|https|http2|net|tls)|socket\.io-client)"
        r"(?:/[^'\"]*)?['\"]",
        lower,
    ):
        return True
    client_aliases = set(
        re.findall(
            r"\b(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*"
            r"(?:api|api_client|axios|client|connection|http|httpx|requests|session|socket)"
            r"(?:\s*\.\s*create\s*\()?",
            lower,
        )
    )
    for pattern in (
        r"\bimport\s+([a-z_$][a-z0-9_$]*)\s+from\s*['\"](?:axios|https?|node:https?)['\"]",
        r"\bimport\s+\*\s+as\s+([a-z_$][a-z0-9_$]*)\s+from\s*['\"](?:axios|https?|node:https?)['\"]",
        r"\b(?:const|let|var)\s+([a-z_$][a-z0-9_$]*)\s*=\s*require\s*\(\s*['\"](?:axios|https?|node:https?)['\"]\s*\)",
    ):
        client_aliases.update(re.findall(pattern, lower))
    if client_aliases and any(
        re.search(
            rf"\b{re.escape(alias)}\s*\.\s*"
            r"(?:delete|patch|post|put|request|send|sendall)\s*\(",
            lower,
        )
        for alias in client_aliases
    ):
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|https|httpx|requests|session|socket)"
        r"\s*\.\s*(?:delete|patch|post|put|send|sendall)\s*\(",
        lower,
    ):
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|https|httpx|requests|session|socket)"
        r"\s*\.\s*request\s*\(",
        lower,
    ):
        # A generic request call can carry a computed write method. Reject it
        # unless a dedicated parser can prove the request is read-only.
        return True
    if re.search(
        r"\b(?:api|api_client|axios|client|connection|http|httpx|requests|session)"
        r"\s*\.\s*request\s*\(",
        lower,
    ):
        # A computed or indirect method cannot be proven read-only without a
        # JavaScript parser, so generic request clients fail closed.
        return True
    if re.search(
        r"\b(?:conn|connection|cursor|database|db|engine|session)"
        r"\s*\.\s*(?:add|commit|create|delete|execute|executemany|flush|insert|save|update|upsert)\s*\(",
        lower,
    ):
        return True
    return False


def heredoc_programs(script: str) -> list[tuple[str, str]]:
    lines = script.splitlines()
    programs: list[tuple[str, str]] = []
    index = 0
    marker_pattern = re.compile(
        r"<<(?P<strip>-?)\s*(?P<quote>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)(?=\s|$)"
    )
    while index < len(lines):
        match = marker_pattern.search(lines[index])
        if match is None:
            index += 1
            continue
        prefix = lines[index][: match.start()]
        tokens = shell_tokens(prefix)
        commands = command_indexes(tokens)
        require(bool(commands), "heredoc interpreter command is ambiguous")
        interpreter = executable_name(tokens[commands[-1]])
        marker = match.group("marker")
        strip_tabs = match.group("strip") == "-"
        end = index + 1
        while end < len(lines):
            candidate = lines[end].lstrip("\t") if strip_tabs else lines[end]
            if candidate == marker:
                break
            end += 1
        require(end < len(lines), "heredoc terminator is missing")
        if interpreter in SHELL_INTERPRETERS | SCRIPT_INTERPRETERS:
            programs.append(
                (interpreter, "\n".join(lines[index + 1 : end]) + "\n")
            )
        index = end + 1
    return programs


def shell_without_heredoc_bodies(script: str) -> str:
    """Keep heredoc launch commands while removing non-shell body text."""

    lines = script.splitlines(keepends=True)
    output: list[str] = []
    marker_pattern = re.compile(
        r"<<(?P<strip>-?)\s*(?P<quote>['\"]?)(?P<marker>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)(?=\s|$)"
    )
    index = 0
    while index < len(lines):
        line = lines[index]
        line_without_newline = line.rstrip("\r\n")
        match = marker_pattern.search(line_without_newline)
        if match is None:
            output.append(line)
            index += 1
            continue
        prefix = line_without_newline[: match.start()].rstrip()
        if "$(" in prefix:
            # The substitution body is already inspected as the heredoc's
            # interpreter program. Preserve its launch command without an
            # unterminated outer assignment/quote.
            prefix = prefix.rsplit("$(", 1)[1]
        output.append(f"{prefix}\n")
        marker = match.group("marker")
        strip_tabs = match.group("strip") == "-"
        index += 1
        while index < len(lines):
            candidate = lines[index].rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate == marker:
                break
            index += 1
        require(index < len(lines), "heredoc terminator is missing")
        index += 1
    return "".join(output)


def heredoc_has_runtime_mutation(
    script: str,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    for interpreter, body in heredoc_programs(script):
        if interpreter in {"python", "python3"}:
            if python_source_has_runtime_mutation(body):
                return True
        elif interpreter in SHELL_INTERPRETERS:
            if contains_runtime_mutation(
                body,
                seen_scripts,
                script_aliases,
                working_directory,
            ):
                return True
        else:
            # General-purpose stdin interpreters are not statically admitted.
            return True
    return False


def repository_script_has_runtime_mutation(
    target: str,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    normalized_target = target.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
    if script_aliases and normalized_target in script_aliases:
        target = script_aliases[normalized_target]
    elif script_aliases:
        for prefix, replacement in script_aliases.items():
            if prefix.endswith("/") and normalized_target.startswith(prefix):
                target = replacement + normalized_target.removeprefix(prefix)
                break
    if "${{" in target or "$" in target:
        return True
    relative_target = target.removeprefix("./")
    if Path(relative_target).is_absolute():
        return True
    if any(marker in relative_target for marker in "*?["):
        try:
            candidates = sorted(working_directory.glob(relative_target))
        except (OSError, ValueError):
            return True
        if not candidates:
            return True
        return any(
            repository_script_path_has_runtime_mutation(
                candidate,
                seen_scripts,
                script_aliases,
                working_directory,
            )
            for candidate in candidates
        )
    candidate = working_directory / relative_target
    if not candidate.exists():
        repository = os.environ.get("GITHUB_REPOSITORY")
        if not repository:
            repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
                "repository",
                "",
            )
        return target not in APPROVED_UNRESOLVED_SCRIPT_TARGETS.get(
            repository,
            frozenset(),
        )
    return repository_script_path_has_runtime_mutation(
        candidate,
        seen_scripts,
        script_aliases,
        working_directory,
    )


def approved_read_only_script_invocation(
    target: str,
    arguments: list[str],
    working_directory: Path,
) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    normalized = target.removeprefix("./")
    policy = APPROVED_READ_ONLY_SCRIPT_INVOCATIONS.get(repository, {}).get(
        normalized
    )
    if policy is None:
        return False
    expected_hash, allowed_arguments = policy
    candidate = working_directory / normalized
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return False
    if not resolved.is_file() or resolved.is_symlink():
        return False
    segment: list[str] = []
    for token in arguments:
        if token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        segment.append(token)
    return (
        tuple(segment) in allowed_arguments
        and hashlib.sha256(resolved.read_bytes()).hexdigest() == expected_hash
    )


def repository_script_path_has_runtime_mutation(
    candidate: Path,
    seen_scripts: set[Path],
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ROOT.resolve())
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if resolved in seen_scripts:
        return True
    suffix = resolved.suffix.lower()
    if suffix not in SCRIPT_SUFFIXES:
        return True
    source = resolved.read_text(encoding="utf-8")
    if resolved == Path(__file__).resolve():
        return False
    if resolved == RELEASE_VALIDATOR_PATH.resolve():
        validate_release_validator_operations(source)
        return False
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    expected_hash = APPROVED_COMPLEX_SCRIPT_SHA256.get(repository, {}).get(relative)
    if expected_hash is not None:
        if hashlib.sha256(source.encode()).hexdigest() != expected_hash:
            return True
        if relative in APPROVED_COMPLEX_SCRIPT_DEPENDENCY_SCAN.get(
            repository,
            frozenset(),
        ):
            dependency_aliases = dict(script_aliases or {})
            for variable in (
                "REPOSITORY_ROOT",
                "REPO_ROOT",
                "ROOT_DIR",
                "repository_root",
                "repo_root",
                "root_dir",
            ):
                if re.search(
                    rf"(?m)^{variable}=.*(?:dirname|git rev-parse --show-toplevel)",
                    source,
                ):
                    dependency_aliases[f"${variable}/"] = ""
                    dependency_aliases[f"${{{variable}}}/"] = ""
            return script_dependencies_have_runtime_mutation(
                source,
                dependency_aliases,
                working_directory,
            )
        return False
    if suffix == ".py":
        return python_source_has_runtime_mutation(source)
    if suffix in {".cjs", ".js", ".mjs"}:
        return javascript_source_has_runtime_mutation(source)
    if suffix not in {".bash", ".sh"}:
        return True
    return contains_runtime_mutation(
        source,
        seen_scripts | {resolved},
        script_aliases,
        working_directory,
    )


def direct_repository_script_target(
    tokens: list[str],
    index: int,
    working_directory: Path,
) -> str | None:
    command_token = tokens[index]
    for prefix in ("$GITHUB_WORKSPACE/", "${GITHUB_WORKSPACE}/"):
        if command_token.startswith(prefix):
            command_token = command_token.removeprefix(prefix)
            break
    name = executable_name(command_token)
    arguments = tokens[index + 1 :]
    if name in {".", "source"}:
        for token in arguments:
            if token in {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}:
                break
            if not token.startswith("-"):
                return token
        return ""
    token = command_token
    if token.startswith(("./", "../")):
        return token
    if "$" in token and Path(token).suffix.lower() in SCRIPT_SUFFIXES:
        # Repository-script resolution will either bind an approved generated
        # path alias or reject the unresolved variable conservatively.
        return token
    if (
        "$" not in token
        and Path(token).suffix.lower() in SCRIPT_SUFFIXES
        and (working_directory / token).is_file()
    ):
        return token
    return None


def interpreter_module_target(
    tokens: list[str],
    index: int,
    working_directory: Path,
) -> str | None:
    if executable_name(tokens[index]) not in {"python", "python3"}:
        return None
    for option_index in range(index + 1, len(tokens)):
        token = tokens[option_index]
        if token in {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}:
            break
        if token != "-m":
            continue
        if option_index + 1 >= len(tokens) or "$" in tokens[option_index + 1]:
            return ""
        module = tokens[option_index + 1]
        candidates = (
            Path(*module.split(".")).with_suffix(".py"),
            Path(*module.split(".")) / "__main__.py",
        )
        for candidate in candidates:
            if (working_directory / candidate).is_file():
                return candidate.as_posix()
        return None
    return None


def interpreter_module_arguments(tokens: list[str], index: int) -> list[str]:
    for option_index in range(index + 1, len(tokens)):
        token = tokens[option_index]
        if token in {"\n", "&", "&&", "(", ")", ";", "|", "||", "{", "}"}:
            break
        if token != "-m":
            continue
        if option_index + 1 >= len(tokens):
            return []
        return raw_command_arguments(tokens, option_index + 1)
    return []


def script_dependencies_have_runtime_mutation(
    script: str,
    script_aliases: dict[str, str] | None,
    working_directory: Path,
) -> bool:
    tokens = shell_tokens(script)
    for index in command_indexes(tokens):
        module_target = interpreter_module_target(tokens, index, working_directory)
        module_arguments = interpreter_module_arguments(tokens, index)
        targets = (
            interpreter_script_target(tokens, index),
            module_target,
            direct_repository_script_target(tokens, index, working_directory),
        )
        for target in targets:
            if (
                target is not None
                and not (
                    target == module_target
                    and approved_read_only_script_invocation(
                        target,
                        module_arguments,
                        working_directory,
                    )
                )
                and repository_script_has_runtime_mutation(
                target,
                set(),
                script_aliases,
                working_directory,
                )
            ):
                return True
    return False


def inline_interpreter_payload_has_runtime_mutation(
    interpreter: str,
    payload: str,
    seen_scripts: set[Path] | None = None,
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    if "$" in payload:
        return True
    if interpreter in {"python", "python3"}:
        return python_source_has_runtime_mutation(payload)
    if interpreter == "node":
        return javascript_source_has_runtime_mutation(payload)
    if interpreter in SHELL_INTERPRETERS:
        return contains_runtime_mutation(
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        )
    # Perl, PHP, and Ruby inline programs are not statically admitted.
    return True


def package_manager_payloads(
    name: str,
    arguments: list[str],
    seen_scripts: set[Path],
    working_directory: Path,
) -> tuple[list[str], Path] | None:
    """Resolve repository-owned package scripts, or fail closed with None."""

    directory_options = {"--cwd", "--dir", "--prefix", "-c"}
    selector_options = {"--filter", "--workspace", "-w"}
    option_value_names = directory_options | selector_options | {"--config"}
    harmless_global_flags = {
        "--color",
        "--help",
        "--no-color",
        "--silent",
        "--version",
        "--yes",
        "-h",
        "-s",
        "-v",
        "-y",
    }
    def safe_directory(base: Path, value: str) -> Path | None:
        if not value or "$" in value or "${{" in value or Path(value).is_absolute():
            return None
        try:
            candidate = (base / value).resolve(strict=True)
            candidate.relative_to(ROOT.resolve())
        except (OSError, ValueError):
            return None
        return candidate if candidate.is_dir() and not candidate.is_symlink() else None

    def selected_workspace(selector: str) -> Path | None:
        direct = safe_directory(ROOT, selector)
        candidates: set[Path] = set()
        if direct is not None and (direct / "package.json").is_file():
            candidates.add(direct)
        for pattern in ("*/package.json", "*/*/package.json", "*/*/*/package.json"):
            for package in ROOT.glob(pattern):
                if package.is_symlink() or "node_modules" in package.parts:
                    continue
                try:
                    document = json.loads(package.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(document, dict) and document.get("name") == selector:
                    candidates.add(package.parent.resolve())
        return next(iter(candidates)) if len(candidates) == 1 else None

    effective_directory = working_directory
    selector: str | None = None
    command: str | None = None
    command_index: int | None = None
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"|", "||", "&&", ";", "&", "{", "}"}:
            break
        if token == "SUBSTITUTION" or "$" in token:
            return None
        lower_token = token.lower()
        option_name = lower_token.split("=", 1)[0]
        if option_name in option_value_names:
            if "=" in token:
                value = token.split("=", 1)[1]
            else:
                if index + 1 >= len(arguments):
                    return None
                value = arguments[index + 1]
                index += 1
            if option_name in directory_options:
                resolved = safe_directory(effective_directory, value)
                if resolved is None:
                    return None
                effective_directory = resolved
            elif option_name in selector_options:
                selector = value
            else:
                # An arbitrary configuration file can change command parsing.
                return None
            index += 1
            continue
        if token.startswith("-"):
            if lower_token in harmless_global_flags:
                index += 1
                continue
            return None
        command = token
        command_index = index
        break
    if selector is not None:
        selected_directory = selected_workspace(selector)
        if selected_directory is None:
            return None
        effective_directory = selected_directory
    if command is None:
        return [], effective_directory
    lower = command.lower()
    if lower in {
        "access",
        "adduser",
        "deprecate",
        "dist-tag",
        "dlx",
        "hook",
        "login",
        "logout",
        "owner",
        "publish",
        "star",
        "team",
        "token",
        "unpublish",
        "unstar",
        "version",
    }:
        return None
    package_path = effective_directory / "package.json"
    if not package_path.is_file() or package_path.is_symlink():
        return None
    try:
        document = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    scripts = document.get("scripts", {}) if isinstance(document, dict) else {}
    if not isinstance(scripts, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in scripts.items()
    ):
        return None
    executable_command = lower
    if lower == "exec" and name in {"bun", "pnpm", "yarn"}:
        if command_index is None:
            return None
        executable_command = ""
        for token in arguments[command_index + 1 :]:
            if token in {"|", "||", "&&", ";", "&", "{", "}"}:
                break
            if token == "SUBSTITUTION" or "$" in token or token.startswith("-"):
                return None
            executable_command = executable_name(token).lower()
            break
        if not executable_command:
            return None
    if name in {"npx", "bunx"} or lower == "exec":
        dependencies: set[str] = set()
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            values = document.get(field, {})
            if isinstance(values, dict):
                dependencies.update(
                    key for key in values if isinstance(key, str)
                )
        safe_executables = {"eslint", "playwright", "tsc", "vite", "vitest"}
        declared_names = {
            "playwright": {"@playwright/test", "playwright"},
        }.get(executable_command, {executable_command})
        return (
            ([], effective_directory)
            if executable_command in safe_executables
            and bool(declared_names & dependencies)
            else None
        )
    script_name: str | None = None
    if lower in {"run", "run-script"}:
        if command_index is None:
            return None
        for token in arguments[command_index + 1 :]:
            if token in {"|", "||", "&&", ";", "&", "{", "}"}:
                break
            lower_token = token.lower()
            if lower_token in option_value_names or any(
                lower_token.startswith(f"{option}=")
                for option in option_value_names
                if option.startswith("--")
            ):
                return None
            if not token.startswith("-"):
                script_name = token
                break
        if script_name is None:
            return None
    elif name in {"bun", "pnpm", "yarn"} and lower not in {
        "add",
        "audit",
        "config",
        "exec",
        "install",
        "pack",
        "remove",
        "run",
        "run-script",
        "set",
        "upgrade",
    }:
        script_name = command
    elif lower in {"restart", "start", "stop", "test"}:
        script_name = lower
    if script_name is not None:
        selected = [f"pre{script_name}", script_name, f"post{script_name}"]
        if script_name not in scripts:
            return None
    elif lower in {"ci", "install"}:
        if "--ignore-scripts" in arguments:
            return [], effective_directory
        selected = ["preinstall", "install", "postinstall", "prepublish", "prepare"]
    elif lower == "pack":
        selected = ["prepack", "prepare", "postpack"]
    else:
        return [], effective_directory
    payloads: list[str] = []
    for selected_name in selected:
        payload = scripts.get(selected_name)
        if payload is None:
            continue
        sentinel = package_path.with_name(
            f"{package_path.name}.codestra-script-{selected_name}"
        )
        if sentinel in seen_scripts:
            return None
        seen_scripts.add(sentinel)
        payloads.append(payload)
    return payloads, effective_directory


def contains_runtime_command(script: str) -> bool:
    if heredoc_has_runtime_mutation(script, set(), None, ROOT):
        return True
    shell_script = shell_without_heredoc_bodies(script)
    parsed_substitutions = shell_command_substitutions(shell_script)
    if parsed_substitutions is None:
        return True
    substitutions, shell_script = parsed_substitutions
    if any(contains_runtime_command(payload) for payload in substitutions):
        return True
    tokens = shell_tokens(shell_script)
    for index in command_indexes(tokens):
        bindings = shell_command_bindings(tokens, index)
        command_token = resolved_command_token(tokens[index], bindings)
        name = executable_name(command_token)
        arguments = command_arguments(tokens, index)
        if command_token_has_dynamic_executable(command_token):
            return True
        if absolute_executable_is_unproved(command_token):
            return True
        if (
            name in RUNTIME_TOOLS
            or name in SHELL_WRAPPERS
            or name.endswith("deploy_immutable")
            or name.endswith("apply-plan.sh")
            or api_client_has_mutating_operation(name, arguments)
        ):
            return True
        payload = interpreter_payload(tokens, index)
        if payload is not None and inline_interpreter_payload_has_runtime_mutation(
            name,
            payload,
        ):
            return True
    return False


def contains_runtime_mutation(
    script: str,
    seen_scripts: set[Path] | None = None,
    script_aliases: dict[str, str] | None = None,
    working_directory: Path = ROOT,
) -> bool:
    if seen_scripts is None:
        seen_scripts = set()
    if heredoc_has_runtime_mutation(
        script,
        seen_scripts,
        script_aliases,
        working_directory,
    ):
        return True
    shell_script = shell_without_heredoc_bodies(script)
    parsed_substitutions = shell_command_substitutions(shell_script)
    if parsed_substitutions is None:
        return True
    substitutions, shell_script = parsed_substitutions
    if any(
        contains_runtime_mutation(
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        )
        for payload in substitutions
    ):
        return True
    tokens = shell_tokens(shell_script)
    for index in command_indexes(tokens):
        bindings = shell_command_bindings(tokens, index)
        command_token = resolved_command_token(tokens[index], bindings)
        name = executable_name(command_token)
        raw_tail = raw_command_arguments(tokens, index)
        tail = [executable_name(token) for token in raw_tail]
        lower_name = name.lower()
        payload = interpreter_payload(tokens, index)
        if payload is not None and inline_interpreter_payload_has_runtime_mutation(
            name,
            payload,
            seen_scripts,
            script_aliases,
            working_directory,
        ):
            return True
        target = interpreter_script_target(tokens, index)
        if target is not None:
            invocation_arguments: list[str] = []
            for target_index, token in enumerate(raw_tail):
                if token.removeprefix("./") == target.removeprefix("./"):
                    invocation_arguments = raw_tail[target_index + 1 :]
                    break
            if not approved_read_only_script_invocation(
                target,
                invocation_arguments,
                working_directory,
            ) and repository_script_has_runtime_mutation(
                target,
                seen_scripts,
                script_aliases,
                working_directory,
            ):
                return True
        module_target = interpreter_module_target(tokens, index, working_directory)
        if (
            module_target is not None
            and not approved_read_only_script_invocation(
                module_target,
                interpreter_module_arguments(tokens, index),
                working_directory,
            )
            and repository_script_has_runtime_mutation(
                module_target,
                seen_scripts,
                script_aliases,
                working_directory,
            )
        ):
            return True
        resolved_tokens = tokens
        if command_token != tokens[index]:
            resolved_tokens = tokens.copy()
            resolved_tokens[index] = command_token
        direct_target = direct_repository_script_target(
            resolved_tokens,
            index,
            working_directory,
        )
        if direct_target is not None and repository_script_has_runtime_mutation(
            direct_target,
            seen_scripts,
            script_aliases,
            working_directory,
        ) and not approved_read_only_script_invocation(
            direct_target,
            raw_tail,
            working_directory,
        ):
            return True
        if command_token_has_dynamic_executable(command_token) and direct_target is None:
            return True
        if absolute_executable_is_unproved(command_token):
            return True
        if command_consumes_pipeline(tokens, index) and name in (
            SHELL_INTERPRETERS | SCRIPT_INTERPRETERS
        ):
            return True
        if name in SHELL_WRAPPERS:
            return True
        if name in {"alias", "unalias"} or (
            name == "shopt" and "expand_aliases" in raw_tail
        ):
            # Shell aliases can replace an apparently harmless command token
            # after static parsing, so alias manipulation is not read-only.
            return True
        if name in {"make", "just", "task"}:
            return True
        if name in {"bun", "bunx", "npm", "npx", "pnpm", "yarn"}:
            package_resolution = package_manager_payloads(
                name,
                raw_tail,
                seen_scripts,
                working_directory,
            )
            if package_resolution is None:
                return True
            package_payloads, package_directory = package_resolution
            if any(
                contains_runtime_mutation(
                    package_payload,
                    seen_scripts,
                    script_aliases,
                    package_directory,
                )
                for package_payload in package_payloads
            ):
                return True
        if name == "find" and any(
            token.lower() in {"-exec", "-execdir", "-ok", "-okdir"}
            or token == "SUBSTITUTION"
            or "$" in token
            for token in raw_tail
        ):
            # Shell expansion can supply an action token such as -exec.
            # Unresolved arguments cannot prove a find expression read-only.
            return True
        if name == "xargs":
            payload = xargs_payload(raw_tail)
            if payload is None or payload and contains_runtime_mutation(
                payload,
                seen_scripts,
                script_aliases,
                working_directory,
            ):
                return True
        if name in {"ansible-playbook", "scp", "ssh"}:
            return True
        if name in {"helm", "kubectl", "terraform", "tofu"} and (
            runtime_cli_operation_is_dynamic(name, raw_tail)
        ):
            return True
        if name == "kubectl" and any(item in KUBECTL_MUTATIONS for item in tail):
            return True
        if name == "helm" and any(item in HELM_MUTATIONS for item in tail):
            return True
        if name in {"terraform", "tofu"} and (
            any(item in TERRAFORM_MUTATIONS for item in tail)
            or "state" in tail and any(item in {"mv", "push", "rm"} for item in tail)
        ):
            return True
        if name in {"docker", "podman"} and "compose" in tail and any(
            item in CONTAINER_MUTATIONS for item in tail
        ):
            return True
        if name in {"docker", "podman"} and any(
            item in {"exec", "run"} for item in tail
        ):
            # The image entrypoint or nested executable can perform an
            # arbitrary runtime mutation and is not statically provable here.
            return True
        if name in {"docker", "podman"} and (
            "stack" in tail
            and any(item in {"deploy", "rm"} for item in tail)
            or "service" in tail
            and any(
                item in {"create", "rm", "rollback", "scale", "update"}
                for item in tail
            )
            or "swarm" in tail
            and any(item in {"init", "join", "leave", "update"} for item in tail)
        ):
            return True
        if api_client_has_mutating_operation(name, tail):
            return True
        if (
            name.endswith("deploy_immutable")
            or name.endswith("apply-plan.sh")
            or lower_name.startswith("deploy_")
            and lower_name.endswith((".py", ".sh"))
            and any(item in {"apply", "apply-and-issue", "deploy", "rollback"} for item in tail)
            or "reconcile" in lower_name
            and any(item in {"apply", "apply-and-issue", "deploy"} for item in tail)
        ):
            return True
    return False


def option_value(tokens: list[str], names: set[str]) -> str | None:
    for index, token in enumerate(tokens):
        lower = token.lower()
        if lower in names:
            return tokens[index + 1].lower() if index + 1 < len(tokens) else ""
        for name in names:
            if lower.startswith(f"{name}="):
                return lower.split("=", 1)[1]
            if name in {"-x", "-m"} and lower.startswith(name) and len(lower) > 2:
                return lower[2:]
    return None


def api_client_has_mutating_operation(name: str, tail: list[str]) -> bool:
    """Classify explicit write modes for generic API and cloud clients."""

    lower_name = name.lower()
    lower_tail = [token.lower() for token in tail]
    if lower_name in {"curl", "wget"}:
        if lower_name == "curl" and any(
            token == "-K"
            or lower == "--config"
            or token.startswith("-K") and len(token) > 2
            or lower.startswith("--config=")
            for token, lower in zip(tail, lower_tail, strict=True)
        ):
            return True
        method = option_value(lower_tail, {"--method", "--request", "-m", "-x"})
        if method is not None and method not in {"get", "head", "options", "trace"}:
            return True
        return any(
            lower in HTTP_MUTATION_FLAGS
            or any(
                lower.startswith(f"{flag}=")
                for flag in HTTP_MUTATION_FLAGS
                if flag.startswith("--")
            )
            or lower.startswith("-d") and len(token) > 2
            or token.startswith(("-F", "-T"))
            or lower.startswith("--post-")
            for token, lower in zip(tail, lower_tail, strict=True)
        )
    if lower_name == "gh" and lower_tail:
        inherited_value_options = {"--config-dir", "--hostname", "--repo", "-r"}
        index = 0
        while index < len(lower_tail) and lower_tail[index].startswith("-"):
            option = lower_tail[index]
            if option in inherited_value_options:
                index += 2
                continue
            if any(
                option.startswith(f"{name}=")
                for name in inherited_value_options
                if name.startswith("--")
            ) or option.startswith("-r") and len(option) > 2:
                index += 1
                continue
            return True
        arguments = lower_tail[index:]
        if not arguments:
            return False
        if arguments[0] == "api":
            method = option_value(arguments[1:], {"--method", "-x"})
            return (
                method not in {None, "get"}
                or any(
                    token in {"--field", "--input", "--raw-field", "-f"}
                    or token.startswith(
                        ("--field=", "--input=", "--raw-field=", "-f=")
                    )
                    for token in arguments[1:]
                )
            )
        return arguments[:2] in (["workflow", "run"], ["run", "rerun"])
    if lower_name in {"aws", "az", "doctl", "gcloud"}:
        # These general-purpose clients can mutate through non-verb operations
        # (for example, `aws s3 cp`). No native workflow currently needs a
        # cloud CLI for read-only evidence, so any invocation fails closed.
        return True
    return False


def contains_runtime_action(step: dict[str, Any]) -> bool:
    value = step.get("uses")
    if not isinstance(value, str):
        return False
    normalized = value.split(" #", 1)[0].strip().lower()
    if normalized.startswith("actions/github-script@"):
        inputs = step.get("with")
        if not isinstance(inputs, dict) or not isinstance(inputs.get("script"), str):
            return True
        script = inputs["script"].lower()
        if any(
            marker in script
            for marker in (
                "child_process",
                "createworkflowdispatch",
                "repositorydispatch",
                "workflow_dispatch",
                "/dispatches",
                "exec.exec",
                "exec.getexecoutput",
                "fetch(",
            )
        ):
            return True
        if re.search(r"\bgithub\s*\[", script) or re.search(
            r"\b(?:const|let|var)\s*\{[^}]+\}\s*=\s*github\b",
            script,
        ):
            # Bracket access and destructuring can hide REST, request, or
            # GraphQL writers from property-name inspection.
            return True
        if re.search(
            r"github(?:\.rest)?(?:\.[a-z0-9_]+)+\."
            r"(?:add|cancel|create|delete|disable|dispatch|enable|lock|merge|"
            r"remove|rerun|set|unlock|update|upload)[a-z0-9_]*\b",
            script,
        ):
            # A mutating REST method can be assigned to another identifier
            # before invocation, so the property reference itself is unsafe.
            return True
        request_calls = list(re.finditer(r"github\.request\s*\(", script))
        if re.search(
            r"github\s*(?:\.\s*graphql\b|\[\s*['\"]graphql['\"]\s*\])",
            script,
        ):
            # GraphQL documents and interpolated fragments cannot be proved
            # read-only, and bracket access can alias the callable.
            return True
        if "github.request" in script and not request_calls:
            # Reject callable aliases such as ``const write = github.request``.
            return True
        return any(
            re.match(r"\s*['\"`]\s*(?:get|head)\s+", script[match.end() :])
            is None
            for match in request_calls
        )
    return (
        normalized.startswith("./")
        or "${{" in normalized
        or any(marker in normalized for marker in MUTATING_ACTION_MARKERS)
        or not any(
            normalized.startswith(prefix) for prefix in SAFE_NATIVE_ACTION_PREFIXES
        )
    )


def contains_image_publication(step: dict[str, Any]) -> bool:
    uses = step.get("uses")
    inputs = step.get("with")
    if isinstance(uses, str) and isinstance(inputs, dict):
        normalized = uses.split(" #", 1)[0].strip().lower()
        if normalized.startswith("docker/build-push-action@"):
            return inputs.get("push", False) not in {False, "false"}
        if normalized.startswith("actions/attest-build-provenance@"):
            return inputs.get("push-to-registry", False) not in {False, "false"}
    raw_tokens = shell_tokens(str(step.get("run", "")))
    tokens = [executable_name(item).lower() for item in raw_tokens]
    return any(
        name in {"docker", "podman"} and "push" in tokens[index + 1 : index + 5]
        for index in command_indexes(raw_tokens)
        for name in [tokens[index]]
    )


def job_condition(job: WorkflowJob) -> str | None:
    value = job.data.get("if")
    return value if isinstance(value, str) else None


def job_executable_configuration_mutation(
    job: WorkflowJob,
    *,
    approved: bool = False,
) -> bool:
    """Treat unreviewed job containers and services as executable code."""

    return not approved and ("container" in job.data or "services" in job.data)


def job_executable_configuration_approved(workflow: str, path: str) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    return (
        APPROVED_JOB_EXECUTABLE_CONFIGURATION_SHA256.get(repository, {}).get(path)
        == hashlib.sha256(workflow.encode()).hexdigest()
    )


def job_reusable_workflow_mutation(
    job: WorkflowJob,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    value = job.data.get("uses")
    if value is None:
        return False
    if not isinstance(value, str) or "${{" in value:
        return True
    normalized = value.split(" #", 1)[0].strip()
    if not normalized.startswith("./.github/workflows/"):
        return True
    candidate = ROOT / normalized.removeprefix("./")
    if candidate.is_symlink():
        return True
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to((ROOT / ".github/workflows").resolve())
    except (OSError, ValueError):
        return True
    if not resolved.is_file() or resolved.is_symlink():
        return True
    if seen_workflows is None:
        seen_workflows = set()
    if resolved in seen_workflows:
        return True
    relative = resolved.relative_to(ROOT.resolve()).as_posix()
    return workflow_has_runtime_mutation(
        resolved.read_text(encoding="utf-8"),
        relative,
        seen_workflows | {resolved},
    )


def workflow_script_aliases(workflow: str, path: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    pattern = re.compile(
        r'^\s*install\s+-m\s+0?755\s+([A-Za-z0-9_./-]+)\s+["\']?(\$\{?RUNNER_TEMP\}?/[A-Za-z0-9_.-]+)["\']?\s*$'
    )
    for job in workflow_jobs(workflow, path).values():
        for step in workflow_steps(job, path):
            uses = step.get("uses")
            inputs = step.get("with")
            if (
                isinstance(uses, str)
                and uses.startswith("actions/checkout@")
                and isinstance(inputs, dict)
                and isinstance(inputs.get("path"), str)
                and inputs.get("repository", repository) == repository
            ):
                checkout_path = str(inputs["path"]).strip("/")
                require(
                    bool(checkout_path)
                    and "${{" not in checkout_path
                    and "$" not in checkout_path,
                    f"checkout path is dynamic or invalid: {path}",
                )
                alias = f"{checkout_path}/"
                require(alias not in aliases, f"duplicate checkout path binding: {path}")
                aliases[alias] = ""
            script = str(step.get("run", "")).replace("\\\n", " ")
            for line in script.splitlines():
                match = pattern.fullmatch(line)
                if not match:
                    continue
                source, destination = match.groups()
                destination = destination.replace("$RUNNER_TEMP/", "${RUNNER_TEMP}/")
                require(destination not in aliases, f"duplicate generated script binding: {path}")
                candidate = step_working_directory(job, step, path) / source
                require(
                    candidate.is_file() and not candidate.is_symlink(),
                    f"generated script source is missing or unsafe: {path}",
                )
                aliases[destination] = source
    return aliases


def workflow_has_runtime_command(workflow: str, path: str) -> bool:
    jobs = workflow_jobs(workflow, path)
    script_aliases = workflow_script_aliases(workflow, path)
    return any(
        step_has_runtime_mutation(job, step, path, script_aliases)
        for job in jobs.values()
        for step in workflow_steps(job, path)
    )


def step_has_runtime_mutation(
    job: WorkflowJob,
    step: dict[str, Any],
    path: str,
    script_aliases: dict[str, str],
) -> bool:
    run = str(step.get("run", ""))
    shell = step.get("shell", job.shell)
    if shell is not None:
        if not isinstance(shell, str) or "${{" in shell or "$" in shell:
            return True
        shell_name = executable_name(shell.split()[0]).lower() if shell.split() else ""
        if shell_name in {"python", "python3"}:
            return python_source_has_runtime_mutation(run)
        if shell_name == "node":
            return javascript_source_has_runtime_mutation(run)
        if shell_name not in {"bash", "dash", "sh", "zsh"}:
            # PowerShell, cmd, and custom shells are not parsed by the POSIX
            # classifier. An unproved run block must be treated as mutating.
            return True
    return contains_runtime_mutation(
        run,
        script_aliases=script_aliases,
        working_directory=step_working_directory(job, step, path),
    )


def workflow_has_runtime_mutation(
    workflow: str,
    path: str,
    seen_workflows: set[Path] | None = None,
) -> bool:
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_hash = APPROVED_CONTROL_PLANE_WORKFLOW_SHA256.get(repository, {}).get(
        path
    )
    if approved_hash is not None:
        if hashlib.sha256(workflow.encode()).hexdigest() != approved_hash:
            return True
        script_aliases = workflow_script_aliases(workflow, path)
        return any(
            job_reusable_workflow_mutation(job, path, seen_workflows)
            or any(
                script_dependencies_have_runtime_mutation(
                    str(step.get("run", "")),
                    script_aliases,
                    step_working_directory(job, step, path),
                )
                or isinstance(step.get("uses"), str)
                and str(step["uses"]).strip().startswith("./")
                for step in workflow_steps(job, path)
            )
            for job in workflow_jobs(workflow, path).values()
        )
    if seen_workflows is None:
        seen_workflows = set()
    script_aliases = workflow_script_aliases(workflow, path)
    approved_job_configuration = job_executable_configuration_approved(
        workflow,
        path,
    )
    return any(
        job_executable_configuration_mutation(
            job,
            approved=approved_job_configuration,
        )
        or job_reusable_workflow_mutation(job, path, seen_workflows)
        or any(
            step_has_runtime_mutation(job, step, path, script_aliases)
            or contains_runtime_action(step)
            for step in workflow_steps(job, path)
        )
        for job in workflow_jobs(workflow, path).values()
    )


def workflow_has_image_publication(workflow: str, path: str) -> bool:
    return any(
        contains_image_publication(step)
        for job in workflow_jobs(workflow, path).values()
        for step in workflow_steps(job, path)
    )


def workflow_actions(workflow: str, path: str) -> list[str]:
    jobs = workflow_jobs(workflow, path)
    actions = [
        str(step["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        for step in workflow_steps(job, path)
        if isinstance(step.get("uses"), str) and step["uses"]
    ]
    actions.extend(
        str(job.data["uses"]).split(" #", 1)[0].strip()
        for job in jobs.values()
        if isinstance(job.data.get("uses"), str) and job.data["uses"]
    )
    return actions


def validate_intent_source_binding(intent: str) -> None:
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("verify" in jobs, "release-intent verify job is missing")
    steps = workflow_steps(jobs["verify"], ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if isinstance(step.get("uses"), str)
        and step["uses"].startswith("actions/checkout@")
    ]
    require(len(checkout_indexes) == 1, "release-intent must have one exact checkout step")
    checkout_index = checkout_indexes[0]
    checkout = steps[checkout_index]
    require(
        checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "release-intent checkout action is not pinned",
    )
    require(
        checkout["with"].get("ref") == "${{ github.sha }}",
        "release-intent checkout is not bound to the workflow commit",
    )
    require(
        checkout["with"].get("persist-credentials") is False,
        "release-intent checkout persists credentials",
    )
    precheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("name")
        == "Verify dispatched source is current protected head before checkout"
    ]
    require(len(precheck_indexes) == 1, "release-intent protected-head precheck is missing")
    require(precheck_indexes[0] < checkout_index, "release-intent checks out before validating the protected head")
    precheck = steps[precheck_indexes[0]]
    require(
        precheck["env"].get("GH_TOKEN") == "${{ github.token }}"
        and precheck["env"].get("EVENT_SHA") == "${{ github.sha }}"
        and precheck["env"].get("REQUESTED_SOURCE_SHA") == "${{ inputs.source_sha }}",
        "release-intent protected-head precheck environment is not exact",
    )
    commands = {
        line.strip()
        for line in str(precheck.get("run", "")).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required_commands = {
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
        'branch="$(gh api "repos/${GITHUB_REPOSITORY}" --jq .default_branch)"',
        'test "$branch" = "main"',
        'head="$(gh api "repos/${GITHUB_REPOSITORY}/branches/${branch}" --jq .commit.sha)"',
        'test "$head" = "$EVENT_SHA"',
    }
    require(
        required_commands <= commands,
        "release-intent protected-head precheck is incomplete",
    )


def validate_protected_job_recheck(intent: str) -> None:
    jobs = workflow_jobs(intent, ".github/workflows/manual-release-intent.yml")
    require("protected-intent" in jobs, "release-intent protected job is missing")
    job = jobs["protected-intent"]
    require(
        job.data.get("environment")
        == {"name": "${{ needs.verify.outputs.environment }}"},
        "protected job environment binding is not exact",
    )
    steps = workflow_steps(job, ".github/workflows/manual-release-intent.yml")
    checkout_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("uses")
        == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        and step.get("with", {}).get("ref") == "${{ github.sha }}"
        and step.get("with", {}).get("persist-credentials") is False
    ]
    recheck_indexes = [
        index
        for index, step in enumerate(steps)
        if step.get("run")
        == "python3 .codestra/validate-release-intent.py --recheck-protected-gates"
    ]
    require(len(checkout_indexes) == 1, "protected job exact checkout is missing")
    require(len(recheck_indexes) == 1, "protected job policy recheck is missing")
    require(checkout_indexes[0] < recheck_indexes[0], "protected job rechecks before exact checkout")
    recheck = steps[recheck_indexes[0]]
    expected_env = {
        "GH_TOKEN": "${{ github.token }}",
        "CODESTRA_ORCHESTRATOR_TOKEN": "${{ secrets.CODESTRA_ORCHESTRATOR_TOKEN }}",
        "PHASE": "${{ inputs.phase }}",
        "SOURCE_SHA": "${{ inputs.source_sha }}",
        "RELEASE_ID": "${{ inputs.release_id }}",
        "CANDIDATE_SHA256": "${{ inputs.candidate_sha256 }}",
        "IMAGES_JSON": "${{ inputs.images_json }}",
        "PREVIOUS_IMAGES_JSON": "${{ inputs.previous_images_json }}",
    }
    require(recheck.get("env") == expected_env, "protected job policy recheck inputs are incomplete")


def validate_release_validator_operations(source: str) -> None:
    """Allow evidence clients only; reject runtime-capable execution paths."""

    try:
        tree = ast.parse(source, filename=str(RELEASE_VALIDATOR_PATH))
    except SyntaxError as exc:
        raise ContractError("release-intent validator is not valid Python") from exc

    def unresolved_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = unresolved_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    imports: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                imports.add(root)
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def qualified_name(node: ast.expr) -> str:
        raw = unresolved_name(node)
        root, separator, tail = raw.partition(".")
        replacement = aliases.get(root, root)
        return f"{replacement}.{tail}" if separator else replacement

    def is_os_process_launcher(name: str) -> bool:
        return (
            name.startswith("os.exec")
            or name.startswith("os.spawn")
            or name in {"os.posix_spawn", "os.posix_spawnp"}
        )

    prohibited_url_calls = {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.request.URLopener.open",
        "urllib.request.FancyURLopener.open",
    }
    command_bindings: dict[str, set[tuple[str, ...]]] = {}
    opener_bindings: set[str] = set()

    def restricted_callable_name(name: str) -> bool:
        return (
            name.startswith("subprocess.")
            or is_os_process_launcher(name)
            or name in prohibited_url_calls
            or name == "urllib.request.Request"
        )

    def target_value_pairs(
        target: ast.expr,
        value: ast.expr,
    ) -> list[tuple[str, ast.expr]]:
        if isinstance(target, ast.Name):
            return [(target.id, value)]
        if (
            isinstance(target, (ast.List, ast.Tuple))
            and isinstance(value, (ast.List, ast.Tuple))
            and len(target.elts) == len(value.elts)
        ):
            return [
                pair
                for child_target, child_value in zip(target.elts, value.elts)
                for pair in target_value_pairs(child_target, child_value)
            ]
        return []

    def named_assignments(node: ast.AST) -> list[tuple[str, ast.expr]]:
        if isinstance(node, ast.Assign):
            return [
                pair
                for target in node.targets
                for pair in target_value_pairs(target, node.value)
            ]
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            return [(node.target.id, node.value)]
        return []

    for node in ast.walk(tree):
        for target_name, value in named_assignments(node):
            if not isinstance(value, (ast.Name, ast.Attribute)):
                invoked_callables = {
                    id(child.func)
                    for child in ast.walk(value)
                    if isinstance(child, ast.Call)
                }
                embedded_restricted = any(
                    id(child) not in invoked_callables
                    and isinstance(child, (ast.Name, ast.Attribute))
                    and restricted_callable_name(qualified_name(child))
                    for child in ast.walk(value)
                )
                require(
                    not embedded_restricted,
                    "release-intent validator stores a restricted callable "
                    f"in an unresolved expression at line {value.lineno}: "
                    f"{target_name}",
                )
            if isinstance(value, (ast.Name, ast.Attribute)):
                callable_name = qualified_name(value)
                if restricted_callable_name(callable_name):
                    aliases[target_name] = callable_name
            if isinstance(value, (ast.List, ast.Tuple)):
                prefix: list[str] = []
                for item in value.elts:
                    if not isinstance(item, ast.Constant) or not isinstance(
                        item.value, str
                    ):
                        break
                    prefix.append(item.value)
                if prefix:
                    prefix[0] = executable_name(prefix[0])
                    command_bindings.setdefault(target_name, set()).add(
                        tuple(prefix)
                    )
            elif (
                isinstance(value, ast.Call)
                and qualified_name(value.func) == "urllib.request.build_opener"
            ):
                opener_bindings.add(target_name)
    require(
        not (imports & FORBIDDEN_RELEASE_VALIDATOR_IMPORTS),
        "release-intent validator imports a runtime/network client",
    )

    allowed_subprocess_calls = {"check_output", "run"}

    def bound_commands(argument: ast.expr) -> set[tuple[str, ...]]:
        if isinstance(argument, (ast.List, ast.Tuple)):
            prefix: list[str] = []
            for item in argument.elts:
                if isinstance(item, ast.Starred) and isinstance(item.value, ast.Name):
                    if not prefix:
                        return command_bindings.get(item.value.id, set())
                    break
                if not isinstance(item, ast.Constant) or not isinstance(
                    item.value, str
                ):
                    break
                prefix.append(item.value)
            if prefix:
                prefix[0] = executable_name(prefix[0])
                return {tuple(prefix)}
        if isinstance(argument, ast.Name):
            return command_bindings.get(argument.id, set())
        return set()

    def allowed_evidence_command(command: tuple[str, ...]) -> bool:
        return any(
            len(command) >= len(prefix) and command[: len(prefix)] == prefix
            for prefix in ALLOWED_RELEASE_VALIDATOR_COMMAND_PREFIXES
        )

    function_stack: list[str] = []

    class OperationsVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            function_stack.append(node.name)
            self.generic_visit(node)
            function_stack.pop()

        @staticmethod
        def mutated_command_binding(target: ast.expr) -> bool:
            while isinstance(target, (ast.Attribute, ast.Subscript)):
                target = target.value
            return isinstance(target, ast.Name) and target.id in command_bindings

        def visit_Assign(self, node: ast.Assign) -> None:
            require(
                not any(
                    isinstance(target, (ast.Attribute, ast.Subscript))
                    and self.mutated_command_binding(target)
                    for target in node.targets
                ),
                "release-intent validator mutates an allowlisted command",
            )
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            require(
                not self.mutated_command_binding(node.target),
                "release-intent validator mutates an allowlisted command",
            )
            self.generic_visit(node)

        def visit_Return(self, node: ast.Return) -> None:
            if node.value is not None:
                require(
                    not restricted_callable_name(qualified_name(node.value)),
                    "release-intent validator returns a restricted callable",
                )
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            qualified = qualified_name(node.func)
            if isinstance(node.func, ast.Attribute):
                require(
                    not (
                        self.mutated_command_binding(node.func.value)
                        and node.func.attr
                        in {
                            "__delitem__",
                            "__iadd__",
                            "__imul__",
                            "__setitem__",
                            "clear",
                            "insert",
                            "pop",
                            "remove",
                            "reverse",
                            "sort",
                        }
                    ),
                    "release-intent validator mutates an allowlisted command",
                )
            require(
                qualified
                not in {
                    "__import__",
                    "builtins.__import__",
                    "builtins.compile",
                    "builtins.eval",
                    "builtins.exec",
                    "builtins.getattr",
                    "builtins.setattr",
                    "compile",
                    "eval",
                    "exec",
                    "getattr",
                    "importlib.import_module",
                    "setattr",
                }
                and qualified not in {"os.popen", "os.system"}
                and not is_os_process_launcher(qualified),
                "release-intent validator contains dynamic command execution",
            )
            if qualified.startswith("subprocess."):
                method = qualified.split(".", 1)[1]
                require(
                    method in allowed_subprocess_calls and bool(node.args),
                    "release-intent validator uses a non-allowlisted subprocess API",
                )
                commands = bound_commands(node.args[0])
                require(
                    bool(commands)
                    and all(allowed_evidence_command(command) for command in commands),
                    "release-intent validator executes a non-evidence command "
                    f"at line {node.lineno}: {sorted(commands)}",
                )
                require(
                    not any(
                        keyword.arg == "shell"
                        and not (
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is False
                        )
                        for keyword in node.keywords
                    ),
                    "release-intent validator enables a subprocess shell",
                )
            require(
                qualified not in prohibited_url_calls,
                "release-intent validator uses an unapproved network-opening API",
            )
            approved_url_call = qualified == "urllib.request.Request" or any(
                qualified == f"{name}.open" for name in opener_bindings
            )
            if approved_url_call:
                require(
                    bool(function_stack)
                    and function_stack[-1] in {"api_request", "download_artifact_archive"},
                    "release-intent validator opens a URL outside the evidence clients",
                )
                require(
                    len(node.args) == 1
                    and not any(isinstance(argument, ast.Starred) for argument in node.args),
                    "evidence client uses unproved positional request arguments",
                )
                require(
                    all(keyword.arg is not None for keyword in node.keywords),
                    "evidence client uses unproved request keyword expansion",
                )
                for keyword in node.keywords:
                    if keyword.arg == "data":
                        require(
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is None,
                            "evidence client request must not contain a body",
                        )
                    if keyword.arg == "method":
                        require(
                            qualified == "urllib.request.Request"
                            and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value in {"GET", "HEAD"},
                            "evidence client request method must be provably read-only",
                        )
            self.generic_visit(node)

        def visit_Attribute(self, node: ast.Attribute) -> None:
            require(
                not (
                    function_stack
                    and function_stack[-1] in {"api_request", "download_artifact_archive"}
                    and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node.attr in {"method", "data", "get_method"}
                ),
                "evidence client mutates request method or body after construction",
            )
            self.generic_visit(node)

    OperationsVisitor().visit(tree)


def validate(contract: dict[str, Any]) -> None:
    repository = os.environ.get("GITHUB_REPOSITORY", contract.get("repository", ""))
    repository_id_text = os.environ.get("GITHUB_REPOSITORY_ID")
    require(contract.get("schema_version") == SCHEMA, "contract schema mismatch")
    require(repository in EXPECTED_IDENTITIES, "repository is outside the protected catalog identity map")
    require(contract.get("repository") == repository, "repository identity mismatch")
    expected_id, expected_role, expected_deployment, expected_runtime = EXPECTED_IDENTITIES[repository]
    require(contract.get("repository_id") == expected_id, "stable repository ID mismatch")
    require(contract.get("role") == expected_role, "repository role contradicts the protected catalog")
    require(
        contract.get("deployment_authority") is expected_deployment,
        "deployment authority contradicts the protected catalog",
    )
    require(
        contract.get("runtime_mutation_authority") is expected_runtime,
        "runtime mutation authority contradicts the protected catalog",
    )
    if repository_id_text:
        require(repository_id_text.isdigit(), "GITHUB_REPOSITORY_ID is invalid")
        require(contract.get("repository_id") == int(repository_id_text), "stable repository ID mismatch")
    require(contract.get("default_branch") == "main", "default branch must be main")
    require(contract.get("release_intent_workflow") == ".github/workflows/manual-release-intent.yml", "intent workflow mismatch")
    require(contract.get("require_verified_commit") is True, "verified commits must be required")
    require(contract.get("required_check_app_id") == 15368, "required checks must be bound to GitHub Actions")

    checks = require_string_list(
        contract.get("required_checks"),
        "at least one exact-head check is required",
        nonempty=True,
    )
    require(len(checks) == len(set(checks)), "required checks contain duplicates")

    deployment_authority = contract.get("deployment_authority") is True
    runtime_mutation_authority = contract.get("runtime_mutation_authority")
    if not isinstance(runtime_mutation_authority, bool):
        raise ContractError("runtime mutation authority must be boolean")
    require(
        runtime_mutation_authority is (contract.get("role") == "infrastructure"),
        "only the infrastructure repository may hold runtime mutation authority",
    )
    supported = contract.get("supported_phases")
    if deployment_authority:
        require(supported == PHASES, "deployment authority must support the normalized phase sequence")
    else:
        require(supported == ["plan"], "non-deployment authority must be plan-only")

    artifacts = require_mapping(contract.get("artifact_policy"), "artifact policy is missing")
    minimum = artifacts.get("minimum_images")
    maximum = artifacts.get("maximum_images")
    if not isinstance(minimum, int) or not isinstance(maximum, int):
        raise ContractError("image bounds must be integers")
    require(0 <= minimum <= maximum, "image bounds are invalid")
    require(minimum == maximum, "contract must declare an exact image count")
    repositories = require_string_list(
        artifacts.get("image_repositories"),
        "image repositories must match the exact image count",
    )
    require(len(repositories) == maximum, "image repositories must match the exact image count")
    require(len(repositories) == len(set(repositories)), "image repositories contain duplicates")
    require(
        all(
            isinstance(item, str)
            and re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+", item)
            for item in repositories
        ),
        "image repository is invalid",
    )
    (
        expected_repositories,
        expected_sbom,
        expected_provenance,
        expected_signature,
        expected_verifier,
        expected_storage,
    ) = EXPECTED_ARTIFACT_POLICIES[repository]
    require(
        minimum == maximum == len(expected_repositories)
        and repositories == list(expected_repositories),
        "artifact image policy contradicts the protected repository identity",
    )
    require(
        artifacts.get("require_sbom") is expected_sbom
        and artifacts.get("require_provenance") is expected_provenance
        and artifacts.get("require_signature") is expected_signature
        and artifacts.get("attestation_verifier") == expected_verifier
        and artifacts.get("attestation_storage") == expected_storage,
        "artifact supply-chain policy contradicts the protected repository identity",
    )
    require(artifacts.get("require_digest") is True, "digest-only images are mandatory")
    require(artifacts.get("allow_rebuild_after_staging") is False, "rebuild after staging is forbidden")
    require(artifacts.get("allow_retag_after_staging") is False, "retag after staging is forbidden")
    for field in ("require_sbom", "require_provenance", "require_signature"):
        require(type(artifacts.get(field)) is bool, f"{field} must be boolean")
    supply_chain_required = any(
        artifacts[field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    )
    if supply_chain_required:
        require(artifacts.get("attestation_verifier") in {"github", "cosign"}, "attestation verifier is missing")
        require(artifacts.get("attestation_storage") in {"github", "oci"}, "attestation storage is missing")
        require(
            artifacts.get("attestation_verifier") != "cosign" or artifacts.get("attestation_storage") == "oci",
            "Cosign attestations must use OCI storage",
        )
        signer_workflow = artifacts.get("signer_workflow")
        require(
            isinstance(signer_workflow, str)
            and signer_workflow.startswith(".github/workflows/")
            and signer_workflow.endswith((".yml", ".yaml"))
            and (ROOT / signer_workflow).is_file(),
            "signer workflow is missing or invalid",
        )
    if contract.get("role") == "canonical-middleware":
        require(
            artifacts.get("require_sbom") is True
            and artifacts.get("require_provenance") is True
            and artifacts.get("require_signature") is True
            and artifacts.get("attestation_verifier") == "cosign",
            "canonical middleware supply-chain requirements cannot be downgraded",
        )

    environments = require_mapping(contract.get("environments"), "environment policy is missing")
    expected_environments = {
        "staging": "staging-readonly",
        "canary": "production-readonly-canary",
        "production": "production",
    }
    require(
        environments == expected_environments if deployment_authority else environments == {},
        "protected environment policy mismatch",
    )

    safety = require_mapping(contract.get("safety"), "safety controls are missing")
    require(set(safety) == SAFETY_KEYS, "safety controls are incomplete or unexpected")
    require(all(value is False for value in safety.values()), "every external/live effect must remain disabled")

    native = require_mapping(contract.get("native_workflows"), "native workflow policy must be an object")
    required_native = REQUIRED_NATIVE_WORKFLOWS.get(repository, {})
    require(
        all(native.get(name) == path for name, path in required_native.items()),
        "native workflow scope contradicts the protected repository mapping",
    )
    signer_workflow = artifacts.get("signer_workflow")
    if supply_chain_required:
        require(
            signer_workflow in native.values(),
            "signer workflow is outside the enforced native workflow scope",
        )
    for value in native.values():
        require(isinstance(value, str) and value.startswith(".github/workflows/") and value.endswith((".yml", ".yaml")), "native workflow path is invalid")
        path = ROOT / value
        require(path.is_file() and not path.is_symlink(), f"native workflow is missing or unsafe: {value}")
        workflow = path.read_text(encoding="utf-8")
        if runtime_mutation_authority is False and workflow_has_runtime_mutation(workflow, value):
            require_mutating_jobs_disabled(workflow, value)
    if runtime_mutation_authority is False:
        workflow_paths = sorted(
            path
            for pattern in ("*.yml", "*.yaml")
            for path in (ROOT / ".github/workflows").glob(pattern)
        )
        require(bool(workflow_paths), "repository has no workflows to enforce")
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_runtime_mutation(workflow, relative):
                require_mutating_jobs_disabled(workflow, relative)
    if repository == "appolon1908-hue/scrapper":
        for path in workflow_paths:
            relative = path.relative_to(ROOT).as_posix()
            workflow = path.read_text(encoding="utf-8")
            if workflow_has_image_publication(workflow, relative):
                require_image_publishing_jobs_disabled(workflow, relative)

    require_string_list(contract.get("blockers"), "blockers must be non-empty strings")

    require(INTENT_PATH.is_file() and not INTENT_PATH.is_symlink(), "manual release-intent workflow is missing or unsafe")
    require(RELEASE_VALIDATOR_PATH.is_file() and not RELEASE_VALIDATOR_PATH.is_symlink(), "release-intent validator is missing or unsafe")
    intent = INTENT_PATH.read_text(encoding="utf-8")
    release_validator = RELEASE_VALIDATOR_PATH.read_text(encoding="utf-8")
    validate_release_validator_operations(release_validator)
    for marker in (
        "runtime_contacted\": False",
        "production_changed\": False",
        "external_effects_enabled\": False",
        "[\"git\", \"rev-parse\", \"HEAD\"]",
        "required checks are not app-bound",
        "prior evidence hash mismatch",
        "--source-digest",
    ):
        require(marker in release_validator, f"release-intent safety marker is missing: {marker}")
    for marker in (
        "persist-credentials: false",
        "prior_evidence_run_id:",
        "protected_environment_approved == false",
        "protected_environment_job_completed = true",
    ):
        require(marker in intent, f"release-intent workflow marker is missing: {marker}")
    validate_intent_source_binding(intent)
    validate_protected_job_recheck(intent)
    require(
        not workflow_has_runtime_command(intent, ".github/workflows/manual-release-intent.yml"),
        "release-intent workflow contains a runtime/deployment command",
    )
    actions = workflow_actions(intent, ".github/workflows/manual-release-intent.yml")
    require(bool(actions) and set(actions) <= ALLOWED_ACTIONS, "release-intent workflow uses a non-allowlisted action")


def validate_negative_regressions(contract: dict[str, Any]) -> None:
    mutations = []

    missing_check = deepcopy(contract)
    missing_check["required_checks"] = []
    mutations.append(("missing required checks", missing_check))

    wrong_check_app = deepcopy(contract)
    wrong_check_app["required_check_app_id"] = 1
    mutations.append(("wrong required-check app", wrong_check_app))

    mutable_retag = deepcopy(contract)
    mutable_retag["artifact_policy"]["allow_retag_after_staging"] = True
    mutations.append(("mutable retag", mutable_retag))

    incomplete_images = deepcopy(contract)
    incomplete_images["artifact_policy"]["minimum_images"] = (
        incomplete_images["artifact_policy"]["maximum_images"] + 1
    )
    mutations.append(("invalid image bounds", incomplete_images))

    wrong_repositories = deepcopy(contract)
    wrong_repositories["artifact_policy"]["image_repositories"] = [
        "ghcr.io/example/wrong"
    ] * (wrong_repositories["artifact_policy"]["maximum_images"] + 1)
    mutations.append(("incorrect image repositories", wrong_repositories))

    identity_artifact_downgrade = deepcopy(contract)
    identity_artifact_downgrade["artifact_policy"].update(
        {
            "minimum_images": 0,
            "maximum_images": 0,
            "image_repositories": [],
            "require_sbom": False,
            "require_provenance": False,
            "require_signature": False,
            "attestation_verifier": None,
            "attestation_storage": None,
        }
    )
    if contract["artifact_policy"]["maximum_images"] != 0:
        mutations.append(("repository artifact-policy downgrade", identity_artifact_downgrade))

    live_effect = deepcopy(contract)
    live_effect["safety"]["payment_execution"] = True
    mutations.append(("enabled live effect", live_effect))

    phase_escalation = deepcopy(contract)
    phase_escalation["deployment_authority"] = False
    phase_escalation["supported_phases"] = PHASES
    mutations.append(("non-authority phase escalation", phase_escalation))

    runtime_escalation = deepcopy(contract)
    runtime_escalation["runtime_mutation_authority"] = not runtime_escalation["runtime_mutation_authority"]
    mutations.append(("runtime mutation authority contradiction", runtime_escalation))

    role_escalation = deepcopy(contract)
    role_escalation["role"] = (
        "application" if contract.get("role") == "infrastructure" else "infrastructure"
    )
    role_escalation["runtime_mutation_authority"] = (
        role_escalation["role"] == "infrastructure"
    )
    mutations.append(("self-declared infrastructure authority", role_escalation))

    missing_native = deepcopy(contract)
    missing_native["native_workflows"] = {
        "invalid": ".github/workflows/does-not-exist.yml"
    }
    mutations.append(("missing native workflow", missing_native))

    if any(
        contract["artifact_policy"][field]
        for field in ("require_sbom", "require_provenance", "require_signature")
    ):
        supply_chain_downgrade = deepcopy(contract)
        supply_chain_downgrade["artifact_policy"]["attestation_verifier"] = "none"
        mutations.append(("supply-chain verifier downgrade", supply_chain_downgrade))

    for name, mutation in mutations:
        try:
            validate(mutation)
        except ContractError:
            continue
        raise ContractError(f"negative regression unexpectedly passed: {name}")


def validate_intent_negative_regressions() -> None:
    intent = INTENT_PATH.read_text(encoding="utf-8")
    unsafe_intents = (
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            "ref: ${{ github.sha }}",
            "ref: ${{ inputs['source_sha'] }}",
            1,
        ),
        intent.replace(
            "          ref: ${{ github.sha }}",
            "          # ref: ${{ github.sha }}\n          ref: ${{ inputs.source_sha }}",
            1,
        ),
        intent.replace(
            '          test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            '          # test "$EVENT_SHA" = "$REQUESTED_SOURCE_SHA"',
            1,
        ),
    )
    for unsafe in unsafe_intents:
        try:
            validate_intent_source_binding(unsafe)
        except ContractError:
            continue
        raise ContractError("negative regression unexpectedly passed: unsafe source binding")
    unsafe_protected_job = intent.replace(
        "    environment:\n      name: ${{ needs.verify.outputs.environment }}",
        "    environment: unreviewed-production",
        1,
    )
    try:
        validate_protected_job_recheck(unsafe_protected_job)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: protected environment binding"
        )
    for command in (
        "helm upgrade release chart",
        "kubectl apply -f runtime.yml",
        "terraform apply",
        "tofu destroy",
        "ssh runtime.example true",
        "ansible-playbook production.yml",
        "./apply-plan.sh",
        "command docker pull example.invalid/image",
        'echo "$TOKEN" | docker login ghcr.io',
        "bash -c 'kubectl apply -f runtime.yml'",
        "sh -c 'terraform apply'",
        "eval 'helm upgrade release chart'",
    ):
        require(
            contains_runtime_command(command),
            f"negative runtime command regression passed: {command}",
        )
    require(
        not contains_runtime_command("# docker pull example.invalid/image"),
        "comment-only runtime command was treated as executable",
    )
    enabled_mutation = """name: synthetic
jobs:
  deploy:
    # RUNTIME_MUTATION_DISABLED=true
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
"""
    try:
        require_mutating_jobs_disabled(enabled_mutation, "synthetic.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: enabled mutating job")
    enabled_service = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    services:
      writer:
        image: example.invalid/runtime-writer:latest
    steps:
      - run: echo validation
"""
    try:
        require_mutating_jobs_disabled(enabled_service, "synthetic-service.yml")
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: executable job service"
        )
    enabled_action_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses : vendor/kubernetes-deploy@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(enabled_action_mutation, "synthetic-action.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: action mutating job")
    quoted_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: "ssh runtime.example deploy"
"""
    try:
        require_mutating_jobs_disabled(quoted_mutation, "synthetic-quoted.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: quoted mutating command")
    github_script_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await exec.exec('kubectl', ['apply', '-f', 'runtime.yml'])
"""
    try:
        require_mutating_jobs_disabled(github_script_mutation, "synthetic-github-script.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: github-script mutation")
    octokit_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await github.rest.repos.createDeployment({owner, repo, ref})
"""
    try:
        require_mutating_jobs_disabled(octokit_mutation, "synthetic-octokit.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: Octokit mutation")
    github_request_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: await github.request('POST /repos/{owner}/{repo}/deployments')
"""
    try:
        require_mutating_jobs_disabled(
            github_request_mutation,
            "synthetic-github-request.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: GitHub request mutation"
        )
    for name, script in (
        (
            "GitHub GraphQL mutation",
            "await github.graphql('mutation { createDeployment(input: {}) { id } }')",
        ),
        (
            "aliased GitHub request",
            "const write = github.request; "
            "await write('POST /repos/{owner}/{repo}/deployments')",
        ),
        (
            "aliased GitHub REST mutation",
            "const write = github.rest.issues.createComment; "
            "await write({owner, repo, issue_number, body: 'changed'})",
        ),
        (
            "bracket-aliased GitHub GraphQL",
            "const gql = github['graphql']; "
            "await gql('mutation { createDeployment(input: {}) { id } }')",
        ),
        (
            "bracket-accessed GitHub request",
            "await github['request']('POST /repos/{owner}/{repo}/deployments')",
        ),
        (
            "bracket-accessed GitHub REST mutation",
            "await github['rest']['issues']['create']({owner, repo})",
        ),
        (
            "destructured GitHub REST mutation",
            "const {createDeployment} = github.rest.repos; "
            "await createDeployment({owner, repo, ref})",
        ),
    ):
        workflow = f"""name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/github-script@0123456789012345678901234567890123456789
        with:
          script: {script}
"""
        try:
            require_mutating_jobs_disabled(workflow, "synthetic-github-writer.yml")
        except ContractError:
            pass
        else:
            raise ContractError(
                f"negative regression unexpectedly passed: {name}"
            )
    dynamic_publication = """name: synthetic
jobs:
  publish:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker/build-push-action@0123456789012345678901234567890123456789
        with:
          push: ${{ true }}
"""
    try:
        require_image_publishing_jobs_disabled(
            dynamic_publication,
            "synthetic-dynamic-publication.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: dynamic image publication"
        )
    python_shell_mutation = """name: synthetic
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: |
          import subprocess
          subprocess.run(["kubectl", "apply", "-f", "runtime.yml"])
"""
    try:
        require_mutating_jobs_disabled(
            python_shell_mutation,
            "synthetic-python-shell.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: declared Python shell")
    workflow_python_shell_mutation = """name: synthetic
defaults:
  run:
    shell: python
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: urllib.request.urlopen(url, data=b'x')
"""
    try:
        require_mutating_jobs_disabled(
            workflow_python_shell_mutation,
            "synthetic-workflow-python-shell.yml",
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: workflow-level Python shell"
        )
    require(
        workflow_has_runtime_command(
            python_shell_mutation,
            "synthetic-release-intent-python-shell.yml",
        ),
        "negative release-intent Python shell regression passed",
    )
    reusable_mutation = """name: synthetic
jobs:
  deploy:
    uses: vendor/runtime/.github/workflows/deploy.yml@0123456789012345678901234567890123456789
"""
    try:
        require_mutating_jobs_disabled(reusable_mutation, "synthetic-reusable.yml")
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: reusable workflow mutation")
    local_reusable = ROOT / ".github/workflows/.codestra-local-runtime-negative.yml"
    try:
        local_reusable.write_text(
            """name: synthetic local runtime
on: workflow_call
jobs:
  deploy:
    runs-on: ubuntu-24.04
    steps:
      - run: kubectl apply -f runtime.yml
""",
            encoding="utf-8",
        )
        caller = """name: synthetic caller
jobs:
  deploy:
    uses: ./.github/workflows/.codestra-local-runtime-negative.yml
"""
        try:
            require_mutating_jobs_disabled(caller, "synthetic-local-reusable.yml")
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: local reusable workflow mutation"
            )
    finally:
        local_reusable.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix=".codestra-contract-", dir=ROOT) as directory:
        local_script = Path(directory) / "runtime.sh"
        local_script.write_text("kubectl apply -f runtime.yml\n", encoding="utf-8")
        relative = local_script.relative_to(ROOT).as_posix()
        require(
            contains_runtime_mutation(f"bash {relative}"),
            "negative local interpreter script regression passed",
        )
        require(
            contains_runtime_mutation(relative),
            "negative directly invoked script regression passed",
        )
        require(
            contains_runtime_mutation(f"source {relative}"),
            "negative sourced script regression passed",
        )
        require(
            contains_runtime_mutation(f"$GITHUB_WORKSPACE/{relative}"),
            "negative workspace-qualified script regression passed",
        )
        working_directory = Path(directory) / "nested"
        working_directory.mkdir()
        nested_script = working_directory / "runtime-nested.sh"
        nested_script.write_text("docker service update runtime\n", encoding="utf-8")
        nested_relative = working_directory.relative_to(ROOT).as_posix()
        working_directory_workflow = f"""name: synthetic working directory
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - working-directory: {nested_relative}
        run: bash runtime-nested.sh
"""
        try:
            require_mutating_jobs_disabled(
                working_directory_workflow,
                "synthetic-working-directory.yml",
            )
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: working-directory script"
            )
        require(
            contains_runtime_mutation(
                "bash runtime-*.sh",
                working_directory=working_directory,
            ),
            "negative globbed script regression passed",
        )
        module_directory = working_directory / "ops"
        module_directory.mkdir()
        (module_directory / "deploy.py").write_text(
            "import subprocess\n"
            "subprocess.run(['kubectl', 'apply', '-f', 'runtime.yml'], check=True)\n",
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "python3 -m ops.deploy",
                working_directory=working_directory,
            ),
            "negative Python module regression passed",
        )
        require(
            contains_runtime_mutation(
                "python3 -B -E -I -s -m ops.deploy",
                working_directory=working_directory,
            ),
            "negative long-option Python module regression passed",
        )
        (working_directory / "package.json").write_text(
            json.dumps(
                {
                    "name": "codestra-contract-fixture",
                    "scripts": {
                        "deploy": "kubectl apply -f runtime.yml",
                        "prepack": "kubectl apply -f runtime.yml",
                        "validate": "python3 -m compileall -q .",
                    }
                }
            ),
            encoding="utf-8",
        )
        require(
            contains_runtime_mutation(
                "npm run deploy",
                working_directory=working_directory,
            ),
            "negative package script regression passed",
        )
        require(
            not contains_runtime_mutation(
                "npm run validate",
                working_directory=working_directory,
            ),
            "read-only package script regression failed",
        )
        require(
            contains_runtime_mutation(
                "npm pack",
                working_directory=working_directory,
            ),
            "negative package lifecycle regression passed",
        )
        require(
            contains_runtime_mutation(
                "npm --prefix . run deploy",
                working_directory=working_directory,
            ),
            "negative package option regression passed",
        )
        for scoped_command in (
            "npm --workspace codestra-contract-fixture run deploy",
            "pnpm --filter codestra-contract-fixture deploy",
        ):
            require(
                contains_runtime_mutation(
                    scoped_command,
                    working_directory=ROOT,
                ),
                "negative scoped package regression passed",
            )
    require(
        contains_runtime_mutation("bash generated-runtime.sh"),
        "negative unresolved script regression passed",
    )
    require(
        contains_runtime_mutation(
            """python3 - <<'PY'
import subprocess
subprocess.run(["kubectl", "apply", "-f", "runtime.yml"], check=True)
PY
"""
        ),
        "negative stdin interpreter regression passed",
    )
    require(
        contains_runtime_mutation(
            """python3 <<'PY' > /tmp/out
import urllib.request
urllib.request.urlopen('https://runtime.example/mutate', data=b'x')
PY
"""
        ),
        "negative redirected heredoc regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            'import requests\nrequests.post("https://runtime.example/mutate")\n'
        ),
        "negative Python HTTP mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import urllib.request\n"
            "request = urllib.request.Request("
            "'https://runtime.example/mutate', method='POST')\n"
        ),
        "negative Python urllib mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import urllib.request\n"
            "urllib.request.urlopen("
            "'https://runtime.example/mutate', data=b'x=1')\n"
        ),
        "negative Python urlopen body regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os, urllib.request\n"
            "urllib.request.Request('https://runtime.example/mutate', "
            "method=os.environ['METHOD'])\n"
        ),
        "negative computed urllib method regression passed",
    )
    for dynamic_import in (
        "__import__('subprocess').run(['kubectl', 'apply'])\n",
        "import importlib\n"
        "importlib.import_module('subprocess').run(['kubectl', 'apply'])\n",
    ):
        require(
            python_source_has_runtime_mutation(dynamic_import),
            "negative dynamic Python import regression passed",
        )
    require(
        python_source_has_runtime_mutation(
            "import boto3\nboto3.client('s3').upload_file('a', 'bucket', 'key')\n"
        ),
        "negative Python cloud-client mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import smtplib\nsmtp = smtplib.SMTP('smtp.example')\n"
            "smtp.sendmail('from@example', ['to@example'], 'message')\n"
        ),
        "negative live SMTP delivery regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.execvp('kubectl', ['kubectl', 'apply', '-f', 'runtime.yml'])\n"
        ),
        "negative Python os.exec mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.spawnlp(os.P_WAIT, 'kubectl', 'kubectl', 'apply', "
            "'-f', 'runtime.yml')\n"
        ),
        "negative Python os.spawn mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import os\nos.posix_spawnp('kubectl', "
            "['kubectl', 'apply', '-f', 'runtime.yml'], os.environ)\n"
        ),
        "negative Python os.posix_spawn mutation regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch = subprocess.run\n"
            "launch(['kubectl', 'apply', '-f', 'runtime.yml'], check=True)\n"
        ),
        "negative assigned Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch: object = subprocess.run\n"
            "launch(['kubectl', 'apply', '-f', 'runtime.yml'], check=True)\n"
        ),
        "negative annotated Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import subprocess\nlaunch = subprocess.run\n"
            "launch(['kubectl', 'apply'])\nlaunch = print\n"
        ),
        "negative reassigned Python launcher regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import requests\nrequests.Session().post('https://runtime.example/mutate')\n"
        ),
        "negative constructed Python client regression passed",
    )
    require(
        python_source_has_runtime_mutation(
            "import requests\nclient = requests.Session()\n"
            "client.post('https://runtime.example/mutate')\n"
        ),
        "negative assigned Python client regression passed",
    )
    require(
        javascript_source_has_runtime_mutation(
            "await client.post('https://runtime.example/mutate')\n"
        ),
        "negative JavaScript HTTP mutation regression passed",
    )
    require(
        javascript_source_has_runtime_mutation(
            "await axios.request({method: 'post', url: '/mutate'})\n"
        ),
        "negative JavaScript generic request regression passed",
    )
    for javascript_mutation in (
        "const writer = axios.create(); await writer.post('/mutate')\n",
        "import transport from 'axios'; await transport.post('/mutate')\n",
        "const write = fetch; await write('/mutate', {method: 'POST'})\n",
        "await fetch(new URL(endpoint), {method: 'POST', body})\n",
        "const options = {method: 'POST', body: data}; fetch(url, options)\n",
        "import https from 'node:https'; "
        "https.request({method: 'POST'}, callback).end()\n",
        'const {exec: run} = require("node:child_process"); '
        'run("kubectl apply -f runtime.yml")\n',
    ):
        require(
            javascript_source_has_runtime_mutation(javascript_mutation),
            "negative aliased/nested JavaScript mutation regression passed",
        )
    require(
        not python_source_has_runtime_mutation(
            'import requests\nrequests.get("https://evidence.example/status")\n'
        ),
        "read-only Python HTTP regression failed",
    )
    require(
        not python_source_has_runtime_mutation(
            'cursor.execute("SELECT status FROM evidence")\n'
        ),
        "read-only Python SQL regression failed",
    )
    require(
        python_source_has_runtime_mutation(
            'cursor.execute("WITH removed AS (DELETE FROM sessions RETURNING *) "'
            '"SELECT * FROM removed")\n'
        ),
        "negative mutating SQL CTE regression passed",
    )
    unsafe_validator = """import subprocess
subprocess.run([\"kubectl\", \"apply\", \"-f\", \"runtime.yml\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: runtime validator operation")
    unsafe_aliased_validator = """import subprocess as sp
sp.run(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_aliased_validator)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: aliased runtime operation")
    unsafe_callable_validator = """import subprocess
runner = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: assigned subprocess callable"
        )
    unsafe_annotated_callable_validator = """import subprocess
runner: object = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_annotated_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: annotated subprocess callable"
        )
    unsafe_chained_callable_validator = """import subprocess
ignored = runner = subprocess.run
runner(["kubectl", "apply", "-f", "runtime.yml"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_chained_callable_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: chained subprocess callable"
        )
    for indirect_callable_validator in (
        "import subprocess\n(runner,) = (subprocess.run,)\n"
        "runner(['kubectl', 'apply'])\n",
        "import subprocess\ndef launcher():\n    return subprocess.run\n"
        "runner = launcher()\nrunner(['kubectl', 'apply'])\n",
        "import subprocess\nrunner = {'go': subprocess.run}['go']\n"
        "runner(['kubectl', 'apply'])\n",
    ):
        try:
            validate_release_validator_operations(indirect_callable_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: indirect restricted callable"
            )
    for unsafe_dynamic_validator in (
        "import subprocess\nrunner = getattr(subprocess, 'run')\n"
        "runner(['kubectl', 'apply'])\n",
        "import urllib.request\ngetattr(urllib.request, 'urlopen')"
        "('https://runtime.example/mutate')\n",
        "import builtins\nbuiltins.exec("
        '"import os; os.system(\\\'kubectl apply -f runtime.yml\\\')")\n',
        "import builtins, subprocess\n"
        "launch = builtins.getattr(subprocess, 'run')\n"
        "launch(['kubectl', 'apply'])\n",
        "import importlib\n"
        "importlib.import_module('subprocess').run(['kubectl', 'apply'])\n",
    ):
        try:
            validate_release_validator_operations(unsafe_dynamic_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: dynamic restricted callable"
            )
    unsafe_mutated_command_validator = """import subprocess
command = ["git", "status"]
command[0] = "kubectl"
command[1] = "apply"
subprocess.run(command, check=True)
"""
    try:
        validate_release_validator_operations(unsafe_mutated_command_validator)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: mutated allowlisted command"
        )
    unsafe_method_mutated_command_validator = """import subprocess
command = ["git", "status"]
command.clear()
command.extend(["kubectl", "apply"])
subprocess.run(command, check=True)
"""
    try:
        validate_release_validator_operations(
            unsafe_method_mutated_command_validator
        )
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: method-mutated allowlisted command"
        )
    for unsafe_os_validator in (
        "import os\nos.execvp('kubectl', ['kubectl', 'apply'])\n",
        "import os\nlaunch = os.posix_spawnp\n"
        "launch('kubectl', ['kubectl', 'apply'], os.environ)\n",
    ):
        try:
            validate_release_validator_operations(unsafe_os_validator)
        except ContractError:
            pass
        else:
            raise ContractError(
                "negative regression unexpectedly passed: release-validator OS launcher"
            )
    unsafe_urlopen = """import urllib.request
urllib.request.urlopen("https://runtime.example/mutate")
"""
    try:
        validate_release_validator_operations(unsafe_urlopen)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: unapproved URL opener")
    unsafe_aliased_urlopen = """import urllib.request
open_url = urllib.request.urlopen
open_url("https://runtime.example/mutate")
"""
    try:
        validate_release_validator_operations(unsafe_aliased_urlopen)
    except ContractError:
        pass
    else:
        raise ContractError(
            "negative regression unexpectedly passed: aliased URL opener"
        )
    for function_name in ("api_request", "download_artifact_archive"):
        for request_arguments in (
            "url, method='POST'", "url, data=b'payload'",
            "url, method=method", "url, **options", "url, b'payload'",
            "*arguments", "url, method='GET', data=b'payload'",
        ):
            unsafe = (
                "import urllib.request\n"
                f"def {function_name}():\n"
                f"    request = urllib.request.Request({request_arguments})\n"
            )
            try:
                validate_release_validator_operations(unsafe)
            except ContractError:
                pass
            else:
                raise ContractError(f"mutating evidence request admitted: {request_arguments}")
        for suffix in ("", ", method='GET'", ", method='HEAD'", ", data=None"):
            validate_release_validator_operations(
                "import urllib.request\n"
                f"def {function_name}():\n"
                f"    request = urllib.request.Request(url{suffix})\n"
            )
        for statement in (
            "NO_REDIRECT_OPENER.open(request, data=b'payload')",
            "NO_REDIRECT_OPENER.open(request, b'payload')",
            "NO_REDIRECT_OPENER.open(request, **options)",
            "request.method = 'POST'", "request.data = b'payload'",
            "request.method: str = 'POST'",
        ):
            unsafe = (
                "import urllib.request\n"
                "NO_REDIRECT_OPENER = urllib.request.build_opener()\n"
                f"def {function_name}():\n"
                "    request = urllib.request.Request(url)\n"
                f"    {statement}\n"
            )
            try:
                validate_release_validator_operations(unsafe)
            except ContractError:
                pass
            else:
                raise ContractError(f"mutating evidence opener admitted: {statement}")
    for source in (
        'import transport from "axios"; transport.post(runtimeUrl, payload)',
        'import { request as send } from "undici"; send(url, options)',
        'import * as transport from "node:https"; transport.request(options)',
        'const transport = require("axios"); transport.create().post(url, body)',
        'const {default: transport} = await import("got"); transport.post(url)',
        'import transport from "axios/dist/node/axios.cjs"; transport.post(url)',
    ):
        require(javascript_source_has_runtime_mutation(source),
                f"imported network alias bypass admitted: {source}")
    require(not javascript_source_has_runtime_mutation(
        'import { strict as assert } from "node:assert"; assert.equal(1, 1)'
    ), "read-only non-network import was rejected")
    for smtp_source in (
        "import smtplib; smtp = smtplib.SMTP('example.invalid'); "
        "smtp.sendmail('a', 'b', 'c')",
        "from smtplib import SMTP_SSL as Mail; "
        "Mail('example.invalid').send_message(message)",
        "import aiosmtplib; aiosmtplib.send(message)",
    ):
        require(
            python_source_has_runtime_mutation(smtp_source),
            "negative SMTP delivery regression passed",
        )
    unsafe_status_writer = """import subprocess
subprocess.run([\"gh\", \"api\", \"--method\", \"POST\"], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_status_writer)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: validator status writer")
    unsafe_buildx_writer = """import subprocess
subprocess.run(["docker", "buildx", "build", "--push", "."], check=True)
"""
    try:
        validate_release_validator_operations(unsafe_buildx_writer)
    except ContractError:
        pass
    else:
        raise ContractError("negative regression unexpectedly passed: validator image writer")
    for command in (
        "curl -X POST https://runtime.example/mutate",
        "METHOD=POST; curl -X \"$METHOD\" https://runtime.example/mutate",
        "curl --data-urlencode action=deploy https://runtime.example/mutate",
        "gh api --method POST repos/example/runtime/dispatches",
        "gh -R example/runtime workflow run deploy.yml",
        "gh run rerun 123 -R example/runtime",
        "aws ecs update-service --cluster production --service api",
        "aws s3 cp artifact s3://production-bucket/artifact",
        "env -i kubectl apply -f runtime.yml",
        "sudo -n ssh runtime.example deploy",
        "sudo --unknown-option harmless-command",
        "docker stack deploy -c compose.yml app",
        "docker service update --image example.invalid/app service",
        "docker run --rm bitnami/kubectl apply -f runtime.yml",
        "builtin eval 'kubectl apply -f runtime.yml'",
        "timeout 60 kubectl apply -f runtime.yml",
        "result=`kubectl apply -f runtime.yml`",
        'result="$(kubectl apply -f runtime.yml)"',
        'tool=kubectl; "$tool" apply -f runtime.yml',
        'tool=kubectl; "$tool" apply -f runtime.yml; tool=echo',
        'tool=kubectl; echo tool=echo; "$tool" apply -f runtime.yml',
        'kubectl "$ACTION" -f runtime.yml',
        "coproc kubectl apply -f runtime.yml",
        "deploy() { kubectl apply -f runtime.yml; }; deploy",
        "printf '%s ' runtime.yml | xargs kubectl apply -f",
        "printf kubectl | xargs --replace={} {} apply -f runtime.yml",
        "printf kubectl | xargs $(printf '%s' '--replace={}') "
        "sh -c '{} apply -f runtime.yml'",
        "printf '%s\\0' 'kubectl apply -f runtime.yml' | xargs -0 sh -c",
        "printf './deploy.sh\\n' | xargs bash",
        "find . -exec kubectl apply -f runtime.yml {} \\;",
        'ACTION=-exec; find . "$ACTION" kubectl apply -f runtime.yml {} \\;',
        'find . "${ACTION}" kubectl apply -f runtime.yml {} \\;',
        'action=-execdir; find . "$action" sh -c '
        '"kubectl apply -f runtime.yml" \\;',
        "shopt -s expand_aliases; alias deploy='kubectl apply -f runtime.yml'; deploy",
        "make up",
        "curl -K request.conf",
        "curl -fsSL https://example.invalid/deploy.sh | bash",
        "python3 -c \"import subprocess; "
        "subprocess.run(['kubectl', 'apply', '-f', 'runtime.yml'])\"",
        "python3 -B -E -I -c \"import subprocess; "
        "subprocess.run(['kubectl', 'apply'])\"",
        "node --eval='require(\"node:child_process\").execSync("
        '"kubectl apply -f runtime.yml")\'',
        "python3 -c'import os; os.system(\"kubectl apply -f runtime.yml\")'",
        "/tmp/python",
        "/tmp/generated-runtime apply",
        "echo foo\\ # `kubectl apply -f runtime.yml`",
    ):
        require(
            contains_runtime_mutation(command),
            f"negative API mutation regression passed: {command}",
        )
    require(
        not contains_runtime_mutation(
            "find . -type f -print0 | xargs -0 sha256sum"
        ),
        "read-only xargs checksum regression failed",
    )
    require(
        not contains_runtime_mutation("# `kubectl apply -f runtime.yml`"),
        "comment-only legacy substitution was treated as executable",
    )


def require_mutating_jobs_disabled(workflow: str, path: str) -> None:
    mutating_jobs = 0
    script_aliases = workflow_script_aliases(workflow, path)
    repository = os.environ.get("GITHUB_REPOSITORY")
    if not repository:
        repository = json.loads(CONTRACT_PATH.read_text(encoding="utf-8")).get(
            "repository",
            "",
        )
    approved_control_plane = (
        APPROVED_CONTROL_PLANE_WORKFLOW_SHA256.get(repository, {}).get(path)
        == hashlib.sha256(workflow.encode()).hexdigest()
    )
    approved_job_configuration = job_executable_configuration_approved(
        workflow,
        path,
    )
    for job_name, job in workflow_jobs(workflow, path).items():
        if approved_control_plane:
            mutating = job_reusable_workflow_mutation(job, path) or any(
                script_dependencies_have_runtime_mutation(
                    str(step.get("run", "")),
                    script_aliases,
                    step_working_directory(job, step, path),
                )
                or isinstance(step.get("uses"), str)
                and str(step["uses"]).strip().startswith("./")
                for step in workflow_steps(job, path)
            )
        else:
            mutating = job_executable_configuration_mutation(
                job,
                approved=approved_job_configuration,
            ) or job_reusable_workflow_mutation(job, path) or any(
                step_has_runtime_mutation(job, step, path, script_aliases)
                or contains_runtime_action(step)
                for step in workflow_steps(job, path)
            )
        if mutating:
            mutating_jobs += 1
            require(
                "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                f"mutating job lacks disable marker: {path}:{job_name}",
            )
            require(
                job_condition(job) == "${{ false }}",
                f"mutating job is not unconditionally disabled: {path}:{job_name}",
            )
    require(mutating_jobs > 0, f"native mutation classification drift: {path}")


def require_image_publishing_jobs_disabled(workflow: str, path: str) -> None:
    publishing_jobs = 0
    for job in workflow_jobs(workflow, path).values():
        if any(
            contains_image_publication(step)
            for step in workflow_steps(job, path)
        ):
            publishing_jobs += 1
            require(
                "RUNTIME_MUTATION_DISABLED=true" in job.raw,
                f"image-publishing job lacks disable marker: {path}",
            )
            require(
                job_condition(job) == "${{ false }}",
                f"image-publishing job is not unconditionally disabled: {path}",
            )
    require(publishing_jobs > 0, f"image publication classification drift: {path}")


def main() -> int:
    contract = load_contract()
    validate(contract)
    validate_negative_regressions(contract)
    validate_intent_negative_regressions()
    subprocess.run(
        ["python3", str(RELEASE_VALIDATOR_PATH), "--self-test"],
        cwd=ROOT,
        check=True,
    )
    expected_sha = os.environ.get("EXPECTED_SHA")
    if expected_sha:
        require(re.fullmatch(r"[0-9a-f]{40}", expected_sha) is not None, "expected source SHA is invalid")
        actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        require(actual_sha == expected_sha, "contract validation checkout is not the exact event source")
    print("PRODUCTION_ORCHESTRATOR_CONTRACT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
