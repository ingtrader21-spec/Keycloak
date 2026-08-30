from __future__ import annotations

import argparse
import sys

from .apply import cmd_apply
from .export import cmd_export_rollback, cmd_export_secrets, cmd_prepare_rollback
from .plan_review import cmd_plan, cmd_review
from .common import EngineError

def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    sub = value.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--output-dir", required=True)
    plan.add_argument("--expected-deploy-sha", required=True)
    plan.set_defaults(func=cmd_plan)
    review = sub.add_parser("review")
    review.add_argument("--plan", required=True)
    review.add_argument("--expected-plan-sha", required=True)
    review.add_argument("--expected-deploy-sha", required=True)
    review.add_argument("--output", required=True)
    review.set_defaults(func=cmd_review)
    apply = sub.add_parser("apply")
    apply.add_argument("--plan", required=True)
    apply.add_argument("--expected-plan-sha", required=True)
    apply.add_argument("--review", required=True)
    apply.add_argument("--expected-review-sha", required=True)
    apply.add_argument("--expected-deploy-sha", required=True)
    apply.set_defaults(func=cmd_apply)
    export = sub.add_parser("export-rollback")
    export.add_argument("--output", required=True)
    export.add_argument("--include-managed-realm-roles", action="store_true")
    export.add_argument("clients", nargs="*")
    export.set_defaults(func=cmd_export_rollback)
    prepare = sub.add_parser("prepare-rollback")
    prepare.add_argument("--plan", required=True)
    prepare.add_argument("--output", required=True)
    prepare.set_defaults(func=cmd_prepare_rollback)
    secrets = sub.add_parser("export-secrets")
    secrets.add_argument("--output-dir", required=True)
    secrets.add_argument("clients", nargs="*")
    secrets.set_defaults(func=cmd_export_secrets)
    return value


def main() -> None:
    try:
        args = parser().parse_args()
        args.func(args)
    except EngineError as exc:
        print(f"PROTECTED_IDENTITY_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
