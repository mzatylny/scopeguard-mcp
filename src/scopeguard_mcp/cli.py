"""Local operator CLI for ScopeGuard configuration and engagement control."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from .config import Settings
from .models import Capability, EngagementMode
from .service import ScopeGuardService


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="scopeguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("doctor", help="show safety settings and audit health")
    subparsers.add_parser("verify-audit", help="verify the tamper-evident audit chain")

    create = subparsers.add_parser(
        "create-engagement", help="create an operator-authorized engagement"
    )
    create.add_argument("--title", required=True)
    create.add_argument("--ticket", required=True)
    create.add_argument("--target", action="append", required=True, dest="targets")
    create.add_argument(
        "--capability",
        action="append",
        required=True,
        dest="capabilities",
        choices=[capability.value for capability in Capability],
    )
    create.add_argument(
        "--mode",
        choices=[mode.value for mode in EngagementMode],
        default=EngagementMode.DRY_RUN.value,
    )
    create.add_argument("--expires-in-minutes", type=int, default=60)

    revoke = subparsers.add_parser("revoke-engagement", help="revoke an engagement")
    revoke.add_argument("engagement_id")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    service = ScopeGuardService(Settings.from_env())
    if args.command == "doctor":
        result = service.health()
    elif args.command == "verify-audit":
        result = service.verify_audit()
    elif args.command == "create-engagement":
        result = service.create_engagement(
            title=args.title,
            ticket=args.ticket,
            targets=args.targets,
            capabilities=args.capabilities,
            mode=args.mode,
            expires_in_minutes=args.expires_in_minutes,
        )
    elif args.command == "revoke-engagement":
        result = service.revoke_engagement(args.engagement_id)
    else:  # pragma: no cover - argparse enforces the command set.
        raise AssertionError(f"unexpected command: {args.command}")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
