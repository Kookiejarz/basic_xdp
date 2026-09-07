from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from auto_xdp.admin.runtime import (
    RuntimeContext,
    collect_backend_report,
    deactivate_runtime,
    render_backend_json,
    render_backend_text,
)


def _cmd_backend(args: argparse.Namespace) -> int:
    report = collect_backend_report(
        RuntimeContext(
            env_config=Path(args.env_config),
            bpf_pin_dir=Path(args.bpf_pin_dir),
            run_state_dir=Path(args.run_state_dir),
            nft_family=args.nft_family,
            nft_table=args.nft_table,
            interface=args.interface or "",
        )
    )
    if args.json:
        print(render_backend_json(report))
    else:
        print(render_backend_text(report))
    return 0


def _cmd_deactivate(args: argparse.Namespace) -> int:
    messages = deactivate_runtime(
        RuntimeContext(
            env_config=Path(args.env_config),
            bpf_pin_dir=Path(args.bpf_pin_dir),
            run_state_dir=Path(args.run_state_dir),
            nft_family=args.nft_family,
            nft_table=args.nft_table,
            interface=args.interface or "",
        )
    )
    print("\n".join(messages) if messages else "Auto XDP data plane is already inactive")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m auto_xdp.admin.main")
    parser.add_argument("--env-config", default="/etc/auto_xdp/auto_xdp.env")
    parser.add_argument("--bpf-pin-dir", default="/sys/fs/bpf/xdp_fw")
    parser.add_argument("--run-state-dir", default="/run/auto_xdp")
    parser.add_argument("--nft-family", default="inet")
    parser.add_argument("--nft-table", default="auto_xdp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    backend = subparsers.add_parser("backend")
    backend.add_argument("--interface")
    backend.add_argument("--json", action="store_true")
    backend.set_defaults(func=_cmd_backend)
    deactivate = subparsers.add_parser("deactivate")
    deactivate.add_argument("--interface")
    deactivate.set_defaults(func=_cmd_deactivate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "deactivate" and os.geteuid() != 0:
        print("deactivation requires root; try re-running with sudo", file=sys.stderr)
        return 77
    try:
        return int(args.func(args))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Permission denied: {exc}", file=sys.stderr)
        print("This command needs root; try re-running with sudo.", file=sys.stderr)
        return 77


if __name__ == "__main__":
    sys.exit(main())
