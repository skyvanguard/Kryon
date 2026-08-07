"""F1.4 — ``kryon credential`` subcommand (named, encrypted credentials)."""

from __future__ import annotations

import argparse
import sys


def add_credential_subparser(subparsers) -> argparse.ArgumentParser:
    p = subparsers.add_parser("credential", help="F1.4 — Manage encrypted engagement credentials")
    sub = p.add_subparsers(dest="credential_action", required=True)

    add = sub.add_parser("add", help="Store/overwrite a named credential")
    add.add_argument("--name", required=True)
    add.add_argument("--host", default="")
    add.add_argument("--user", default="")
    add.add_argument("--password", default="")
    add.add_argument("--ssh-key", default="", dest="ssh_key_path")
    add.add_argument("--ssh-port", default="")
    add.add_argument("--notes", default="")

    sub.add_parser("list", help="List stored credential names")

    show = sub.add_parser("show", help="Show a credential (password masked)")
    show.add_argument("--name", required=True)

    rm = sub.add_parser("remove", help="Remove a named credential")
    rm.add_argument("--name", required=True)
    return p


def _mask(value: str) -> str:
    return "********" if value else ""


def run_credential_command(args) -> int:
    from kryon.onboarding.credential_store import CredentialStore, CredentialStoreError

    try:
        return _run_credential_command(args, CredentialStore())
    except CredentialStoreError as e:
        # Undecryptable store — surface a clean message, never a raw traceback,
        # and never silently proceed (which risked destroying stored secrets).
        print(f"FATAL: {e}", file=sys.stderr)
        return 3


def _run_credential_command(args, store) -> int:
    action = args.credential_action

    if action == "add":
        store.add(
            args.name,
            host=args.host,
            user=args.user,
            password=args.password,
            ssh_key_path=args.ssh_key_path,
            ssh_port=args.ssh_port,
            notes=args.notes,
        )
        print(f"stored credential '{args.name}'")
        return 0

    if action == "list":
        names = store.list_names()
        print("\n".join(names) if names else "(no credentials stored)")
        return 0

    if action == "show":
        cred = store.get(args.name)
        if cred is None:
            print(f"no such credential '{args.name}'", file=sys.stderr)
            return 1
        for k, v in cred.items():
            print(f"  {k}: {_mask(v) if k == 'password' else v}")
        return 0

    if action == "remove":
        if store.remove(args.name):
            print(f"removed credential '{args.name}'")
            return 0
        print(f"no such credential '{args.name}'", file=sys.stderr)
        return 1

    print(f"credential: unknown action '{action}'", file=sys.stderr)
    return 2
