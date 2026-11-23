"""Command-line interface for the AgentGrid SDK."""
from __future__ import annotations

import argparse
import getpass
import json
from typing import Optional

from .client import (
    AgentGrid,
    AgentGridError,
    clear_pending_client,
    load_api_key,
    load_pending_client,
    save_api_key,
    save_pending_client,
)


def _client(args: argparse.Namespace) -> AgentGrid:
    return AgentGrid(base_url=args.base_url)


def _require_key(args: argparse.Namespace, *, prompt: bool = True) -> str:
    key = load_api_key()
    if key:
        return key
    if not prompt:
        raise AgentGridError(0, "No API key. Run `agrid register` first.")
    entered = getpass.getpass("AgentGrid API key: ").strip()
    if not entered:
        raise AgentGridError(0, "No API key entered.")
    path = save_api_key(entered)
    print("Saved key locally to " + str(path))
    return entered


def _next_steps(client: AgentGrid) -> None:
    print()
    print("Next - three steps to your first signed handoff:")
    print("  1. agrid quickstart")
    print("     Two agents, a verified card, a signed handoff, and its receipt.")
    print("  2. agrid card <agent_id>")
    print("     Offline signature check for any public card (ID from step 1).")
    print("  3. agrid receipts <agent_id>")
    print("     Read the immutable receipts (worker ID from step 1).")
    print()
    print("Guide: " + client.base_url + "/guide")
    print("API:   " + client.base_url + "/docs")


def cmd_register(args: argparse.Namespace) -> int:
    client = _client(args)
    email = (args.email or "").strip()
    if not email:
        try:
            email = input("AgentGrid email (required): ").strip()
        except EOFError as exc:
            raise AgentGridError(0, "A real email is required.") from exc
    if not email:
        raise AgentGridError(0, "A real email is required.")

    result = client.register(email=email, client_id=args.client_id or "")
    client_id = str(result["client_id"])
    pending_path = save_pending_client(client_id)
    print("Registration created: " + client_id + " (tier: " + str(result.get("tier", "free")) + ")")
    print("A 6-digit code was sent to that address. No API key exists yet.")
    print("Check your inbox, then run: agrid verify <code>")
    print("Verification runs your first signed handoff automatically.")
    print("No code after a minute? Run: agrid resend")
    print("Pending client ID saved at " + str(pending_path) + " (verify needs no --client-id).")
    print()
    print("Guide: " + client.base_url + "/guide")
    print("API:   " + client.base_url + "/docs")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    client = _client(args)
    client_id = (args.client_id or "").strip() or load_pending_client()
    if not client_id:
        raise AgentGridError(
            0,
            "No pending registration found. Run `agrid register` or pass --client-id.",
        )
    result = client.verify_email(client_id, args.code.strip())
    path = save_api_key(result["api_key"])
    clear_pending_client()
    print("Email verified. API key stored at " + str(path) + " (not displayed).")
    print("Save a backup of that key now; the service shows it only once.")

    if getattr(args, "no_quickstart", False):
        _next_steps(client)
        return 0

    print("\nRunning your first signed handoff now...")
    try:
        _print_quickstart_result(client, client.quickstart())
    except Exception as exc:
        # A failed demo must never turn a successful verification into a failure.
        detail = getattr(exc, "detail", str(exc))
        print("Quickstart could not run automatically: " + str(detail))
        print("Retry any time with: agrid quickstart")
        _next_steps(client)
    return 0


def cmd_resend(args: argparse.Namespace) -> int:
    client = _client(args)
    client_id = (args.client_id or "").strip() or load_pending_client()
    if not client_id:
        raise AgentGridError(
            0,
            "No pending registration found. Run `agrid register` or pass --client-id.",
        )
    client.resend_verification(client_id)
    print("A fresh 6-digit code was sent. Run `agrid verify <code>` after it arrives.")
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    key = args.api_key or getpass.getpass("AgentGrid API key: ").strip()
    if not key.startswith("agk_"):
        raise AgentGridError(0, "That does not look like an AgentGrid API key (expected agk_...).")
    path = save_api_key(key)
    print("Logged in. Key stored at " + str(path) + " (not displayed).")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    client = _client(args)
    health = client.health()
    print("Service: " + str(health.get("status")) + " / database: " + str(health.get("database")))
    _require_key(args)
    me = client.me()
    print("Client: " + str(me.get("client_id")) + " / tier: " + str(me.get("tier")))
    print("Cycle: " + str(me.get("cycle_start")) + " -> " + str(me.get("cycle_end")))
    return 0


def _print_quickstart_result(client: AgentGrid, result: dict) -> None:
    from_agent = result["from_agent"]
    to_agent = result["to_agent"]
    verification = result["verification"]
    print("AgentGrid quickstart -> " + client.base_url + "\n")
    print(f"1. Registered agents: {from_agent.agent_id} -> {to_agent.agent_id}")
    print(
        f"2. Card verified online={verification['online']} "
        f"and offline={verification.get('offline', False)}"
    )
    print(f"3. Signed handoff accepted: {result['receipt']['handoff_id']}")
    print(f"4. Receipts for worker: {result['receipt_count']}")
    print("\nDone. Open the card at " + from_agent.card_url)
    print("Next: agrid card " + from_agent.agent_id)
    print("      agrid receipts " + to_agent.agent_id)


def cmd_quickstart(args: argparse.Namespace) -> int:
    _require_key(args)
    client = _client(args)
    _print_quickstart_result(client, client.quickstart())
    return 0


def cmd_statement(args: argparse.Namespace) -> int:
    _require_key(args)
    statement = _client(args).statement(args.cycle_start)
    print("Invoice: " + str(statement.get("invoice_id")))
    print("Cycle: " + str(statement.get("cycle_start")) + " -> " + str(statement.get("cycle_end")))
    print("Tier: " + str(statement.get("tier")) + " / status: " + str(statement.get("payment_status")))
    print("Total due (USD): " + str(statement.get("total_due_usd")))
    print("Hard caps: " + str(statement.get("hard_caps")))
    return 0


def cmd_card(args: argparse.Namespace) -> int:
    client = _client(args)
    card = client.card(args.agent_id)
    verification = client.verify_card(args.agent_id)
    print("Agent: " + str(card.get("name")) + " (" + str(card.get("agent_id")) + ")")
    print("Capabilities: " + ", ".join(card.get("capabilities", [])))
    print("Card URL: " + client.base_url + "/a/" + args.agent_id)
    print(
        "Signature: online="
        + str(verification.get("online"))
        + " offline="
        + str(verification.get("offline"))
    )
    return 0


def cmd_receipts(args: argparse.Namespace) -> int:
    _require_key(args)
    data = _client(args).receipts(args.agent_id)
    items = data.get("receipts", [])
    print("Agent: " + str(args.agent_id) + " / receipts: " + str(data.get("count", len(items))))
    for receipt in items:
        print(
            "- "
            + str(receipt["handoff_id"])
            + "  "
            + str(receipt["from_agent_id"])
            + " -> "
            + str(receipt["to_agent_id"])
        )
        print("  task_hash: " + str(receipt["task_hash"]))
        print("  scope: " + json.dumps(receipt.get("scope", {}), sort_keys=True))
        print("  created: " + str(receipt["created_at"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agrid", description="AgentGrid SDK command line")
    parser.add_argument(
        "--base-url",
        default=None,
        help="AgentGrid base URL (default: AGENTGRID_BASE_URL or production URL)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="create a free client after email verification")
    register.add_argument(
        "--email", default=None, help="real email for the 6-digit human-verification code"
    )
    register.add_argument("--client-id", default=None, help=argparse.SUPPRESS)
    register.set_defaults(func=cmd_register)

    verify = sub.add_parser("verify", help="confirm the emailed code and save your API key")
    verify.add_argument("code", help="6-digit code from the AgentGrid verification email")
    verify.add_argument(
        "--client-id", default=None, help="override the pending client ID from `agrid register`"
    )
    verify.add_argument(
        "--no-quickstart",
        action="store_true",
        help="skip the automatic first handoff after verification",
    )
    verify.set_defaults(func=cmd_verify)

    resend = sub.add_parser("resend", help="send a fresh verification code")
    resend.add_argument(
        "--client-id", default=None, help="override the pending client ID from `agrid register`"
    )
    resend.set_defaults(func=cmd_resend)

    login = sub.add_parser("login", help="store an API key locally")
    login.add_argument("--api-key", default=None, help="API key (prompted if omitted)")
    login.set_defaults(func=cmd_login)

    sub.add_parser("doctor", help="check service and account status").set_defaults(func=cmd_doctor)
    sub.add_parser("quickstart", help="run a real signed handoff").set_defaults(func=cmd_quickstart)

    statement = sub.add_parser("statement", help="show the current billing statement")
    statement.add_argument("--cycle-start", default=None, help="optional YYYY-MM-DD cycle start")
    statement.set_defaults(func=cmd_statement)

    card = sub.add_parser("card", help="verify a public Agent Card")
    card.add_argument("agent_id")
    card.set_defaults(func=cmd_card)

    receipts = sub.add_parser("receipts", help="read immutable receipts for an agent")
    receipts.add_argument("agent_id")
    receipts.set_defaults(func=cmd_receipts)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AgentGridError as exc:
        print("ERROR: " + exc.detail)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
