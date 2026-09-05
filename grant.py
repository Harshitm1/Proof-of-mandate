"""The user granting spending authority. Their phone, standing in as a terminal.

Deliberately NOT an MCP tool, for the same reason approve.py isn't: an agent
that could mint its own mandate would have no limits at all. This process holds
the user's private key; the agent never sees it.

    python grant.py
"""
import json, sys, time, uuid

from core import IntentMandate, Envelope
from mcp_server import (MANDATE_FILE, MERCHANT_ID, USER_ID, USER_KEY, AGENT_ID,
                        _rs)


def rupees(prompt: str, default: int) -> int:
    """Read rupees, store paise. Money is integer paise everywhere below this."""
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip() or str(default)
        try:
            paise = round(float(raw) * 100)
        except ValueError:
            print("     Numbers only.")
            continue
        if paise <= 0:
            print("     Must be positive.")
            continue
        return int(paise)


def count(prompt: str, default: int) -> int:
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip() or str(default)
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
        print("     Whole numbers above zero only.")


def main() -> int:
    print("\nGrant spending authority to your agent.")
    print("Press Enter to accept each default.\n")

    budget = rupees("Total budget (Rs)", 2000)
    per_txn = rupees("Most it may spend at once (Rs)", 1500)
    countersign = rupees("Ask me before anything above (Rs)", 1000)
    merchant = input(f"  Merchant, or * for any [{MERCHANT_ID}]: ").strip() or MERCHANT_ID
    uses = count("How many purchases", 5)
    days = count("Valid for how many days", 30)
    constraints = (input('  In your own words ["groceries only"]: ').strip()
                   or "groceries only")

    # These are the user's own limits, so contradictions are worth catching here
    # rather than surfacing later as a gate denial the user cannot explain.
    if per_txn > budget:
        print(f"\n  Per-purchase limit is above the total budget. "
              f"Capping it at {_rs(budget)}.")
        per_txn = budget
    if countersign > per_txn:
        print(f"\n  Approval threshold is above the per-purchase limit, so nothing "
              f"would ever reach you. Lowering it to {_rs(per_txn)}.")
        countersign = per_txn

    mandate = IntentMandate(
        mandate_id="INT-" + uuid.uuid4().hex[:8].upper(),
        user_id=USER_ID,
        agent_id=AGENT_ID,
        merchant_id=merchant,
        budget_paise=budget,
        per_txn_paise=per_txn,
        countersign_above_paise=countersign,
        max_uses=uses,
        expires_at=int(time.time()) + days * 86400,
        constraints=constraints,
        nonce=uuid.uuid4().hex,
    )

    print(f"\n  You are about to sign:\n"
          f"    up to {_rs(budget)} in total, at most {_rs(per_txn)} at a time\n"
          f"    you approve anything above {_rs(countersign)} yourself\n"
          f"    merchant: {merchant}\n"
          f"    {uses} purchases, expires in {days} days\n"
          f'    "{constraints}"')
    if input("\n  Sign this? [y/N] ").strip().lower() != "y":
        print("  Nothing signed. The agent has no authority.")
        return 1

    env = Envelope.wrap(mandate).sign(USER_ID, USER_KEY)
    MANDATE_FILE.write_text(json.dumps(env.to_dict(), indent=2))
    print(f"\n  Signed. {mandate.mandate_id} is now the agent's authority.")
    print("  Revoke it any time by deleting mandate.json.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
