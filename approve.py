"""The user's phone, standing in as a terminal command.

Deliberately NOT an MCP tool: if the agent could approve its own purchases the
approval would be worth nothing. A prompt injection can ask for approval; it
cannot grant it, because the user's private key is not in the agent's reach.

    python approve.py CART-1A2B3C4D
"""
import sys

from mcp_server import load_cart, save_cart, USER_ID, USER_KEY, _rs


def main(cart_id: str) -> int:
    env = load_cart(cart_id)
    if env is None:
        print(f"No cart {cart_id}. Ask the agent to quote first.")
        return 1

    cart = env.body()
    # Every line, never just the first. The user signs the whole payload, so
    # showing a summary that omits items is a consent-surface attack waiting to
    # happen: a hidden line item would be paid for but never displayed.
    print("Approve this purchase?")
    for line in cart["items"]:
        print(f"  {line['name']} x{line['qty']}"
              f"  {_rs(line['unit_paise'] * line['qty'])}")
    print(f"  ---\n  {_rs(cart['total_paise'])} from {cart['merchant_id']}")
    if input("  [y/N] ").strip().lower() != "y":
        print("Declined. Nothing signed.")
        return 1

    env.sign(USER_ID, USER_KEY)
    save_cart(cart_id, env)
    print(f"Signed. {cart_id} now carries your approval.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
