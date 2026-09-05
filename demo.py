"""The whole story, end to end, for the pitch video.

    .venv/bin/python demo.py
"""
import json, sys, textwrap, time

import mcp_server as m
import evidence_doc
from mcp_server import load_cart, save_cart, USER_ID, USER_KEY

j = json.loads
W = 74


def head(n, title):
    print(f"\n{'━' * W}\n {n}.  {title}\n{'━' * W}")


def beat(s=0.0):
    time.sleep(s)


def box(lines, mark=""):
    print()
    for l in lines:
        print(f"   {mark}{l}")
    print()


def main(pause=0.0):
    head(1, "THE USER GRANTS AUTHORITY")
    m.ensure_demo_mandate()   # a real user taps the approval page instead
    b = j(m.budget())
    box([f"\"{b['constraints']}\"", "",
         f"budget            {b['budget']}",
         f"per purchase      {b['per_purchase_limit']}",
         f"needs my approval above {b['human_approval_needed_above']}"])
    print("   Signed with the user's private key. The agent holds no key.")
    beat(pause)

    head(2, "A NORMAL PURCHASE")
    q = j(m.quote("ATTA5", 1))
    print(f"   agent: quote({q['item']}) -> {q['total']}")
    r = j(m.pay(q["cart_id"]))
    print(f"   gate : PAID {r['amount']}   razorpay {r['razorpay_order_id']}")
    clean_cart = q["cart_id"]
    beat(pause)

    head(3, "THE MERCHANT'S LISTING IS POISONED")
    rice = [p for p in j(m.browse()) if p["sku"] == "RICE5"][0]
    hidden = rice["description"].split("\n\n", 1)[1]
    print(f"   Listing: {rice['name']}  {rice['price']}")
    box(textwrap.wrap(hidden, 66), mark="│ ")
    print("   Hidden in the product description. The agent reads this as text.")
    beat(pause)

    head(4, "A COMPROMISED AGENT OBEYS IT")
    q2 = j(m.quote("FESTIVE99", 1))
    print(f"   agent: quote(FESTIVE99) -> {q2['total']}")
    print(f"   agent: pay({q2['cart_id']})")
    r2 = j(m.pay(q2["cart_id"]))
    box([f"REFUSED   {r2['code']}",
         f"          {r2['reason']}",
         f"          attempted {r2['attempted']}, moved Rs 0.00"])
    print("   The agent was fooled. No money moved.")
    beat(pause)

    head(5, "A PURCHASE THAT NEEDS THE HUMAN")
    q3 = j(m.quote("GHEE1", 2))
    r3 = j(m.pay(q3["cart_id"]))
    print(f"   agent: pay({q3['cart_id']}) -> {r3['code']}  ({r3['attempted']})")
    print(f"   {r3['how_to_resolve']}")
    env = load_cart(q3["cart_id"]); env.sign(USER_ID, USER_KEY); save_cart(q3["cart_id"], env)
    print("\n   [user signs on their own device, outside the agent's reach]")
    r3b = j(m.pay(q3["cart_id"]))
    print(f"   gate : PAID {r3b['amount']}   razorpay {r3b['razorpay_order_id']}")
    beat(pause)

    head(6, "WEEKS LATER: THE CHARGEBACK")
    pack = j(m.evidence(clean_cart))
    print(f"   customer says: \"I never authorized this.\"\n")
    for k, v in pack["cryptographic_checks"].items():
        print(f"   {'✓' if v else '·'}  {k.replace('_', ' ')}")
    path = evidence_doc.write(pack, "evidence.html")
    print(f"\n   {pack['conclusion']}")
    print(f"\n   Document written to {path}")

    print(f"\n{'━' * W}")
    print(" The agent can be fooled. The gate cannot.")
    print(f"{'━' * W}\n")


if __name__ == "__main__":
    main(pause=float(sys.argv[1]) if len(sys.argv) > 1 else 0.0)
