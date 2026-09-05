"""Proof-of-Mandate as an MCP server.

Add this to Claude and it can shop -- but every rupee it spends passes the gate.
The tool surface is deliberately narrow: the agent can request a quote and pay a
quote, and it has no tool that lets it name an amount. There is nothing for a
prompt injection to overwrite.

Human approval is NOT exposed here on purpose. It lives in approve.py, out of
the agent's reach, standing in for a tap on the user's phone.
"""
import json, os, time, uuid
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from core import (IntentMandate, Cart, Envelope, Keyring, AuditLog, Gate,
                  new_keypair, public_pem, evidence_pack)
from cryptography.hazmat.primitives import serialization

HERE = Path(__file__).parent
ENV = HERE / ".env"
if ENV.exists():                       # keys never live in the repo
    for _line in ENV.read_text().splitlines():
        _k, _, _v = _line.strip().partition("=")
        if _k and not _k.startswith("#"):
            os.environ.setdefault(_k, _v)
KEYS = HERE / "demo_keys.json"
CARTS_FILE = HERE / "demo_carts.json"   # shared with approve.py, which is a separate process
MANDATE_FILE = HERE / "mandate.json"    # written by grant.py, also a separate process


def _rail():
    """Razorpay test mode, or None if no keys are configured.

    The gate's decision does not depend on this -- authorization and execution
    are separate concerns, which is the whole point of the architecture.
    """
    kid, secret = os.environ.get("RAZORPAY_KEY_ID"), os.environ.get("RAZORPAY_KEY_SECRET")
    if not (kid and secret):
        return None
    import razorpay
    return razorpay.Client(auth=(kid, secret))


RAIL = _rail()

USER_ID, MERCHANT_ID, AGENT_ID = "user:priya", "merchant:freshcart", "agent:claude"
GATE_ID = "gate:pom"

# Stands in for the merchant's own product API. The gate never sees any of this:
# a cart is an opaque line-item list plus a signed total, so the number of
# products a merchant sells is invisible to it. Swap this for a real catalogue
# call and nothing in core.py changes.
#
# RICE5 carries a live prompt injection. That is deliberate -- it is the demo.
CATALOG = json.loads((HERE / "catalog.json").read_text())


def _load_keys():
    """Generate on first run, reuse after -- approve.py needs the same identities."""
    load = lambda p: serialization.load_pem_private_key(p.encode(), password=None)
    dump = lambda k: k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    d = json.loads(KEYS.read_text()) if KEYS.exists() else {}
    # agent and gate keys were added later; top up an existing file rather than
    # regenerating, so carts already saved by approve.py stay verifiable.
    if not all(k in d for k in ("user", "merchant", "agent", "gate")):
        for name in ("user", "merchant", "agent", "gate"):
            d.setdefault(name, dump(new_keypair()))
        KEYS.write_text(json.dumps(d))
    return (load(d["user"]), load(d["merchant"]),
            load(d["agent"]), load(d["gate"]))


USER_KEY, MERCHANT_KEY, AGENT_KEY, GATE_KEY = _load_keys()

keyring = Keyring()
keyring.register(USER_ID, USER_KEY)
keyring.register(MERCHANT_ID, MERCHANT_KEY)
keyring.register(AGENT_ID, AGENT_KEY)
keyring.register(GATE_ID, GATE_KEY)
audit = AuditLog(GATE_ID, GATE_KEY)
gate = Gate(keyring, audit)

def _demo_mandate() -> IntentMandate:
    """What a first run gets, so the demo works on a fresh clone. Replace it by
    running grant.py, which is how a real user would set their own limits."""
    return IntentMandate(
        mandate_id="INT-DEMO",
        user_id=USER_ID,
        agent_id=AGENT_ID,
        merchant_id=MERCHANT_ID,
        budget_paise=200000,             # Rs 2,000 total
        per_txn_paise=150000,            # Rs 1,500 per purchase
        countersign_above_paise=100000,  # above Rs 1,000 the human must approve
        max_uses=5,
        expires_at=int(time.time()) + 24 * 3600,
        constraints="groceries only, under Rs 2000 total, FreshCart only",
        nonce=uuid.uuid4().hex,
    )


def load_mandate() -> Envelope:
    """The user's signed spending authority.

    It lives on disk because grant.py writes it from a separate process holding
    the user's key. There is deliberately no MCP tool that creates one: an agent
    able to mint its own authority would have no limits at all.
    """
    if MANDATE_FILE.exists():
        return Envelope.from_dict(json.loads(MANDATE_FILE.read_text()))
    env = Envelope.wrap(_demo_mandate()).sign(USER_ID, USER_KEY)
    MANDATE_FILE.write_text(json.dumps(env.to_dict(), indent=2))
    return env


INTENT = load_mandate()

def save_cart(cart_id: str, env: Envelope):
    d = json.loads(CARTS_FILE.read_text()) if CARTS_FILE.exists() else {}
    d[cart_id] = env.to_dict()
    CARTS_FILE.write_text(json.dumps(d, indent=2))


def load_cart(cart_id: str):
    """Carts live on disk because approve.py is a different process -- the user's
    device, in the demo's fiction. It signs there; the gate reads the result here."""
    if not CARTS_FILE.exists():
        return None
    d = json.loads(CARTS_FILE.read_text())
    return Envelope.from_dict(d[cart_id]) if cart_id in d else None


mcp = MCPServer("proof-of-mandate")


def _rs(paise: int) -> str:
    return f"Rs {paise / 100:,.2f}"


@mcp.tool()
def browse() -> str:
    """List what this merchant sells. Returns SKU, name and price."""
    return json.dumps([
        {"sku": k, "name": v["name"], "price": _rs(v["paise"]), "description": v["desc"]}
        for k, v in CATALOG.items()
    ], indent=2)


@mcp.tool()
def budget() -> str:
    """How much spending authority is left under the current mandate."""
    st = gate.state.get(load_mandate().body()["mandate_id"])
    spent = st.spent_paise if st else 0
    m = load_mandate().body()
    return json.dumps({
        "constraints": m["constraints"],
        "budget": _rs(m["budget_paise"]),
        "spent": _rs(spent),
        "remaining": _rs(m["budget_paise"] - spent),
        "per_purchase_limit": _rs(m["per_txn_paise"]),
        "human_approval_needed_above": _rs(m["countersign_above_paise"]),
    }, indent=2)


@mcp.tool()
def quote(sku: str, qty: int = 1) -> str:
    """Ask the merchant to price an item. Returns a cart_id to pay with.

    The price is set and signed by the merchant. You cannot alter it.
    """
    if sku not in CATALOG:
        return json.dumps({"error": f"unknown sku {sku}", "available": list(CATALOG)})
    if qty < 1:
        return json.dumps({"error": "qty must be at least 1"})
    item = CATALOG[sku]
    cart_id = f"CART-{uuid.uuid4().hex[:8].upper()}"
    cart = Cart(
        cart_id=cart_id,
        intent_id=load_mandate().body()["mandate_id"],
        merchant_id=MERCHANT_ID,
        items=[{"sku": sku, "name": item["name"], "qty": qty, "unit_paise": item["paise"]}],
        total_paise=item["paise"] * qty,
        expires_at=int(time.time()) + 600,
        nonce=uuid.uuid4().hex,
    )
    save_cart(cart_id, Envelope.wrap(cart).sign(MERCHANT_ID, MERCHANT_KEY)
                                          .sign(AGENT_ID, AGENT_KEY))
    return json.dumps({
        "cart_id": cart_id,
        "item": item["name"],
        "qty": qty,
        "total": _rs(cart.total_paise),
        "note": "Merchant-signed. Call pay(cart_id) to complete.",
    }, indent=2)


@mcp.tool()
def pay(cart_id: str) -> str:
    """Pay a quoted cart. The gate decides; you cannot override it.

    There is no amount parameter by design -- the amount comes from the
    merchant's signed cart.
    """
    env = load_cart(cart_id)
    if env is None:
        return json.dumps({"paid": False, "code": "UNKNOWN_CART",
                           "reason": f"no quote called {cart_id}"})
    intent = load_mandate()
    d = gate.authorize(intent, env)
    if d.allowed:
        rail_ref = ""
        if RAIL is not None:
            try:
                order = RAIL.order.create({
                    "amount": d.amount_paise, "currency": "INR",
                    "receipt": cart_id[:40],
                    "notes": {"mandate_id": d.mandate_id, "gate_code": d.code,
                              "agent_id": AGENT_ID,
                              "chain_head": audit.entries[-1]["hash"][:32]},
                })
                rail_ref = order["id"]
            except Exception as e:
                # The gate said yes and the rail said no. Consume nothing: the
                # budget is untouched and the cart stays payable.
                gate.rail_failed(cart_id, d.mandate_id, f"{type(e).__name__}: {e}"[:200])
                return json.dumps({
                    "paid": False, "code": "RAIL_UNAVAILABLE",
                    "reason": "Authorized, but the payment provider could not be "
                              "reached. No budget was consumed -- retry is safe.",
                    "attempted": _rs(d.amount_paise)}, indent=2)
        gate.settle(intent, env, rail_ref=rail_ref)
        return json.dumps({"paid": True, "amount": _rs(d.amount_paise),
                           "cart_id": cart_id, "razorpay_order_id": rail_ref or None,
                           "reason": d.reason}, indent=2)
    out = {"paid": False, "code": d.code, "reason": d.reason,
           "attempted": _rs(d.amount_paise)}
    if d.needs_countersign:
        out["how_to_resolve"] = (
            f"The user must approve this themselves. Ask them to run: "
            f"python approve.py {cart_id}")
    return json.dumps(out, indent=2)


@mcp.tool()
def evidence(cart_id: str) -> str:
    """Produce the dispute-evidence pack for a completed purchase."""
    return json.dumps(evidence_pack(gate, audit, cart_id), indent=2, default=str)


@mcp.tool()
def evidence_document(cart_id: str) -> str:
    """Render the evidence pack as the document a merchant sends an acquirer.

    Writes an HTML representment and returns its path.
    """
    import evidence_doc
    pack = evidence_pack(gate, audit, cart_id)
    path = evidence_doc.write(pack, str(HERE / f"evidence-{cart_id}.html"))
    return json.dumps({"written": path, "verdict": pack.get("conclusion", "")[:80]})


if __name__ == "__main__":
    mcp.run()
