"""One runnable check for the gate. Every deny path gets an assertion.

    .venv/bin/python test_core.py
"""
import json, time
from dataclasses import asdict

from core import (IntentMandate, Cart, Envelope, Keyring, AuditLog, Gate,
                  new_keypair, canonical, evidence_pack, _b64)

USER, MERCHANT, ATTACKER = new_keypair(), new_keypair(), new_keypair()


def setup(**intent_over):
    kr = Keyring()
    kr.register("user:priya", USER)
    kr.register("merchant:freshcart", MERCHANT)
    kr.register("merchant:evilmart", ATTACKER)
    audit = AuditLog()
    return kr, audit, Gate(kr, audit)


def make_intent(**over):
    base = dict(mandate_id="INT1", user_id="user:priya", agent_id="agent:claude",
                merchant_id="merchant:freshcart", budget_paise=500000,
                per_txn_paise=200000, countersign_above_paise=150000, max_uses=3,
                expires_at=int(time.time()) + 3600,
                constraints="groceries, under Rs 2000", nonce="n1")
    base.update(over)
    return Envelope.wrap(IntentMandate(**base)).sign("user:priya", USER)


def make_cart(total=100000, merchant="merchant:freshcart", signer=MERCHANT,
              signer_id=None, cart_id="CART1", intent_id="INT1", items=None, **over):
    if items is None:
        items = [{"sku": "ATTA5", "name": "Atta 5kg", "qty": 1, "unit_paise": total}]
    base = dict(cart_id=cart_id, intent_id=intent_id, merchant_id=merchant,
                items=items, total_paise=total,
                expires_at=int(time.time()) + 600, nonce="c1")
    base.update(over)
    return Envelope.wrap(Cart(**base)).sign(signer_id or merchant, signer)


def test_happy_path():
    _, _, gate = setup()
    d = gate.authorize(make_intent(), make_cart(100000))
    assert d.allowed and d.code == "ALLOWED" and d.amount_paise == 100000, d


def test_intent_must_be_signed_by_the_user():
    _, _, gate = setup()
    forged = Envelope.wrap(IntentMandate(
        mandate_id="INT1", user_id="user:priya", agent_id="agent:claude",
        merchant_id="*", budget_paise=10**9, per_txn_paise=10**9,
        countersign_above_paise=10**9, max_uses=99,
        expires_at=int(time.time()) + 3600, constraints="anything", nonce="x")
    ).sign("user:priya", ATTACKER)          # attacker's key, user's claimed id
    d = gate.authorize(forged, make_cart(100000))
    assert not d.allowed and d.code == "INTENT_UNSIGNED", d


def test_injected_agent_cannot_inflate_the_amount():
    """The core claim. A compromised agent edits the cart; the signature dies."""
    _, _, gate = setup()
    cart = make_cart(185000 // 100 * 100)
    body = cart.body()
    body["total_paise"] = 2000000                      # "charge Rs 20,000"
    body["items"][0]["unit_paise"] = 2000000
    tampered = Envelope(_b64(canonical(body)), dict(cart.sigs))  # keep the old sig
    d = gate.authorize(make_intent(), tampered)
    assert not d.allowed and d.code == "CART_UNSIGNED", d


def test_attacker_cannot_sign_a_cart_as_another_merchant():
    _, _, gate = setup()
    cart = make_cart(100000, merchant="merchant:freshcart", signer=ATTACKER)
    d = gate.authorize(make_intent(), cart)
    assert not d.allowed and d.code == "CART_UNSIGNED", d


def test_fake_merchant_is_out_of_scope():
    _, _, gate = setup()
    cart = make_cart(100000, merchant="merchant:evilmart", signer=ATTACKER)
    d = gate.authorize(make_intent(), cart)
    assert not d.allowed and d.code == "MERCHANT_NOT_ALLOWED", d


def test_cart_arithmetic_must_hold():
    _, _, gate = setup()
    items = [{"sku": "A", "name": "A", "qty": 2, "unit_paise": 30000}]   # = 60000
    cart = make_cart(100000, items=items)
    d = gate.authorize(make_intent(), cart)
    assert not d.allowed and d.code == "CART_ARITHMETIC", d


def test_cart_must_cite_this_mandate():
    _, _, gate = setup()
    d = gate.authorize(make_intent(), make_cart(100000, intent_id="SOMEONE_ELSE"))
    assert not d.allowed and d.code == "CART_INTENT_MISMATCH", d


def test_expired_mandate():
    _, _, gate = setup()
    d = gate.authorize(make_intent(expires_at=int(time.time()) - 1), make_cart(100000))
    assert not d.allowed and d.code == "MANDATE_EXPIRED", d


def test_expired_cart():
    _, _, gate = setup()
    d = gate.authorize(make_intent(), make_cart(100000, expires_at=int(time.time()) - 1))
    assert not d.allowed and d.code == "CART_EXPIRED", d


def test_revoked():
    _, _, gate = setup()
    gate.revoke("INT1")
    d = gate.authorize(make_intent(), make_cart(100000))
    assert not d.allowed and d.code == "MANDATE_REVOKED", d


def test_per_txn_cap():
    _, _, gate = setup()
    d = gate.authorize(make_intent(countersign_above_paise=10**9), make_cart(300000))
    assert not d.allowed and d.code == "PER_TXN_CAP", d


def test_budget_and_uses_exhaust():
    _, _, gate = setup()
    intent = make_intent()
    for i in range(3):
        cart = make_cart(140000, cart_id=f"C{i}")
        d = gate.authorize(intent, cart)
        if d.allowed:
            gate.settle(intent, cart)
    d = gate.authorize(intent, make_cart(140000, cart_id="Cfinal"))
    assert not d.allowed and d.code in ("BUDGET_EXCEEDED", "USES_EXHAUSTED"), d


def test_replay():
    _, _, gate = setup()
    intent, cart = make_intent(), make_cart(100000)
    assert gate.authorize(intent, cart).allowed
    gate.settle(intent, cart)
    d = gate.authorize(intent, cart)
    assert not d.allowed and d.code == "REPLAY", d


def test_countersign_required_above_threshold():
    _, _, gate = setup()
    d = gate.authorize(make_intent(), make_cart(160000))
    assert not d.allowed and d.code == "COUNTERSIGN_REQUIRED" and d.needs_countersign, d


def test_countersigned_cart_passes():
    _, _, gate = setup()
    cart = make_cart(160000).sign("user:priya", USER)   # the human actually approved
    d = gate.authorize(make_intent(), cart)
    assert d.allowed, d


def test_agent_cannot_countersign_for_the_user():
    _, _, gate = setup()
    cart = make_cart(160000).sign("user:priya", ATTACKER)
    d = gate.authorize(make_intent(), cart)
    assert not d.allowed and d.code == "COUNTERSIGN_REQUIRED", d


def test_audit_chain_detects_tampering():
    _, audit, gate = setup()
    gate.authorize(make_intent(), make_cart(100000))
    assert audit.verify()
    audit.entries[0]["payload"]["decision"]["allowed"] = False
    assert not audit.verify(), "tampering must break the chain"


def test_evidence_pack_defends_a_real_purchase():
    _, audit, gate = setup()
    intent, cart = make_intent(), make_cart(100000)
    assert gate.authorize(intent, cart).allowed
    gate.settle(intent, cart)
    ev = evidence_pack(gate, audit, "CART1")
    assert ev["found"] and ev["settled"]
    assert ev["authorized_by"] == "user:priya"
    assert ev["charged_paise"] == 100000
    assert ev["cryptographic_checks"]["user_signed_the_mandate"]
    assert ev["cryptographic_checks"]["merchant_signed_the_cart"]
    assert ev["cryptographic_checks"]["audit_chain_intact"]
    assert ev["conclusion"].startswith("Authorized")
    assert ev["user_stated_constraints"] == "groceries, under Rs 2000"


def test_evidence_pack_is_honest_about_an_unknown_cart():
    _, audit, gate = setup()
    ev = evidence_pack(gate, audit, "NEVER_HAPPENED")
    assert not ev["found"] and "cannot be defended" in ev["conclusion"], ev


def test_every_deny_is_explained():
    """A refusal nobody can read is not an explanation."""
    _, _, gate = setup()
    for cart in [make_cart(300000), make_cart(100000, intent_id="X"),
                 make_cart(100000, merchant="merchant:evilmart", signer=ATTACKER)]:
        d = gate.authorize(make_intent(countersign_above_paise=10**9), cart)
        assert not d.allowed and d.code and len(d.reason) > 10, d


def test_evidence_pack_is_json_serialisable():
    """It gets emailed to an acquirer, so it has to survive json.dumps."""
    _, audit, gate = setup()
    intent, cart = make_intent(), make_cart(100000)
    gate.authorize(intent, cart)
    gate.settle(intent, cart)
    assert len(json.dumps(evidence_pack(gate, audit, "CART1"))) > 200


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} passed")
