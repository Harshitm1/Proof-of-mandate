"""Proof-of-Mandate: bounded money movement and dispute evidence for AI buyer agents.

Design premise: the buyer agent is assumed hostile or already compromised. It
never moves money and it never names an amount. It can only present two signed
documents to the gate:

    IntentMandate  - signed by the USER. What the agent is allowed to spend.
    Cart           - signed by the MERCHANT. What is actually being charged.

Because the amount lives inside a merchant-signed cart, prompt injection has no
number to tamper with: forging one requires the merchant's private key. Above
the user's threshold the cart must also carry the USER's counter-signature --
that is human-in-the-loop as a cryptographic requirement rather than a UI popup.
(This is AP2's human-present / human-not-present split.)

Money is integer paise everywhere -- no floats on a money path.
"""
import base64, hashlib, json, time
from dataclasses import dataclass, asdict, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class MandateError(Exception):
    """A document could not be trusted. Never downgrade this to a warning."""


# --------------------------------------------------------------------------
# Signing. ECDSA P-256 / SHA-256, per the AP2 mandate spec.
#
# Public-key, not HMAC, and that distinction is load-bearing: with a shared
# secret the merchant could have forged the user's authorization, so the audit
# trail would prove nothing in a dispute.
# --------------------------------------------------------------------------

def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj: dict) -> bytes:
    """One byte-representation per document, so signatures are reproducible."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def new_keypair():
    return ec.generate_private_key(ec.SECP256R1())


def public_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public(pem: str):
    return serialization.load_pem_public_key(pem.encode())


class Keyring:
    """signer_id -> public key.

    ponytail: an in-process dict. A real deployment resolves signer_id against a
    registry -- which is precisely what NPCI's Unified Agent Protocol is being
    built to be. Swap the lookup, keep the interface.
    """

    def __init__(self):
        self._keys = {}

    def register(self, signer_id: str, private_or_pem):
        pem = private_or_pem if isinstance(private_or_pem, str) else public_pem(private_or_pem)
        self._keys[signer_id] = load_public(pem)

    def verify(self, signer_id: str, payload: bytes, sig_b64: str) -> bool:
        key = self._keys.get(signer_id)
        if key is None:
            return False
        try:
            key.verify(_unb64(sig_b64), payload, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


@dataclass
class Envelope:
    """A signed document. Several parties may sign the same payload."""
    payload_b64: str
    sigs: dict = field(default_factory=dict)   # signer_id -> signature

    @property
    def payload(self) -> bytes:
        return _unb64(self.payload_b64)

    def body(self) -> dict:
        return json.loads(self.payload)

    def sign(self, signer_id: str, private_key) -> "Envelope":
        sig = private_key.sign(self.payload, ec.ECDSA(hashes.SHA256()))
        self.sigs[signer_id] = _b64(sig)
        return self

    @classmethod
    def wrap(cls, obj) -> "Envelope":
        return cls(_b64(canonical(asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj)))

    def to_dict(self) -> dict:
        return {"payload_b64": self.payload_b64, "sigs": dict(self.sigs)}

    @classmethod
    def from_dict(cls, d: dict) -> "Envelope":
        return cls(d["payload_b64"], dict(d.get("sigs", {})))


# --------------------------------------------------------------------------
# The two documents
# --------------------------------------------------------------------------

@dataclass
class IntentMandate:
    """Signed by the user. The boundaries the agent operates inside."""
    mandate_id: str
    user_id: str
    agent_id: str
    merchant_id: str             # "*" allows any registered merchant
    budget_paise: int            # total authority across all uses
    per_txn_paise: int           # ceiling on any single cart
    countersign_above_paise: int # above this, the cart needs the user's signature
    max_uses: int
    expires_at: int              # unix seconds
    constraints: str             # the user's own words, carried into evidence
    nonce: str


@dataclass
class Cart:
    """Signed by the merchant. The merchant's binding price attestation."""
    cart_id: str
    intent_id: str
    merchant_id: str
    items: list                  # [{"sku","name","qty","unit_paise"}]
    total_paise: int
    expires_at: int
    nonce: str


# --------------------------------------------------------------------------
# Audit: append-only, hash-chained. Editing any past entry breaks the chain.
# --------------------------------------------------------------------------

class AuditLog:
    def __init__(self):
        self.entries = []

    def append(self, event: str, payload: dict) -> dict:
        entry = {
            "seq": len(self.entries),
            "ts": time.time(),
            "event": event,
            "payload": payload,
            "prev_hash": self.entries[-1]["hash"] if self.entries else "genesis",
        }
        entry["hash"] = hashlib.sha256(canonical(entry)).hexdigest()
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = "genesis"
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if body["prev_hash"] != prev or hashlib.sha256(canonical(body)).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True

    def for_cart(self, cart_id: str) -> list:
        return [e for e in self.entries if e["payload"].get("cart_id") == cart_id]


# --------------------------------------------------------------------------
# Gate: the only path to money. Deterministic, refuses by default.
# --------------------------------------------------------------------------

@dataclass
class Decision:
    allowed: bool
    code: str
    reason: str
    amount_paise: int = 0
    cart_id: str = ""
    mandate_id: str = ""
    needs_countersign: bool = False


@dataclass
class MandateState:
    spent_paise: int = 0
    uses: int = 0
    revoked: bool = False
    settled_carts: set = field(default_factory=set)


class Gate:
    # ponytail: in-memory state, single process. Redis if this ever needs to
    # survive a restart or run on more than one worker.
    def __init__(self, keyring: Keyring, audit: AuditLog, now=time.time):
        self.keyring = keyring
        self.audit = audit
        self.now = now
        self.state = {}

    def revoke(self, mandate_id: str):
        self.state.setdefault(mandate_id, MandateState()).revoked = True
        self.audit.append("mandate.revoked", {"mandate_id": mandate_id})

    def authorize(self, intent_env: Envelope, cart_env: Envelope) -> Decision:
        d = self._evaluate(intent_env, cart_env)
        self.audit.append("gate.decision", {
            "cart_id": d.cart_id,
            "mandate_id": d.mandate_id,
            "decision": asdict(d),
            "intent": intent_env.to_dict(),
            "cart": cart_env.to_dict(),
        })
        return d

    def _evaluate(self, intent_env: Envelope, cart_env: Envelope) -> Decision:
        # 1. The user really signed this mandate.
        try:
            intent = IntentMandate(**intent_env.body())
        except Exception:
            return Decision(False, "INTENT_MALFORMED", "intent mandate could not be parsed")
        if not self.keyring.verify(intent.user_id, intent_env.payload,
                                   intent_env.sigs.get(intent.user_id, "")):
            return Decision(False, "INTENT_UNSIGNED",
                            f"no valid signature from user {intent.user_id}")

        deny = lambda c, why: Decision(False, c, why, mandate_id=intent.mandate_id)

        # 2. The merchant really signed this cart. The amount lives here, so a
        #    prompt-injected agent has no number it can alter.
        try:
            cart = Cart(**cart_env.body())
        except Exception:
            return deny("CART_MALFORMED", "cart could not be parsed")
        if not self.keyring.verify(cart.merchant_id, cart_env.payload,
                                   cart_env.sigs.get(cart.merchant_id, "")):
            return deny("CART_UNSIGNED",
                        f"no valid signature from merchant {cart.merchant_id}")

        d = lambda c, why: Decision(False, c, why, cart.total_paise, cart.cart_id,
                                    intent.mandate_id)

        # 3. The cart's own arithmetic has to hold.
        computed = sum(i["qty"] * i["unit_paise"] for i in cart.items)
        if computed != cart.total_paise:
            return d("CART_ARITHMETIC", f"items sum to {computed}, cart claims {cart.total_paise}")
        if cart.total_paise <= 0:
            return d("AMOUNT_INVALID", "cart total must be positive")

        # 4. The cart has to belong to this mandate.
        if cart.intent_id != intent.mandate_id:
            return d("CART_INTENT_MISMATCH",
                     f"cart cites intent {cart.intent_id}, presented mandate is {intent.mandate_id}")

        st = self.state.setdefault(intent.mandate_id, MandateState())
        now = self.now()

        if st.revoked:
            return d("MANDATE_REVOKED", "mandate was revoked")
        if now > intent.expires_at:
            return d("MANDATE_EXPIRED", f"mandate expired at {intent.expires_at}")
        if now > cart.expires_at:
            return d("CART_EXPIRED", f"cart quote expired at {cart.expires_at}")
        if cart.cart_id in st.settled_carts:
            return d("REPLAY", f"cart {cart.cart_id} was already settled")
        if st.uses >= intent.max_uses:
            return d("USES_EXHAUSTED", f"mandate allows {intent.max_uses} uses, all consumed")
        if intent.merchant_id != "*" and cart.merchant_id != intent.merchant_id:
            return d("MERCHANT_NOT_ALLOWED",
                     f"mandate is scoped to {intent.merchant_id}, cart is from {cart.merchant_id}")
        if cart.total_paise > intent.per_txn_paise:
            return d("PER_TXN_CAP",
                     f"{cart.total_paise} exceeds per-transaction cap {intent.per_txn_paise}")
        if st.spent_paise + cart.total_paise > intent.budget_paise:
            return d("BUDGET_EXCEEDED",
                     f"{st.spent_paise + cart.total_paise} would exceed budget {intent.budget_paise}")

        # 5. Above the user's threshold, the user must have signed this exact
        #    cart -- not merely delegated in advance.
        if cart.total_paise > intent.countersign_above_paise:
            if not self.keyring.verify(intent.user_id, cart_env.payload,
                                       cart_env.sigs.get(intent.user_id, "")):
                dec = d("COUNTERSIGN_REQUIRED",
                        f"{cart.total_paise} is above the {intent.countersign_above_paise} "
                        f"auto-approval threshold and carries no user signature")
                dec.needs_countersign = True
                return dec

        return Decision(True, "ALLOWED",
                        f"within mandate: {cart.total_paise} of "
                        f"{intent.budget_paise - st.spent_paise} remaining",
                        cart.total_paise, cart.cart_id, intent.mandate_id)

    def settle(self, intent_env: Envelope, cart_env: Envelope, rail_ref: str = ""):
        """Record a completed charge. Call only after the rail confirms capture.

        Separate from authorize() on purpose: if the rail fails, no budget is
        consumed and the cart stays replayable, so a payment-provider outage
        cannot silently burn the user's authority.
        """
        intent = IntentMandate(**intent_env.body())
        cart = Cart(**cart_env.body())
        st = self.state.setdefault(intent.mandate_id, MandateState())
        st.spent_paise += cart.total_paise
        st.uses += 1
        st.settled_carts.add(cart.cart_id)
        self.audit.append("gate.settled", {
            "cart_id": cart.cart_id,
            "mandate_id": intent.mandate_id,
            "amount_paise": cart.total_paise,
            "spent_paise": st.spent_paise,
            "rail_ref": rail_ref,
        })

    def rail_failed(self, cart_id: str, mandate_id: str, error: str):
        """The gate said yes and the rail said no. Nothing is consumed."""
        self.audit.append("rail.failed", {
            "cart_id": cart_id, "mandate_id": mandate_id, "error": error,
        })


# --------------------------------------------------------------------------
# Evidence: what the merchant hands the acquirer when the chargeback lands.
# --------------------------------------------------------------------------

def evidence_pack(gate: Gate, audit: AuditLog, cart_id: str) -> dict:
    """Everything needed to prove a specific purchase was authorized.

    The signatures are the load-bearing part: they are public-key, so the
    merchant could not have manufactured the user's authorization.
    """
    entries = audit.for_cart(cart_id)
    if not entries:
        return {"cart_id": cart_id, "found": False,
                "conclusion": "no record of this cart -- cannot be defended"}

    decision = next((e for e in entries if e["event"] == "gate.decision"), None)
    settled = next((e for e in entries if e["event"] == "gate.settled"), None)
    intent_env = Envelope.from_dict(decision["payload"]["intent"])
    cart_env = Envelope.from_dict(decision["payload"]["cart"])
    intent, cart = intent_env.body(), cart_env.body()

    checks = {
        "user_signed_the_mandate": gate.keyring.verify(
            intent["user_id"], intent_env.payload, intent_env.sigs.get(intent["user_id"], "")),
        "merchant_signed_the_cart": gate.keyring.verify(
            cart["merchant_id"], cart_env.payload, cart_env.sigs.get(cart["merchant_id"], "")),
        "user_countersigned_the_cart": gate.keyring.verify(
            intent["user_id"], cart_env.payload, cart_env.sigs.get(intent["user_id"], "")),
        "audit_chain_intact": audit.verify(),
    }
    return {
        "cart_id": cart_id,
        "found": True,
        "authorized_by": intent["user_id"],
        "user_stated_constraints": intent["constraints"],
        "authority_granted": {
            "budget_paise": intent["budget_paise"],
            "per_txn_paise": intent["per_txn_paise"],
            "merchant_scope": intent["merchant_id"],
            "expires_at": intent["expires_at"],
        },
        "charged_paise": cart["total_paise"],
        "items": cart["items"],
        "gate_decision": decision["payload"]["decision"],
        "settled": bool(settled),
        "rail_reference": (settled["payload"].get("rail_ref") or None) if settled else None,
        "cryptographic_checks": checks,
        "audit_entries": entries,
        "chain_head": audit.entries[-1]["hash"],
        "conclusion": (
            "Authorized: the user cryptographically granted this authority and the "
            "charge was verified against a merchant-signed cart inside it."
            if all([checks["user_signed_the_mandate"], checks["merchant_signed_the_cart"],
                    checks["audit_chain_intact"]]) and settled
            else "Incomplete: see cryptographic_checks."
        ),
    }
