# Proof-of-Mandate — working notes

Authorization and dispute-evidence layer for AI agents that spend money. Built
for the Razorpay AI Buildathon 2026, Track 01 (Agentic Commerce).

Read [README.md](README.md) for the pitch and [ARCHITECTURE.md](ARCHITECTURE.md)
for the threat model and decision sequence. This file is the context those two
don't carry.

## Setup

Python 3.12 in `.venv` (the system Python is 3.9 and the MCP SDK needs 3.10+).

```bash
.venv/bin/python test_core.py     # 27 tests
.venv/bin/python attacks.py       # ablation, writes results.json
.venv/bin/python demo.py          # the narrated story, for the video
.venv/bin/python grant.py         # the user setting their own limits
.venv/bin/python injections.py --dry
```

`.env` holds Razorpay test keys and is gitignored. `demo_keys.json`,
`demo_carts.json` and `mandate.json` are local state, also gitignored. A fresh
clone writes a default demo mandate on first run so the demo works immediately;
`grant.py` replaces it with the user's own limits.

## Invariants — do not break these

1. **The agent never names an amount.** `pay()` takes a `cart_id` only. The
   amount comes from a merchant-signed cart. Adding an amount parameter anywhere
   in the agent's reach defeats the entire design.
2. **No tool in the agent's reach creates or approves spending power.**
   `request_authority()` stages a request and returns a *link*; the signature
   happens in `approval.py`, in the user's own context, after they have seen
   the exact figures. `approve.py` and `grant.py` are the terminal fallbacks
   for the same two acts. If the agent could grant its own mandate it would
   have no limits at all; if it could approve its own purchases, approval
   would be worth nothing. The agent may ask. It may never sign.
   A new user starts with **no** mandate and `load_mandate()` returns `None` —
   every tool fails closed on it. Only `demo.py` seeds one, via
   `ensure_demo_mandate()`, so the scripted demo runs without a human.
   `revoke_authority()` **is** a tool, and safely so: it only ever reduces what
   the agent may do. Direction is the test — widening authority needs a
   signature, narrowing it does not.
3. **Signatures are public-key (ECDSA P-256), never HMAC.** With a shared secret
   the merchant could forge the user's authorization, so the evidence would prove
   nothing in a dispute. This was changed from HMAC for exactly that reason.
4. **`authorize()` and `settle()` stay separate.** Budget and replay state move
   only after the rail confirms. A provider outage must not consume authority.
   `settle()` re-checks the time-invariant facts (both signatures, the
   cart-to-mandate binding) and refuses a cart that never came through
   `authorize()` — but deliberately does *not* re-check expiry or budget, so a
   slow rail can never make a captured payment unrecordable.
5. **Money is integer paise.** No floats on a money path.
6. **Every deny carries a code and a human-readable reason.**
   `test_every_deny_is_explained` enforces it.
7. **The agent signs the cart it presents.** A mandate names an `agent_id`; the
   gate requires that agent's signature rather than trusting a self-reported
   id, because a compromised agent would simply assert whichever id the mandate
   names. This is what makes a stolen mandate useless to another agent, and it
   puts the executing agent's identity into the evidence pack.
8. **Audit entries are signed, not merely chained.** A hash chain alone only
   detects an edit — whoever holds the log can re-chain the whole thing and
   still pass `verify()`. `verify(keyring)` checks the per-entry signatures,
   which is what makes the log worth anything to a party who does not trust the
   operator. External anchoring is the remaining upgrade.
9. **Amounts are integers, checked by type.** `1000 == 1000.0` is true in
   Python, so the gate rejects non-`int` amounts outright rather than relying on
   the arithmetic comparison.

## Design decisions worth knowing

- Track 01 was chosen over Track 04 (reconciliation) deliberately: higher
  ceiling, and the hard part is cryptography and policy — deterministic and
  testable — rather than sandbox integration.
- The framing is "the agent can be fooled, the gate cannot". We make **no**
  attempt to keep the agent safe. Assume it is compromised and put money out of
  its reach.
- The audit chain is not decoration. It is the dispute evidence — the same
  mechanism serves prevention and proof, which is why they are one system.
- Prior art is acknowledged openly in the README (AP2, ACP, CertNode,
  Mastercard, Visa). Claiming novelty we don't have would be worse than useless
  in front of a panel.
- The injection compliance column is **left empty on purpose** until a real model
  run fills it. Do not guess it, and do not let a contaminated subject (an agent
  that has read this repo) self-report it.

## Conventions

Comments marked `ponytail:` flag deliberate shortcuts with a named ceiling and an
upgrade path. Keep that convention when adding one.

Tests are plain `assert` in `test_core.py`, run directly, no framework.
