# Proof-of-Mandate — working notes

Authorization and dispute-evidence layer for AI agents that spend money. Built
for the Razorpay AI Buildathon 2026, Track 01 (Agentic Commerce).

Read [README.md](README.md) for the pitch and [ARCHITECTURE.md](ARCHITECTURE.md)
for the threat model and decision sequence. This file is the context those two
don't carry.

## Setup

Python 3.12 in `.venv` (the system Python is 3.9 and the MCP SDK needs 3.10+).

```bash
.venv/bin/python test_core.py     # 23 tests
.venv/bin/python attacks.py       # ablation, writes results.json
.venv/bin/python demo.py          # the narrated story, for the video
.venv/bin/python injections.py --dry
```

`.env` holds Razorpay test keys and is gitignored. `demo_keys.json` and
`demo_carts.json` are local demo state, also gitignored.

## Invariants — do not break these

1. **The agent never names an amount.** `pay()` takes a `cart_id` only. The
   amount comes from a merchant-signed cart. Adding an amount parameter anywhere
   in the agent's reach defeats the entire design.
2. **`approve.py` is not an MCP tool, deliberately.** It is a separate process
   holding the user's private key. If the agent could call it, human approval
   would be worth nothing.
3. **Signatures are public-key (ECDSA P-256), never HMAC.** With a shared secret
   the merchant could forge the user's authorization, so the evidence would prove
   nothing in a dispute. This was changed from HMAC for exactly that reason.
4. **`authorize()` and `settle()` stay separate.** Budget and replay state move
   only after the rail confirms. A provider outage must not consume authority.
5. **Money is integer paise.** No floats on a money path.
6. **Every deny carries a code and a human-readable reason.**
   `test_every_deny_is_explained` enforces it.

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
