# Architecture

## 1. Threat model

The design starts from one assumption, and everything else follows from it:

> **The buyer agent is assumed hostile or already compromised.**

Not "an agent might one day be tricked" — assume it *has* been, on this request,
right now. Prompt injection against an LLM reading untrusted web content is not a
bug with a fix; text is data and instructions at the same time. A payment system
that depends on the model resisting manipulation is a payment system whose
security is a model-behaviour question, and model behaviour is not a control.

So the agent is moved outside the trust boundary entirely.

| Party | Trusted for | Not trusted for |
|---|---|---|
| **User** | Granting authority (holds a private key) | — |
| **Merchant** | Stating its own prices (holds a private key) | Staying within the user's limits |
| **Agent** | Nothing | Anything |
| **Gate** | Every decision | — |

The agent holds no key. It authors no document. It cannot express an amount.
Its entire capability is to *present* two documents that other parties signed.

### Out of scope

- A malicious **merchant** signing an inflated cart. Caught by mandate caps and
  merchant scope, not by the signature.
- A compromised **user device**. If the user's private key leaks, the user's
  authority leaks. That is true of every signature scheme.
- **Availability.** This is an authorization layer, not a rate limiter.

## 2. Trust boundary

```
   ┌──────────────── trusted ────────────────┐   ┌──── untrusted ────┐
   │                                         │   │                   │
   │   user key          merchant key        │   │   buyer agent     │
   │      │                    │             │   │   (LLM + tools)   │
   │      v                    v             │   │        │          │
   │  Intent Mandate        Cart             │   │        │          │
   │      │                    │             │   │        │          │
   │      └────────┬───────────┘             │   │        │          │
   │               v                         │   │        │          │
   │            [ GATE ]  <──── presents ────┼───┼────────┘          │
   │               │                         │   │                   │
   │               v                         │   └───────────────────┘
   │   settle ──> hash-chained audit         │
   │                     │                   │
   │                     v                   │
   │              evidence pack              │
   └─────────────────────────────────────────┘
```

The agent's only edge into the trusted zone is the arrow marked *presents*. That
arrow carries two opaque, signed blobs and a cart id. There is no parameter on it
that an injection can usefully corrupt.

## 3. The two documents

Both are canonical-JSON payloads in a signature envelope. Canonicalisation is
`json.dumps(sort_keys=True, separators=(",", ":"))`, so a document has exactly one
byte representation and signatures reproduce.

**Intent Mandate** — signed by the user:

| Field | Purpose |
|---|---|
| `budget_paise` | total authority across all uses |
| `per_txn_paise` | ceiling on any single cart |
| `countersign_above_paise` | above this, the user must sign the cart itself |
| `merchant_id` | scope (`*` = any registered merchant) |
| `max_uses`, `expires_at` | blast-radius limits |
| `constraints` | the user's own words, carried into evidence |

**Cart** — signed by the merchant:

| Field | Purpose |
|---|---|
| `items`, `total_paise` | the merchant's binding price attestation |
| `intent_id` | which mandate this cart was quoted against |
| `expires_at` | quotes go stale |

An envelope holds a map of `signer_id -> signature`, so a cart can carry both the
merchant's signature and the user's counter-signature.

### Why public-key and not HMAC

The first version used HMAC. That was wrong. With a shared secret, the merchant
holds the same key that "proves" the user authorized the purchase — so the
merchant could have manufactured it, and the audit trail proves nothing to an
acquirer. ECDSA P-256/SHA-256 (the AP2 suite) makes the user's authorization
non-repudiable and unforgeable by the party who benefits from forging it.

## 4. Decision sequence

`Gate.authorize(intent_env, cart_env)` is deterministic, side-effect free, and
refuses by default. Order matters: cheap cryptographic rejection first, then
structural checks, then policy.

```
 1. intent parses                        -> INTENT_MALFORMED
 2. intent signed by its claimed user     -> INTENT_UNSIGNED
 3. cart parses                           -> CART_MALFORMED
 4. cart signed by its claimed merchant   -> CART_UNSIGNED
 5. cart line items sum to the total      -> CART_ARITHMETIC
 6. total is positive                     -> AMOUNT_INVALID
 7. cart cites this mandate               -> CART_INTENT_MISMATCH
 8. mandate not revoked                   -> MANDATE_REVOKED
 9. mandate not expired                   -> MANDATE_EXPIRED
10. cart quote not expired                -> CART_EXPIRED
11. cart not already settled              -> REPLAY
12. uses remain                           -> USES_EXHAUSTED
13. merchant within scope                 -> MERCHANT_NOT_ALLOWED
14. total within per-transaction cap       -> PER_TXN_CAP
15. total within remaining budget          -> BUDGET_EXCEEDED
16. if above threshold: user signed cart   -> COUNTERSIGN_REQUIRED
                                             -> ALLOWED
```

Every outcome carries a machine code **and** a human-readable reason. A refusal
nobody can read is not an explanation, and `test_every_deny_is_explained`
enforces it.

`settle()` is separate from `authorize()`. Budget and replay state only move when
the rail confirms capture, so a failed capture cannot silently consume authority.

## 5. Human-in-the-loop as cryptography

Above `countersign_above_paise`, the cart must carry a signature from the
mandate's `user_id`. Not a UI confirmation — an actual signature.

This is why [`approve.py`](approve.py) is **not** an MCP tool. It is a separate
process holding the user's private key, standing in for a tap on a phone. An
injected agent can ask for approval. It cannot grant it, because the key is not
in its address space.

`test_agent_cannot_countersign_for_the_user` pins this.

## 6. Audit and evidence

Each entry is `{seq, ts, event, payload, prev_hash}` with
`hash = SHA256(canonical(entry))`. Editing any historical entry breaks every hash
after it, and `AuditLog.verify()` detects it.

`evidence_pack(gate, audit, cart_id)` assembles what a merchant hands an acquirer:

- the mandate the user signed, and the constraints they stated in their own words
- the merchant-signed cart, with line items
- the gate's decision, code and reason
- **live re-verification** of every signature at pack-generation time
- the chain head, and every audit entry for that cart

When there is no record, the pack says so — `"no record of this cart — cannot be
defended"` — rather than producing a confident-looking document with nothing
behind it.

## 7. Deliberate simplifications

Marked in code with `ponytail:` comments.

| Shortcut | Ceiling | Upgrade path |
|---|---|---|
| In-memory gate state | Single process, lost on restart | Redis |
| `Keyring` as a dict | No real identity registry | NPCI UAP-style agent registry |
| Settlement stops at order creation | No capture, so no money moves | Checkout or Payment Links completes it |
| Carts persisted as one JSON file | Demo-scale only | Any datastore |

## 7a. Rail failure

`authorize()` and `settle()` are separate calls, and the rail sits between them:

```
  authorize()  ->  ALLOWED
       |
       v
  Razorpay order.create()  --- fails --->  rail_failed() logged
       |                                   budget unchanged
       | ok                                cart still payable
       v                                   agent told RAIL_UNAVAILABLE
  settle(rail_ref=order_id)
```

A payment-provider outage therefore cannot consume the user's authority. The
cart remains replayable precisely because `settle()` never ran — the replay
defence and the outage defence are the same mechanism seen from two sides.

## 8. What would need to change for production

1. **Capture, not just authorization.** `pay()` already creates a real Razorpay
   test-mode Order after the gate allows. Completing the capture needs a
   customer at a checkout page.
2. **Key custody.** User keys belong in device secure enclaves; the demo holds
   them in a local file.
3. **Registry.** `merchant_id` and `agent_id` need to resolve against something
   authoritative. This is precisely the gap NPCI's Unified Agent Protocol is
   being designed to fill.
4. **Durable state.** Budget and replay sets must survive restarts, and be
   correct across concurrent workers.
