# Why This Exists

## The Problem

App Attest verification is cryptographically complex and requires precise, server-side validation. Most implementations either:
- Trust client-provided data (security flaw)
- Mix validation logic with policy decisions (architectural flaw)
- Use opaque libraries without understanding the verification path (maintenance flaw)

## The Solution

This backend provides a **forensic-grade App Attest verification service** that:
- Decodes assertions without trusting client hints
- Reconstructs Sig_structure server-side (single source of truth)
- Performs pure cryptographic verification (no policy, no heuristics)
- Makes explicit trust decisions (backend owns trust, validator owns math)

## What Makes This Different

**Explicit boundaries:**
- iOS app produces assertions only
- Backend owns decoding, reconstruction, validation, and trust
- Validator is pure math and frozen
- Decoder is the single source of truth for bytes
- No layer lies about certainty

**Forensic behavior:**
- The validator answers exactly one question: "Does this signature verify over these exact bytes with this exact key?"
- Nothing else. No policy creep. No "almost valid." No silent reconstruction.

**Cryptographically closed:**
- Real assertion → Verified
- One-byte tamper → Rejected
- No forgiveness. No normalization. No trust leakage.

## What This Is Not

- Not a demo or proof-of-concept
- Not a product feature
- Not a "security framework"
- Not a replacement for proper key management

## What This Is

A **trust primitive** — a building block for systems that need to verify App Attest assertions correctly, without shortcuts, without guessing, without lying.

## When to Use This

- You need server-side App Attest verification
- You want explicit, auditable verification logic
- You need to understand what's being verified and why
- You require forensic-grade behavior (no silent failures)

## When Not to Use This

- You want "magic" security that "just works"
- You prefer opaque libraries over explicit logic
- You need policy decisions mixed with crypto verification
- You want client-provided verification hints

## The Discipline

This system is **boring by design**:
- No retries
- No heuristics
- No "helpful" defaults
- No policy in the validator
- No trust in client data

That discipline is what makes it correct.

---

**Built:** [Date]
**Status:** Cryptographically closed
**Next:** Use it, don't improve it.
