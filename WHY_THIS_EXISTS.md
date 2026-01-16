# Why This Exists

**Independent Development**: This project was developed independently while implementing and testing App Attest verification logic. It reflects the lessons learned from debugging real verification failures, not an official or endorsed implementation.

## The Problem

App Attest verification is cryptographically complex and requires precise, server-side validation. Most implementations are wrong in at least one of these ways:
- They verify the wrong payload (CBOR Sig_structure instead of raw concatenation)
- They accidentally double-hash before signature verification
- They mix protocol parsing with policy decisions
- They rely on undocumented behavior or cargo-culted WebAuthn code
- They make it impossible to audit what is actually being verified

## The Solution

This backend provides a **specification-correct App Attest verification service** that:
- Decodes assertions without trusting client hints
- Reconstructs the exact bytes Apple signed (`authenticatorData || clientDataHash`)
- Performs pure cryptographic verification (no policy, no heuristics)
- Makes explicit trust decisions (backend owns trust, validator owns math)

## What Makes This Different

**Spec correctness:**
- Verifies `authenticatorData || clientDataHash`, which is what Apple actually signs
- Does not assume COSE or WebAuthn semantics that do not apply to App Attest

**Cryptographic clarity:**
- Validator performs a single ES256 verification
- No hidden hashing, no opaque helpers, no magic wrappers
- The bytes being verified are visible and traceable

**Separation of concerns:**
- Decoder parses
- Validator verifies
- Storage is replaceable (RAM, filesystem, HSM, database)
- Policy is intentionally not included

**Auditability:**
- Designed so a reviewer can answer: "What exact bytes are verified, and why?"
- This is rare in App Attest examples and SDK-level integrations

**Production flexibility:**
- Can be dropped behind an API gateway
- Can be wrapped with auth, rate limiting, or allowlists
- Can be used as a reference implementation even if not deployed directly

**Cryptographically closed:**
- Real assertion → Verified
- One-byte tamper → Rejected
- No forgiveness. No normalization. No trust leakage.

**Security boundaries:**
- This service verifies cryptographic authenticity only
- It does not establish device trust, user trust, or request authorization
- Those concerns must be layered separately

## What This Is Not

This backend intentionally does not:
- Perform device trust policy
- Track risk scores
- Store long-term state beyond keys
- Enforce rate limits
- Authenticate callers
- Hide implementation details

Those are higher-level concerns and should live outside cryptographic verification.

## What This Is

A **minimal, specification-correct verification layer** — a building block for systems that need to verify App Attest assertions correctly, without shortcuts, without guessing, without lying.

In short: this repo is valuable because it is boringly correct in a space full of half-working implementations.

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
- Correct bytes
- Correct hash
- Correct signature semantics
- No accidental complexity
- No retries
- No heuristics
- No "helpful" defaults
- No policy in the validator
- No trust in client data

That discipline is what makes it correct. That's exactly what App Attest needs, and almost no public examples provide it.

---

**Status:** Cryptographically closed and specification-correct
**Next:** Use it, don't improve it.
