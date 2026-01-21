# Identity Bindings

This chapter describes the identity binding enforcement details.

## Overview

The backend enforces four mandatory bindings before verification. If any binding fails, verification is rejected before cryptographic verification is attempted.

## Binding A: flowID ↔ keyID

**Check:** The stored public key's `flowID` must match the request's `flowID`.

**Enforcement:** During VERIFY, after loading stored public key.

**Failure reason:** `"flowID ↔ keyID binding violation: stored flowID (X) != request flowID (Y)"`

## Binding B: flowID ↔ challenge

**Check:** The stored challenge must be bound to the request's `flowID`.

**Enforcement:** During VERIFY, when consuming challenge.

**Failure reasons:** 
- `"missing_hash"` - Challenge not found
- `"expired_hash"` - Challenge expired (TTL exceeded)
- `"reused_hash"` - Challenge already consumed

## Binding C: keyID ↔ publicKeyX963

**Check:** The `keyID` must equal `SHA256(publicKeyX963)` exactly (App Attest invariant).

**Enforcement:** During REGISTER (validation) and VERIFY (assertion).

**Failure reason:** `"Public key SHA256 does not match keyID - wrong public key stored"`

## Binding D: flowID ↔ verifyRunID

**Check:** If `verifyRunID` is provided, it must match the stored `verifyRunID` for that `flowID`.

**Enforcement:** During VERIFY, when consuming challenge (if verifyRunID provided).

**Failure reason:** `"verifyRunID_mismatch"`

## Enforcement Order

All bindings are enforced before cryptographic verification:

1. Load stored public key for (keyID, flowID)
2. Check Binding A: flowID ↔ keyID
3. Check Binding C: keyID ↔ publicKeyX963
4. Load stored challenge for (keyID, flowID)
5. Check Binding B: flowID ↔ challenge
6. Check Binding D: flowID ↔ verifyRunID (if provided)
7. Proceed to cryptographic verification only if all bindings pass

If any binding fails, reject immediately. Do NOT return "DER verification failed" for binding violations.
