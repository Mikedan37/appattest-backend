# Overview

This chapter introduces the App Attest Backend Verification Service and explains its purpose and scope.

## What This Service Does

The App Attest Backend Verification Service performs cryptographic verification of Apple App Attest assertion signatures. It implements protocol-level enforcement including identity bindings and challenge consumption.

The service provides three endpoints:

1. **Registration** - Extracts and stores public keys from attestation objects
2. **Challenge Generation** - Generates and issues challenges bound to key and flow identifiers
3. **Verification** - Verifies assertion signatures using stored keys and challenges

## Scope

This service performs cryptographic verification only. It does not implement:

- Trust decisions
- Authorization
- Freshness validation beyond protocol-level challenge TTL
- Policy logic

A `verified` response indicates that the signature is cryptographically valid for the observed byte sequence. It does not indicate authorization, trust, or freshness beyond the protocol-level challenge consumption.

## Backend Authority

The backend is the sole authority for:

1. **Challenge generation** - The backend generates, stores, and supplies challenges to the frontend. The frontend does not generate or modify them.

2. **flowID lifecycle** - The backend issues `flowID` during registration and enforces its binding to `keyID` and challenge throughout the flow.

3. **Identity bindings** - The backend enforces four mandatory bindings before verification:
   - `flowID ↔ keyID`
   - `flowID ↔ challenge`
   - `keyID ↔ publicKeyX963`
   - `flowID ↔ verifyRunID` (if provided)

All client-provided values (`keyID`, `flowID`, `assertionObject`, `verifyRunID`) are treated as untrusted inputs and validated against stored server state.

## What This Service Does Not Do

- Trust validation (certificate chain verification, key source validation)
- Authorization (access control, user permissions)
- Policy enforcement (bundle ID checks, team ID validation, environment restrictions)
- Freshness validation beyond 5-minute challenge TTL

See [Verification Semantics](./04-Verification-Semantics.md) for the meaning of a "verified" response.
