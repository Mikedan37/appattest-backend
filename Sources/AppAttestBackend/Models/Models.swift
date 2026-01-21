//
//  Models.swift
//  AppAttestBackend
//
//  AssertionVerificationMode, RejectReason, CanonicalVerificationLog.
//

import Foundation

// MARK: - Assertion verification mode

/// APP_ATTEST_ASSERTION_MODE: strict|s => strictECDSA, opaque|o => opaquePolicy. Default: strictECDSA.
enum AssertionVerificationMode: String {
    case strictECDSA = "STRICT"
    case opaquePolicy = "OPAQUE"
    
    static var current: AssertionVerificationMode {
        switch ProcessInfo.processInfo.environment["APP_ATTEST_ASSERTION_MODE"]?.lowercased() {
        case "opaque", "o": return .opaquePolicy
        case "strict", "s": return .strictECDSA
        default: return .strictECDSA
        }
    }
}

// MARK: - Reject reasons

enum RejectReason: String {
    case IDENTITY_MISMATCH
    case EXPIRED_CHALLENGE
    case REPLAYED_CHALLENGE
    case CBOR_DECODE_FAILED
    case SIGNED_BYTES_MISMATCH
    case PUBKEY_MISMATCH
    case SIGNATURE_MISMATCH
    case ECDSA_VERIFY_FAILED
    case SIGNCOUNT_REPLAY
    case MALFORMED_SIGNATURE
    case UNTRUSTED_ATTESTATION_ROOT
    case INVALID_INTERMEDIATE_SIGNATURE
    case INVALID_LEAF_SIGNATURE
    case ROOT_NOT_SELF_SIGNED
    case ASSERTION_CBOR_DECODE_FAILED
    case ASSERTION_MISSING_AUTHENTICATOR_DATA
    case ASSERTION_MISSING_SIGNATURE
    case SIGNATURE_DER_DECODE_FAILED
    case PUBLIC_KEY_INVALID
    case SIGNED_BYTES_LENGTH_INVALID
    case CLIENT_DATA_HASH_NOT_FOUND
    case CLIENT_DATA_HASH_INVALID_LENGTH
}

// MARK: - Canonical verification log (one JSON line per verifyRunID, grep-friendly)

struct CanonicalVerificationLog: Encodable {
    let tag = "VERIFICATION_CANONICAL"
    let mode: String
    let keyID_sha256: String
    let flowID: String
    let verifyRunID: String?
    let authenticatorData_sha256: String
    let clientDataHash_sha256: String
    let signedBytes_sha256: String
    let nonce_sha256: String
    let signature_sha256: String
    let publicKeyX963_sha256: String
    let signCount: UInt32?
    let rpIdHash_ok: Bool?
    let ecdsa_digest_valid: Bool
    let ecdsa_message_valid: Bool
    let decision: String
    let reject_reason: String?
    
    enum CodingKeys: String, CodingKey {
        case tag, mode, keyID_sha256, flowID, verifyRunID
        case authenticatorData_sha256, clientDataHash_sha256, signedBytes_sha256, nonce_sha256
        case signature_sha256, publicKeyX963_sha256, signCount, rpIdHash_ok
        case ecdsa_digest_valid, ecdsa_message_valid, decision, reject_reason
    }
}

struct AssertionVerifyCanonical: Encodable {
    let verifyRunID: String
    let flowID: String
    let keyID_sha256: String
    let publicKeyX963_length: Int
    let publicKeyX963_prefix1: String
    let publicKeyX963_sha256: String
    let publicKeyX963_hex_prefix: String?
    let publicKeyX963_hex_suffix: String?
    let clientData_length: Int?
    let clientData_sha256: String?
    let clientDataHash_length: Int
    let clientDataHash_hex: String
    let clientDataHash_sha256: String?
    let authenticatorData_length: Int
    let authenticatorData_sha256: String
    let signedBytes_length: Int
    let signedBytes_sha256: String
    let nonce_hex: String?
    let nonce_sha256: String?
    let signature_length: Int
    let signature_sha256: String
    let assertionObject_length: Int
    let assertionObject_sha256: String
}
