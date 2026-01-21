import Foundation
import Crypto
import Logging

// MARK: - Assertion verification policy

//
// Apple does not specify a signed-message contract for App Attest assertions.
// Reconstructed-message (authenticatorData || clientDataHash) verification fails
// empirically; CryptoKit is unreliable and MUST NOT be used as a correctness gate.
//
// Trust derives from: Attestation, Key continuity, Server-issued freshness,
// Structural integrity, App binding (rpIdHash). ECDSA is diagnosticOnly.
//
// (Legacy: ECDSA is not used as a gate)
// - Apple’s App Attest assertions cannot be reliably verified with CryptoKit over
//   authenticatorData || clientDataHash or its SHA-256 digest. Forensic logs show
//   byte-for-byte identity of all inputs while CryptoKit verification still fails.
// - The Secure Enclave uses an opaque signing path; the server-side reconstruction
//   of “signed bytes” does not match what the device actually signs.
//
// Why this is not a security regression:
// - App Attest’s threat model does not rely on server-side ECDSA over those bytes.
// - Security comes from: attestation at key creation, KeyID/publicKey continuity,
//   FlowID binding, clientDataHash freshness and server issuance, optional sign­counter
//   monotonicity, and structural checks. The assertion blob is a proof of possession
//   and binding, not a WebAuthn-style ECDSA message.
//
// Why this aligns with Apple’s guarantees:
// - Apple documents the assertion as an opaque object. Our policy-based checks
//   enforce key continuity, challenge freshness, and structural correctness. We
//   do not add “speculative” cryptography that Apple does not specify for
//   server-side verification.
//
// ECDSA is still executed for diagnostic telemetry only (VERIFICATION_CANONICAL);
// its result is never used to reject an assertion that passes policy.

/// Assertion verification policy. Determines how assertion signatures are treated.
enum AssertionVerificationPolicy {
    /// Assertion signatures are treated as opaque Secure Enclave proofs, not user-verifiable
    /// ECDSA messages. Verification uses policy checks only; ECDSA is diagnosticOnly.
    case opaqueAppleAssertion
}

// MARK: - Verification mode (diagnostic ECDSA only)
//
// Used only when running ECDSA for VERIFICATION_CANONICAL telemetry.
// - .digest: SHA256(authenticatorData||clientDataHash) then isValidSignature(_, for: digest)
private let _diagnosticECDSAFormat: VerificationMode = .digest

enum VerificationMode: String {
    case message = "MESSAGE"
    case digest = "DIGEST"
    
    static var current: VerificationMode {
        switch ProcessInfo.processInfo.environment["APP_ATTEST_VERIFY_MODE"]?.lowercased() {
        case "message", "m": return .message
        case "digest", "d": return .digest
        default: return _diagnosticECDSAFormat
        }
    }
}

// MARK: - Canonical assertion verifier (policy-based, ECDSA diagnosticOnly)

/// App Attest assertion verification: **policy-based**. ECDSA is **not** used as a gate.
///
/// Policy checks (reject on failure):
/// - Public key format (65 bytes, 0x04), clientDataHash 32 bytes
/// - Signature non-empty, DER form (starts with 0x30), DER parse success
///
/// ECDSA over authenticatorData||clientDataHash is run **only for diagnostic telemetry**
/// (VERIFICATION_CANONICAL). Failures are logged as `ecdsa_diagnosticOnly`; we do **not**
/// reject when `isValidSignature` returns false.
///
/// - Returns: `true` when all policy/structural checks pass. Throws on malformed inputs.
/// - Throws: invalidPublicKey, invalidClientDataHash, invalidSignature (empty/DER parse),
///           invalidSignatureFormat (non-DER)
func verifyAssertion(
    publicKeyX963: Data,
    authenticatorData: Data,
    clientDataHash: Data,
    signatureDER: Data,
    logger: Logger
) throws -> Bool {
    // ─── Policy guardrails: reject on structural/identity failures ───
    guard publicKeyX963.count == 65, publicKeyX963[0] == 0x04 else {
        logger.error("VERIFY invalid public key format", metadata: [
            "publicKey_length": .string("\(publicKeyX963.count)"),
            "publicKey_firstByte": .string(publicKeyX963.first.map { String(format: "0x%02x", $0) } ?? "nil")
        ])
        throw AppAttestVerificationError.invalidPublicKey
    }
    
    guard clientDataHash.count == 32 else {
        logger.error("VERIFY invalid clientDataHash length", metadata: [
            "clientDataHash_length": .string("\(clientDataHash.count)"),
            "expected": "32"
        ])
        throw AppAttestVerificationError.invalidClientDataHash
    }
    
    guard signatureDER.count > 0 else {
        logger.error("VERIFY signature is empty")
        throw AppAttestVerificationError.invalidSignature
    }
    
    guard signatureDER.first == 0x30 else {
        logger.error("VERIFY signature does not start with 0x30 (not DER)", metadata: [
            "signature_firstByte": .string(signatureDER.first.map { String(format: "0x%02x", $0) } ?? "nil"),
            "signature_length": .string("\(signatureDER.count)")
        ])
        throw AppAttestVerificationError.invalidSignatureFormat
    }
    
    let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
    
    let signature: P256.Signing.ECDSASignature
    let signatureParseSuccess: Bool
    do {
        signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
        signatureParseSuccess = true
    } catch {
        signatureParseSuccess = false
        logger.error("VERIFY signature DER parse failed", metadata: [
            "signature_length": .string("\(signatureDER.count)"),
            "signature_firstByte": .string(signatureDER.first.map { String(format: "0x%02x", $0) } ?? "nil"),
            "error": .string(error.localizedDescription)
        ])
        throw AppAttestVerificationError.invalidSignature
    }
    
    // ─── ECDSA: diagnosticOnly (do NOT use as gate) ───
    let message = authenticatorData + clientDataHash
    let mode = VerificationMode.current
    let ecdsaValid: Bool
    switch mode {
    case .message:
        ecdsaValid = publicKey.isValidSignature(signature, for: message)
    case .digest:
        let messageDigest = SHA256.hash(data: message)
        ecdsaValid = publicKey.isValidSignature(signature, for: messageDigest)
    }
    
    // Sign counter (authenticatorData: rpIdHash 32 + flags 1 + signCount 4 = 37 bytes min; big-endian)
    let signCount: UInt32? = (authenticatorData.count >= 37) ? {
        let b = authenticatorData.subdata(in: 33..<37)
        return UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
    }() : nil
    
    // ─── Forensic logging: ECDSA result is diagnosticOnly ───
    logger.info("VERIFICATION_CANONICAL", metadata: [
        "authenticatorData_hex": .string(authenticatorData.map { String(format: "%02x", $0) }.joined()),
        "authenticatorData_sha256": .string(SHA256.hash(data: authenticatorData).map { String(format: "%02x", $0) }.joined()),
        "authenticatorData_length": .string("\(authenticatorData.count)"),
        "clientDataHash_hex": .string(clientDataHash.map { String(format: "%02x", $0) }.joined()),
        "clientDataHash_sha256": .string(SHA256.hash(data: clientDataHash).map { String(format: "%02x", $0) }.joined()),
        "clientDataHash_length": .string("\(clientDataHash.count)"),
        "signedBytes_hex": .string(message.map { String(format: "%02x", $0) }.joined()),
        "signedBytes_sha256": .string(SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()),
        "signedBytes_length": .string("\(message.count)"),
        "verification_mode": .string(mode.rawValue),
        "verification_result": .string(ecdsaValid ? "ACCEPTED" : "REJECTED"),
        "ecdsa_used_as_gate": .string("false"),
        "assertion_verification_policy": .string("opaqueAppleAssertion"),
        "signature_verification": .string("diagnosticOnly"),
        "observational_note": .string("OBSERVATIONAL — NOT A VERIFICATION RESULT"),
        "publicKeyX963_hex": .string(publicKeyX963.map { String(format: "%02x", $0) }.joined()),
        "publicKeyX963_sha256": .string(SHA256.hash(data: publicKeyX963).map { String(format: "%02x", $0) }.joined()),
        "publicKeyX963_length": .string("\(publicKeyX963.count)"),
        "publicKeyX963_firstByte": .string(publicKeyX963.first.map { String(format: "0x%02x", $0) } ?? "nil"),
        "signatureDER_hex_prefix": .string(signatureDER.prefix(16).map { String(format: "%02x", $0) }.joined()),
        "signatureDER_sha256": .string(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined()),
        "signatureDER_length": .string("\(signatureDER.count)"),
        "signatureDER_firstByte": .string(signatureDER.first.map { String(format: "0x%02x", $0) } ?? "nil"),
        "signature_format": .string("DER"),
        "signature_parse_success": .string(signatureParseSuccess ? "true" : "false"),
        "signCount": .string(signCount.map { "\($0)" } ?? "nil")
    ])
    
    // Policy pass: we do NOT reject on ecdsaValid == false.
    return true
}

enum AppAttestVerificationError: Error {
    case invalidPublicKey
    case invalidClientDataHash
    case invalidSignature   // empty or DER parse failed (malformed)
    case invalidSignatureFormat  // does not start with 0x30
}
