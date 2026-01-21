//
//  VerifyForensicsBuilder.swift
//  AppAttestBackend
//
//  Forensics payload builder (optional).
//

import Foundation

func buildForensics(
    requestID: String?,
    flowID: String,
    keyID_sha256: String,
    verifyRunID: String?,
    assertionObject: Data,
    authenticatorData: Data,
    signature: Data,
    storedClientDataHash: Data,
    publicKeyX963: Data,
    signedMessage: Data,
    errorCase: String?,
    recomputedSignedBytes_hex: String? = nil,
    recomputedSignedBytes_sha256: String? = nil,
    frontendSignedBytes_hex: String? = nil,
    frontendSignedBytes_sha256: String? = nil,
    signedBytesMatch: Bool? = nil,
    digestMatch: Bool? = nil,
    signatureParsed: Bool? = nil,
    curve: String? = nil,
    digest_algorithm: String? = nil
) -> VerifyForensics? {
    let debugLevel = ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_FORENSICS"] ?? "0"
    let groundTruth = (recomputedSignedBytes_hex != nil || signedBytesMatch != nil || signatureParsed != nil || curve != nil)
    let include = (debugLevel == "1" || debugLevel == "2") || groundTruth
    guard include else { return nil }
    
    return VerifyForensics(
        requestID: requestID,
        flowID: flowID,
        keyID_sha256: keyID_sha256,
        verifyRunID: verifyRunID,
        assertionObject_b64_len: assertionObject.count,
        assertionObject_sha256: sha256Hex(assertionObject),
        authenticatorData_len: authenticatorData.count,
        authenticatorData_hex: authenticatorData.map { String(format: "%02x", $0) }.joined(),
        authenticatorData_sha256: sha256Hex(authenticatorData),
        signature_len: signature.count,
        signature_hex: signature.map { String(format: "%02x", $0) }.joined(),
        signature_sha256: sha256Hex(signature),
        storedClientDataHash_len: storedClientDataHash.count,
        storedClientDataHash_hex: storedClientDataHash.map { String(format: "%02x", $0) }.joined(),
        storedClientDataHash_sha256: sha256Hex(storedClientDataHash),
        publicKeyX963_len: publicKeyX963.count,
        publicKeyX963_hex: publicKeyX963.map { String(format: "%02x", $0) }.joined(),
        publicKeyX963_sha256: sha256Hex(publicKeyX963),
        signedMessage_len: signedMessage.count,
        signedMessage_hex: signedMessage.map { String(format: "%02x", $0) }.joined(),
        signedMessage_sha256: sha256Hex(signedMessage),
        verifierMode: AssertionVerificationMode.current.rawValue,
        errorCase: errorCase,
        recomputedSignedBytes_hex: recomputedSignedBytes_hex,
        recomputedSignedBytes_sha256: recomputedSignedBytes_sha256,
        frontendSignedBytes_hex: frontendSignedBytes_hex,
        frontendSignedBytes_sha256: frontendSignedBytes_sha256,
        signedBytesMatch: signedBytesMatch,
        digestMatch: digestMatch,
        signatureParsed: signatureParsed,
        curve: curve,
        digest_algorithm: digest_algorithm
    )
}
