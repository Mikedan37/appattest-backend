//
//  RequestsResponses.swift
//  AppAttestBackend
//
//  API request/response models and forensic payloads.
//

import Foundation
import Vapor

struct VerifyRequest: Content {
    let keyID: String
    let assertionObject_base64: String
    let flowID: String
    let challenge_id: String
    let clientData_base64: String
    let verifyRunID: String?
    // Optional debug fields
    let authenticatorData_raw_base64: String?
    let signedBytes_raw_hex: String?
    let signature_der_base64: String?
    let publicKey_x963_base64: String?
}

struct ClientDataHashRequest: Content {
    let keyID: String
    let flowID: String
    let verifyRunID: String?
}

struct ClientDataHashResponse: Content {
    let clientDataHash: String
    let expiresAt: String
    
    enum CodingKeys: String, CodingKey {
        case clientDataHash
        case expiresAt
    }
}

struct VerifyForensics: Content {
    let requestID: String?
    let flowID: String
    let keyID_sha256: String
    let verifyRunID: String?
    let assertionObject_b64_len: Int
    let assertionObject_sha256: String
    let authenticatorData_len: Int
    let authenticatorData_hex: String
    let authenticatorData_sha256: String
    let signature_len: Int
    let signature_hex: String
    let signature_sha256: String
    let storedClientDataHash_len: Int
    let storedClientDataHash_hex: String
    let storedClientDataHash_sha256: String
    let publicKeyX963_len: Int
    let publicKeyX963_hex: String
    let publicKeyX963_sha256: String
    let signedMessage_len: Int
    let signedMessage_hex: String
    let signedMessage_sha256: String
    let verifierMode: String
    let errorCase: String?
    let recomputedSignedBytes_hex: String?
    let recomputedSignedBytes_sha256: String?
    let frontendSignedBytes_hex: String?
    let frontendSignedBytes_sha256: String?
    let signedBytesMatch: Bool?
    let digestMatch: Bool?
    let signatureParsed: Bool?
    let curve: String?
    let digest_algorithm: String?
}

struct VerifyResponse: Content {
    let status: String
    let reason: String?
    let note: String?
    let firstDifferingByteIndex: Int?
    let assertion_verification_policy: String?
    let mode: String?
    let signCount: UInt32?
    let verifyRunID: String?
    let forensics: VerifyForensics?
}

struct RegisterRequest: Content {
    let keyID: String
    let attestationObject: String
    /// Base64-encoded clientDataHash bytes (required, produced on-device).
    let clientDataHash_base64: String
    /// Base64-encoded challenge bytes (optional, debug-only for audit checks).
    let challenge_base64: String?
}

struct RegisterResponse: Content {
    let status: String
    let reason: String?
    let flowID: String?
    let publicKeySha256: String?
}

struct HealthResponse: Content {
    let status: String
    let buildSha256: String?
    let buildTime: String?
    let storageBackend: String
    let keyCount: Int
    let clientDataHashCount: Int
    let uptimeSeconds: Double
    let lastVerifyRunIDSeen: String?
    
    init(status: String, buildSha256: String? = nil, buildTime: String? = nil, storageBackend: String = "RAM", keyCount: Int = 0, clientDataHashCount: Int = 0, uptimeSeconds: Double = 0, lastVerifyRunIDSeen: String? = nil) {
        self.status = status
        self.buildSha256 = buildSha256
        self.buildTime = buildTime
        self.storageBackend = storageBackend
        self.keyCount = keyCount
        self.clientDataHashCount = clientDataHashCount
        self.uptimeSeconds = uptimeSeconds
        self.lastVerifyRunIDSeen = lastVerifyRunIDSeen
    }
}
