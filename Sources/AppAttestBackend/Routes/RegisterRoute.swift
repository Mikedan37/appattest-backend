//
//  RegisterRoute.swift
//  AppAttestBackend
//

import Foundation
import Vapor
import Crypto

func registerRegisterRoute(_ app: Application) {
    app.post("app-attest", "register") { req -> RegisterResponse in
        let logger = req.logger
        let registerReq = try req.content.decode(RegisterRequest.self)
        
        guard let attestationObject = Data(base64Encoded: registerReq.attestationObject) else {
            return RegisterResponse(status: "rejected", reason: "INVALID_FORMAT", flowID: nil, publicKeySha256: nil)
        }
        guard let clientDataHash = Data(base64Encoded: registerReq.clientDataHash_base64) else {
            return RegisterResponse(status: "rejected", reason: "INVALID_CLIENT_DATA_HASH", flowID: nil, publicKeySha256: nil)
        }
        let challengeForAudit: Data? = {
            guard let challengeB64 = registerReq.challenge_base64,
                  let challenge = Data(base64Encoded: challengeB64) else {
                return nil
            }
            return challenge
        }()
        
        let keyIDBytes: Data
        do { keyIDBytes = try KeyID.decodeBase64(registerReq.keyID) }
        catch { return RegisterResponse(status: "rejected", reason: "INVALID_FORMAT", flowID: nil, publicKeySha256: nil) }
        
        guard let bundleID = ProcessInfo.processInfo.environment["APP_BUNDLE_ID"], !bundleID.isEmpty,
              let teamID = ProcessInfo.processInfo.environment["APP_TEAM_ID"], !teamID.isEmpty else {
            return RegisterResponse(status: "rejected", reason: "APP_BUNDLE_ID / APP_TEAM_ID not set", flowID: nil, publicKeySha256: nil)
        }
        
        if KeyStore.hasKeyID(keyIDBytes) {
            return RegisterResponse(status: "rejected", reason: "KEY_REUSE_ATTEMPT", flowID: nil, publicKeySha256: nil)
        }
        
        let flowID = UUID().uuidString
        let result: AttestationVerificationResult
        do {
            result = try AttestationVerifier.verify(attestationObject: attestationObject, keyIDBytes: keyIDBytes, clientDataHash: clientDataHash, appIDPrefix: teamID, bundleID: bundleID, challengeForAudit: challengeForAudit, logger: logger)
        } catch {
            let reason: String
            if let attestationError = error as? AttestationVerificationError {
                switch attestationError {
                case .invalidCBOR, .invalidFormat, .invalidPublicKey:
                    reason = "INVALID_FORMAT"
                case .missingCertificates:
                    reason = "MISSING_CERT_CHAIN"
                case .untrustedRoot:
                    reason = "UNTRUSTED_ATTESTATION_ROOT"
                case .invalidIntermediateSignature:
                    reason = "INVALID_INTERMEDIATE_SIGNATURE"
                case .invalidLeafSignature:
                    reason = "INVALID_LEAF_SIGNATURE"
                case .rootNotSelfSigned:
                    reason = "ROOT_NOT_SELF_SIGNED"
                case .missingCredentialData:
                    reason = "INVALID_FLAGS"
                case .counterNotZero:
                    reason = "INVALID_SIGN_COUNT"
                case .aaguidMismatch:
                    reason = "INVALID_AAGUID"
                case .rpIdHashMismatch:
                    reason = "RPID_HASH_MISMATCH"
                case .credentialIdMismatch:
                    reason = "CREDENTIAL_ID_MISMATCH"
                case .keyIDMismatch:
                    reason = "KEYID_MISMATCH"
                case .challengeMissing:
                    reason = "MISSING_CHALLENGE"
                case .nonceExtensionMissing:
                    reason = "NONCE_EXTENSION_MISSING"
                case .nonceExtensionDecodeFailed:
                    reason = "NONCE_EXTENSION_DECODE_FAILED"
                case .nonceMismatch:
                    reason = "NONCE_MISMATCH"
                case .clientDataHashInvalidLength:
                    reason = "CLIENT_DATA_HASH_INVALID_LENGTH"
                case .clientDataHashMismatch:
                    reason = "CLIENT_DATA_HASH_MISMATCH"
                default:
                    reason = "attestation verification failed"
                }
            } else {
                reason = "attestation verification failed"
            }
            logger.error("Attestation verification failed: \(error)")
            return RegisterResponse(status: "rejected", reason: reason, flowID: nil, publicKeySha256: nil)
        }
        
        let stored = KeyStore.storePublicKey(
            keyIDBytes: keyIDBytes,
            publicKey: result.publicKeyX963,
            flowID: flowID,
            source: "x5c[0].subjectPublicKeyInfo (leaf certificate SPKI)",
            environment: result.environment,
            receipt: result.receipt,
            logger: logger
        )
        guard stored else {
            return RegisterResponse(status: "rejected", reason: "Failed to store public key", flowID: nil, publicKeySha256: nil)
        }
        
        #if DEBUG
        let pubSha = sha256Hex(result.publicKeyX963)
        #else
        let pubSha: String? = nil
        #endif
        return RegisterResponse(status: "accepted", reason: nil, flowID: flowID, publicKeySha256: pubSha)
    }
    app.get("app-attest", "register") { req -> Response in
        req.logger.warning("Register endpoint called with GET")
        return Response(status: .methodNotAllowed)
    }
}
