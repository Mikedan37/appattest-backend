//
//  VerifyRoute.swift
//  AppAttestBackend
//

import Foundation
import Vapor
import Crypto
import AppAttestCore

func registerVerifyRoute(_ app: Application) {
    app.post("app-attest", "verify") { req -> VerifyResponse in
        let logger = req.logger
        let verifyReq = try req.content.decode(VerifyRequest.self)
        let mode = AssertionVerificationMode.current
        
        var authenticatorData: Data? = nil
        var signatureData: Data? = nil
        var signedBytesSnapshot: Data? = nil
        var clientDataHashSnapshot: Data? = nil
        var publicKeySnapshot: Data? = nil
        var signCountSnapshot: UInt32? = nil
        var rpIdHashOk: Bool? = nil
        var ecdsaDigestValid: Bool? = nil
        var ecdsaMessageValid: Bool? = nil
        var nonceSHA: String? = nil
        
        var keyIDBytes: Data? = nil
        var verifyRunID: String = verifyReq.verifyRunID ?? UUID().uuidString
        func logCanonical(decision: String, reject: RejectReason?) {
            let canon = CanonicalVerificationLog(
                mode: mode.rawValue,
                keyID_sha256: keyIDBytes.map { sha256Hex($0) } ?? "",
                flowID: verifyReq.flowID,
                verifyRunID: verifyRunID,
                authenticatorData_sha256: authenticatorData.map(sha256Hex) ?? "",
                clientDataHash_sha256: clientDataHashSnapshot.map(sha256Hex) ?? "",
                signedBytes_sha256: signedBytesSnapshot.map(sha256Hex) ?? "",
                nonce_sha256: nonceSHA ?? "",
                signature_sha256: signatureData.map(sha256Hex) ?? "",
                publicKeyX963_sha256: publicKeySnapshot.map(sha256Hex) ?? "",
                signCount: signCountSnapshot,
                rpIdHash_ok: rpIdHashOk,
                ecdsa_digest_valid: ecdsaDigestValid ?? false,
                ecdsa_message_valid: ecdsaMessageValid ?? false,
                decision: decision,
                reject_reason: reject?.rawValue
            )
            if let enc = try? JSONEncoder().encode(canon), let js = String(data: enc, encoding: .utf8) {
                logger.info("VERIFICATION_CANONICAL \(js)")
            }
        }
        
        func reject(_ reason: RejectReason) -> VerifyResponse {
            logCanonical(decision: "REJECTED", reject: reason)
            return VerifyResponse(status: "rejected", reason: reason.rawValue, note: nil, firstDifferingByteIndex: nil, assertion_verification_policy: nil, mode: nil, signCount: nil, verifyRunID: verifyRunID, forensics: nil)
        }
        
        do { keyIDBytes = try KeyID.decodeBase64(verifyReq.keyID) }
        catch { 
            logger.error("VERIFY keyID decode failed", metadata: ["keyID": .string(verifyReq.keyID)])
            return reject(.IDENTITY_MISMATCH) 
        }
        guard let decodedKeyID = keyIDBytes else {
            logger.error("VERIFY keyID bytes are nil after decode", metadata: ["keyID": .string(verifyReq.keyID)])
            return reject(.IDENTITY_MISMATCH)
        }
        
        guard let storageKey = makeStorageKey(keyIDBytes: decodedKeyID, flowID: verifyReq.flowID) else { 
            logger.error("VERIFY storageKey creation failed", metadata: [
                "keyID_hex": .string(decodedKeyID.map { String(format: "%02x", $0) }.joined()),
                "flowID": .string(verifyReq.flowID)
            ])
            return reject(.IDENTITY_MISMATCH) 
        }
        
        // Consume challenge and validate challenge_id
        let storedChallenge: Data
        switch ChallengeStore.consumeChallenge(challengeID: verifyReq.challenge_id, keyIDBytes: decodedKeyID, flowID: verifyReq.flowID, logger: logger) {
        case .success(let challenge):
            storedChallenge = challenge
        case .expired: return reject(.EXPIRED_CHALLENGE)
        case .reused: return reject(.REPLAYED_CHALLENGE)
        case .missing:
            logger.error("VERIFY challenge missing", metadata: [
                "challenge_id": .string(verifyReq.challenge_id),
                "keyID_hex": .string(decodedKeyID.map { String(format: "%02x", $0) }.joined()),
                "flowID": .string(verifyReq.flowID)
            ])
            return reject(.CLIENT_DATA_HASH_NOT_FOUND)
        case .keyIDMismatch, .flowIDMismatch:
            return reject(.IDENTITY_MISMATCH)
        }
        
        // Decode clientData from base64
        guard let clientDataBytes = Data(base64Encoded: verifyReq.clientData_base64) else {
            logger.error("VERIFY clientData_base64 decode failed")
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        let clientDataSnapshot = clientDataBytes // For canonical logging
        
        // Parse clientData JSON and validate challenge
        guard let clientDataJSON = try? JSONSerialization.jsonObject(with: clientDataBytes) as? [String: Any] else {
            logger.error("VERIFY clientData JSON parse failed")
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        
        // Validate challenge in clientData matches stored challenge
        let clientDataChallengeBase64: String?
        if let challengeStr = clientDataJSON["challenge"] as? String {
            clientDataChallengeBase64 = challengeStr
        } else if let challengeB64 = clientDataJSON["challenge_b64"] as? String {
            clientDataChallengeBase64 = challengeB64
        } else {
            logger.error("VERIFY clientData missing challenge field")
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        
        guard let clientDataChallengeB64 = clientDataChallengeBase64,
              let clientDataChallenge = Data(base64Encoded: clientDataChallengeB64),
              clientDataChallenge == storedChallenge else {
            logger.error("VERIFY clientData challenge mismatch", metadata: [
                "stored_challenge_sha256": .string(sha256Hex(storedChallenge)),
                "clientData_challenge_b64": .string(clientDataChallengeBase64 ?? "nil")
            ])
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        
        // Validate challenge_id in clientData (if present)
        if let clientDataChallengeID = clientDataJSON["challenge_id"] as? String,
           clientDataChallengeID != verifyReq.challenge_id {
            logger.error("VERIFY clientData challenge_id mismatch", metadata: [
                "request_challenge_id": .string(verifyReq.challenge_id),
                "clientData_challenge_id": .string(clientDataChallengeID)
            ])
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        
        // Validate bundle_id if present
        if let bundleID = ProcessInfo.processInfo.environment["APP_BUNDLE_ID"],
           let clientDataBundleID = clientDataJSON["origin"] as? String,
           clientDataBundleID != bundleID {
            logger.warning("VERIFY clientData bundle_id mismatch", metadata: [
                "expected": .string(bundleID),
                "clientData_origin": .string(clientDataBundleID)
            ])
            // Don't reject, just log warning
        }
        
        // Validate flow_id if present
        if let clientDataFlowID = clientDataJSON["flow_id"] as? String,
           clientDataFlowID != verifyReq.flowID {
            logger.warning("VERIFY clientData flow_id mismatch", metadata: [
                "expected": .string(verifyReq.flowID),
                "clientData_flow_id": .string(clientDataFlowID)
            ])
            // Don't reject, just log warning
        }
        
        // Recompute clientDataHash from clientData bytes
        let clientDataHash = SHA256.hash(data: clientDataBytes)
        let clientDataHashData = Data(clientDataHash)
        clientDataHashSnapshot = clientDataHashData
        
        guard clientDataHashData.count == 32 else {
            logger.error("VERIFY clientDataHash invalid length", metadata: ["length": .string("\(clientDataHashData.count)")])
            return reject(.CLIENT_DATA_HASH_INVALID_LENGTH)
        }
        
        // Log clientData details
        logger.info("VERIFY_CLIENT_DATA [clientData_length: \(clientDataBytes.count), clientData_sha256: \(sha256Hex(clientDataBytes)), clientDataHash_hex: \(dataToHex(clientDataHashData)), clientDataHash_sha256: \(sha256Hex(clientDataHashData))]")
        
        guard let storedEntry = KeyStore.getPublicKey(keyIDBytes: decodedKeyID, flowID: verifyReq.flowID) else { 
            logger.error("VERIFY public key not found", metadata: [
                "keyID_hex": .string(decodedKeyID.map { String(format: "%02x", $0) }.joined()),
                "flowID": .string(verifyReq.flowID)
            ])
            return reject(.IDENTITY_MISMATCH) 
        }
        let publicKeyData = storedEntry.publicKey
        publicKeySnapshot = publicKeyData
        guard publicKeyData.count == 65, publicKeyData.first == 0x04 else { 
            logger.error("VERIFY public key invalid format", metadata: [
                "publicKey_length": .string("\(publicKeyData.count)"),
                "publicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil")
            ])
            return reject(.PUBLIC_KEY_INVALID) 
        }
        
        // Log the public key being used for verification (diagnostic - compare with REGISTER)
        logger.info("VERIFY_PUBKEY_USED [storedPublicKey_x963_len: \(publicKeyData.count), storedPublicKey_x963_hex_prefix: \(publicKeyData.prefix(10).map { String(format: "%02x", $0) }.joined()), storedPublicKey_x963_sha256: \(sha256Hex(publicKeyData)), source: \(storedEntry.source)]")
        
        // Validate public key format (hard-fail on actual bugs)
        guard publicKeyData.count == 65, publicKeyData[0] == 0x04 else {
            logger.error("BUG_DETECTED [stored public key has invalid format] [length: \(publicKeyData.count), firstByte: \(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil")]")
            return reject(.PUBLIC_KEY_INVALID)
        }
        
        // Check if public key is exactly 32 bytes (keyID length) - actual bug
        if publicKeyData.count == 32 {
            logger.error("BUG_DETECTED [stored public key is 32 bytes (keyID length) - keyID was used as public key]")
            return reject(.PUBLIC_KEY_INVALID)
        }
        
        // Check if public key starts with keyID bytes - actual bug
        if publicKeyData.count >= 32 && publicKeyData.prefix(32) == decodedKeyID {
            logger.error("BUG_DETECTED [stored public key starts with keyID bytes - keyID was padded into public key]")
            return reject(.PUBLIC_KEY_INVALID)
        }
        
        // Log keyID derivation check (keyID == SHA256(publicKey) is NORMAL)
        let computedKeyIDFromPubKey = Data(SHA256.hash(data: publicKeyData))
        if computedKeyIDFromPubKey == decodedKeyID {
            logger.info("KEYID_DERIVATION: keyIDHex == sha256(pubKeyX963) (expected) [keyID_hex: \(dataToHex(decodedKeyID)), pubKey_sha256: \(sha256Hex(publicKeyData))]")
        }
        
        guard let assertionObject = Data(base64Encoded: verifyReq.assertionObject_base64) else {
            logger.error("VERIFY assertionObject_base64 decode failed")
            return reject(.ASSERTION_CBOR_DECODE_FAILED)
        }
        
        // Decode CBOR assertion map
        let decodedAuthData: Data
        let decodedSignature: Data
        do {
            let cborValue = try CBORDecoder.decode(assertionObject)
            guard case .map(let pairs) = cborValue else { return reject(.ASSERTION_CBOR_DECODE_FAILED) }
            let map = Dictionary(uniqueKeysWithValues: pairs)
            if let v = map[.unsigned(1)]?.bytes { decodedAuthData = v }
            else if let v = map[.textString("authenticatorData")]?.bytes { decodedAuthData = v }
            else { return reject(.ASSERTION_MISSING_AUTHENTICATOR_DATA) }
            
            if let v = map[.unsigned(2)]?.bytes { decodedSignature = v }
            else if let v = map[.textString("signature")]?.bytes { decodedSignature = v }
            else { return reject(.ASSERTION_MISSING_SIGNATURE) }
        } catch {
            return reject(.ASSERTION_CBOR_DECODE_FAILED)
        }
        authenticatorData = decodedAuthData
        signatureData = decodedSignature
        
        // Construct signedBytes: authenticatorData || clientDataHash (raw Data append)
        let signedBytes = decodedAuthData + clientDataHashData
        signedBytesSnapshot = signedBytes
        
        // VERIFY_CANONICAL_ARTIFACTS: Freeze all inputs before any crypto API calls
        logger.info("VERIFY_CANONICAL_ARTIFACTS [storedPublicKey_sha256: \(sha256Hex(publicKeyData)), storedPublicKey_length: \(publicKeyData.count), authenticatorData_sha256: \(sha256Hex(decodedAuthData)), authenticatorData_length: \(decodedAuthData.count), clientDataHash_sha256: \(sha256Hex(clientDataHashData)), clientDataHash_length: \(clientDataHashData.count), signedBytes_sha256: \(sha256Hex(signedBytes)), signedBytes_length: \(signedBytes.count), signature_der_sha256: \(sha256Hex(decodedSignature)), signature_der_length: \(decodedSignature.count)]")
        
        // Validate signedBytes length
        guard signedBytes.count == decodedAuthData.count + 32 else {
            logger.error("VERIFY signedBytes length invalid", metadata: [
                "signedBytes.count": .string("\(signedBytes.count)"),
                "authenticatorData.count": .string("\(decodedAuthData.count)"),
                "expected": .string("\(decodedAuthData.count + 32)")
            ])
            return reject(.SIGNED_BYTES_LENGTH_INVALID)
        }
        
        // Log BACKEND_CANONICAL immediately after decoding (before any crypto)
        // Use raw keyID bytes for SHA256, not storage key
        let (pubKeyPrefix, pubKeySuffix) = hexPrefixSuffix(publicKeyData, n: 16)
        let canonical = AssertionVerifyCanonical(
            verifyRunID: verifyRunID,
            flowID: verifyReq.flowID,
            keyID_sha256: sha256Hex(decodedKeyID),
            publicKeyX963_length: publicKeyData.count,
            publicKeyX963_prefix1: publicKeyData.first.map { String(format: "%02x", $0) } ?? "00",
            publicKeyX963_sha256: sha256Hex(publicKeyData),
            publicKeyX963_hex_prefix: pubKeyPrefix,
            publicKeyX963_hex_suffix: pubKeySuffix,
            clientData_length: clientDataSnapshot.count,
            clientData_sha256: sha256Hex(clientDataSnapshot),
            clientDataHash_length: clientDataHashData.count,
            clientDataHash_hex: dataToHex(clientDataHashData),
            clientDataHash_sha256: sha256Hex(clientDataHashData),
            authenticatorData_length: decodedAuthData.count,
            authenticatorData_sha256: sha256Hex(decodedAuthData),
            signedBytes_length: signedBytes.count,
            signedBytes_sha256: sha256Hex(signedBytes),
            nonce_hex: nil, // Will be set after crypto computation
            nonce_sha256: nil, // Will be set after crypto computation
            signature_length: decodedSignature.count,
            signature_sha256: sha256Hex(decodedSignature),
            assertionObject_length: assertionObject.count,
            assertionObject_sha256: sha256Hex(assertionObject)
        )
        if let enc = try? JSONEncoder().encode(canonical), let js = String(data: enc, encoding: .utf8) {
            logger.info("BACKEND_CANONICAL \(js)")
        }
        
        guard !decodedSignature.isEmpty, decodedSignature.first == 0x30 else { return reject(.MALFORMED_SIGNATURE) }
        
        guard decodedAuthData.count >= 37 else { return reject(.ASSERTION_CBOR_DECODE_FAILED) }
        
        // rpIdHash binding
        guard let bundleID = ProcessInfo.processInfo.environment["APP_BUNDLE_ID"], !bundleID.isEmpty,
              let teamID = ProcessInfo.processInfo.environment["APP_TEAM_ID"], !teamID.isEmpty else { return reject(.IDENTITY_MISMATCH) }
        let appID = "\(teamID).\(bundleID)"
        let expectedRpIdHash = Data(SHA256.hash(data: Data(appID.utf8)))
        let rpIdHash = decodedAuthData.prefix(32)
        let rpOk = Data(rpIdHash) == expectedRpIdHash
        rpIdHashOk = rpOk
        guard rpOk else { return reject(.IDENTITY_MISMATCH) }
        
        // Extract counter from authenticatorData (bytes 33-36, big-endian)
        guard decodedAuthData.count >= 37 else {
            return reject(.ASSERTION_CBOR_DECODE_FAILED)
        }
        let signCount = UInt32(decodedAuthData[33]) << 24 | UInt32(decodedAuthData[34]) << 16 | UInt32(decodedAuthData[35]) << 8 | UInt32(decodedAuthData[36])
        signCountSnapshot = signCount
        
        // Check counter monotonicity
        if !KeyStore.checkSignCount(storageKey: storageKey, signCount: signCount) {
            logger.error("VERIFY counter not monotonic", metadata: [
                "signCount": .string("\(signCount)"),
                "storageKey": .string(storageKey)
            ])
            return reject(.REPLAYED_CHALLENGE) // Use REPLAYED_CHALLENGE for counter issues
        }
        
        // Verify signature DER parsing
        let signatureParsed: Bool
        do {
            _ = try P256.Signing.ECDSASignature(derRepresentation: decodedSignature)
            signatureParsed = true
        } catch {
            logger.error("VERIFY signature DER decode failed", metadata: [
                "signature_length": .string("\(decodedSignature.count)"),
                "signature_firstByte": .string(decodedSignature.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                "error": .string(error.localizedDescription)
            ])
            return reject(.SIGNATURE_DER_DECODE_FAILED)
        }
        
        if let providedPubKeyB64 = verifyReq.publicKey_x963_base64,
           let providedPubKey = Data(base64Encoded: providedPubKeyB64),
           providedPubKey != publicKeyData {
            return reject(.PUBKEY_MISMATCH)
        }
        if let providedSigB64 = verifyReq.signature_der_base64,
           let providedSig = Data(base64Encoded: providedSigB64),
           providedSig != decodedSignature {
            return reject(.SIGNATURE_MISMATCH)
        }
        
        if let hex = verifyReq.signedBytes_raw_hex {
            guard let fb = dataFromHex(hex) else { return reject(.SIGNED_BYTES_MISMATCH) }
            if fb != signedBytes {
            let idx = firstDifferingByteIndex(fb, signedBytes)
            let gt = buildForensics(
                requestID: req.headers.first(name: "x-request-id"),
                flowID: verifyReq.flowID,
                keyID_sha256: sha256Hex(KeyID.storageKey(decodedKeyID)),
                verifyRunID: verifyReq.verifyRunID,
                assertionObject: assertionObject,
                authenticatorData: decodedAuthData,
                signature: decodedSignature,
                storedClientDataHash: clientDataHashData,
                publicKeyX963: publicKeyData,
                signedMessage: signedBytes,
                errorCase: RejectReason.SIGNED_BYTES_MISMATCH.rawValue,
                recomputedSignedBytes_hex: signedBytes.map { String(format: "%02x", $0) }.joined(),
                recomputedSignedBytes_sha256: sha256Hex(signedBytes),
                frontendSignedBytes_hex: hex,
                frontendSignedBytes_sha256: sha256Hex(fb),
                signedBytesMatch: false,
                digestMatch: true,
                signatureParsed: signatureParsed,
                curve: "P-256",
                digest_algorithm: "SHA256"
            )
            logCanonical(decision: "REJECTED", reject: .SIGNED_BYTES_MISMATCH)
            return VerifyResponse(status: "rejected", reason: RejectReason.SIGNED_BYTES_MISMATCH.rawValue, note: nil, firstDifferingByteIndex: idx, assertion_verification_policy: nil, mode: nil, signCount: nil, verifyRunID: verifyRunID, forensics: gt)
            }
        }
        
        let cryptoResult = try verifyAssertionCrypto(authenticatorData: decodedAuthData, clientDataHash: clientDataHashData, signatureDER: decodedSignature, publicKeyX963: publicKeyData, logger: logger)
        ecdsaDigestValid = cryptoResult.ecdsaDigestValid
        ecdsaMessageValid = cryptoResult.ecdsaMessageValid
        nonceSHA = cryptoResult.nonceSHA256
        
        // Compute nonce for canonical logging (SHA256 of signedBytes)
        let nonceBytes = Data(SHA256.hash(data: cryptoResult.signedBytes))
        let nonceHex = dataToHex(nonceBytes)
        
        // Update canonical log with nonce after crypto computation
        let updatedCanonical = AssertionVerifyCanonical(
            verifyRunID: verifyRunID,
            flowID: verifyReq.flowID,
            keyID_sha256: sha256Hex(decodedKeyID),
            publicKeyX963_length: publicKeyData.count,
            publicKeyX963_prefix1: publicKeyData.first.map { String(format: "%02x", $0) } ?? "00",
            publicKeyX963_sha256: sha256Hex(publicKeyData),
            publicKeyX963_hex_prefix: pubKeyPrefix,
            publicKeyX963_hex_suffix: pubKeySuffix,
            clientData_length: clientDataSnapshot.count,
            clientData_sha256: sha256Hex(clientDataSnapshot),
            clientDataHash_length: clientDataHashData.count,
            clientDataHash_hex: dataToHex(clientDataHashData),
            clientDataHash_sha256: sha256Hex(clientDataHashData),
            authenticatorData_length: decodedAuthData.count,
            authenticatorData_sha256: sha256Hex(decodedAuthData),
            signedBytes_length: signedBytes.count,
            signedBytes_sha256: sha256Hex(signedBytes),
            nonce_hex: nonceHex,
            nonce_sha256: cryptoResult.nonceSHA256,
            signature_length: decodedSignature.count,
            signature_sha256: sha256Hex(decodedSignature),
            assertionObject_length: assertionObject.count,
            assertionObject_sha256: sha256Hex(assertionObject)
        )
        if let enc = try? JSONEncoder().encode(updatedCanonical), let js = String(data: enc, encoding: .utf8) {
            logger.info("BACKEND_CANONICAL_UPDATED \(js)")
        }
        
        // Log verification inputs and results (VERIFY must log these)
        let messageHashSHA256 = cryptoResult.nonceSHA256 // messageHash = SHA256(signedBytes)
        logger.info("VERIFY_VERIFICATION_RESULT [storedPublicKey_sha256: \(sha256Hex(publicKeyData)), signature_der_len: \(decodedSignature.count), signature_der_sha256: \(sha256Hex(decodedSignature)), signedBytes_len: \(cryptoResult.signedBytes.count), signedBytes_sha256: \(cryptoResult.signedBytesSHA256), messageHash_sha256: \(messageHashSHA256), swiftcrypto_result: \(ecdsaMessageValid), openssl_modeA: \(cryptoResult.opensslModeA?.description ?? "not_run"), openssl_modeB: \(cryptoResult.opensslModeB?.description ?? "not_run"), selected_mode: \(cryptoResult.selectedMode ?? "none")]")
        
        // FINAL VERDICT LOGIC (MANDATORY)
        let swiftcryptoResult = cryptoResult.ecdsaMessageValid
        let opensslModeA = cryptoResult.opensslModeA
        let opensslModeB = cryptoResult.opensslModeB
        let selectedMode = cryptoResult.selectedMode
        
        logger.info("ASSERTION_VERDICT [swiftcrypto: \(swiftcryptoResult), openssl_modeA: \(opensslModeA?.description ?? "not_run"), openssl_modeB: \(opensslModeB?.description ?? "not_run"), selected_mode: \(selectedMode ?? "none")]")
        
        // OpenSSL is ground truth when enabled
        if let modeA = opensslModeA, let modeB = opensslModeB {
            // Both modes were run
            if let selected = selectedMode {
                // Exactly one mode succeeded (or both, defaulting to A)
                let opensslSuccess = (selected == "A" && modeA) || (selected == "B" && modeB)
                if opensslSuccess {
                    // OpenSSL succeeded - accept, even if SwiftCrypto fails
                    if !swiftcryptoResult {
                        logger.error("SWIFTCRYPTO_MISMATCH_DETECTED [OpenSSL Mode \(selected) verified successfully but SwiftCrypto returned false - trusting OpenSSL]")
                    }
                    // Accept (OpenSSL is judge)
                } else {
                    // OpenSSL failed - reject, even if SwiftCrypto succeeds
                    if swiftcryptoResult {
                        logger.error("OPENSSL_MISMATCH_DETECTED [OpenSSL verification failed but SwiftCrypto returned true - trusting OpenSSL]")
                    }
                    logger.error("OPENSSL_VERIFICATION_FAILED [OpenSSL verification failed - assertion is invalid]")
                    return reject(.ECDSA_VERIFY_FAILED)
                }
            } else {
                // Neither mode succeeded
                logger.error("OPENSSL_VERIFICATION_FAILED [Both OpenSSL modes failed - assertion is invalid]")
                return reject(.ECDSA_VERIFY_FAILED)
            }
        } else {
            // OpenSSL not enabled - fall back to SwiftCrypto
            if mode == .strictECDSA && !swiftcryptoResult {
                return reject(.ECDSA_VERIFY_FAILED)
            }
        }
        
        KeyStore.updateSignCount(storageKey: storageKey, signCount: signCount)
        
        logCanonical(decision: "ACCEPTED", reject: nil)
        
        return VerifyResponse(
            status: "verified",
            reason: nil,
            note: nil,
            firstDifferingByteIndex: nil,
            assertion_verification_policy: mode.rawValue,
            mode: mode.rawValue,
            signCount: signCount,
            verifyRunID: verifyRunID,
            forensics: nil
        )
    }
    
    // Debug endpoint: POST /debug/assert-canonical (gated by APP_ATTEST_DEBUG_ASSERT=1)
    if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_ASSERT"] == "1" {
        app.post("debug", "assert-canonical") { req -> Response in
            struct DebugAssertRequest: Content {
                let flowID: String
                let keyID: String
                let assertionObject_base64: String
            }
            
            let logger = req.logger
            let debugReq = try req.content.decode(DebugAssertRequest.self)
            
            guard let keyIDBytes = try? KeyID.decodeBase64(debugReq.keyID) else {
                return Response(status: .badRequest, body: .init(string: "Invalid keyID"))
            }
            
            guard let storageKey = makeStorageKey(keyIDBytes: keyIDBytes, flowID: debugReq.flowID) else {
                return Response(status: .badRequest, body: .init(string: "Invalid storageKey"))
            }
            
            guard let storedEntry = KeyStore.getPublicKey(keyIDBytes: keyIDBytes, flowID: debugReq.flowID) else {
                return Response(status: .notFound, body: .init(string: "Public key not found"))
            }
            let publicKeyData = storedEntry.publicKey
            
            // Debug endpoint removed - use /debug/assertion-verify instead
            return Response(status: .notFound, body: .init(string: "Debug endpoint removed - use /debug/assertion-verify"))
        }
    }
}
