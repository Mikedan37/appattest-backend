//
//  main.swift
//  AppAttestBackend
//
//  Vapor backend service for App Attest assertion verification.
//  Endpoint: POST /app-attest/verify
//

import Foundation
import Vapor
import Crypto
import AppAttestCore
import AppAttestValidator

// MARK: - Request/Response Models

struct VerifyRequest: Content {
    let keyID: String
    let assertionObject: String  // base64
    let clientDataHash: String    // base64
}

struct VerifyResponse: Content {
    let status: String  // "verified" | "rejected"
    let reason: String?
}

struct RegisterRequest: Content {
    let keyID: String
    let attestationObject: String  // base64
    let clientDataHash: String    // base64
}

struct RegisterResponse: Content {
    let status: String  // "registered" | "rejected"
    let reason: String?
}

struct HealthResponse: Content {
    let status: String
}

// MARK: - COSE Key Extraction

/// Extracts P-256 public key from COSE key structure.
/// Returns uncompressed format: 0x04 || X || Y (65 bytes)
private func extractPublicKeyFromCOSEKey(_ coseKey: CBORValue) -> Data? {
    guard case .map(let pairs) = coseKey else {
        return nil
    }
    
    var xData: Data? = nil
    var yData: Data? = nil
    
    // Extract x and y coordinates from COSE key map
    // COSE key labels: -2 = x, -3 = y
    for (key, value) in pairs {
        if case .negative(-2) = key, case .byteString(let xBytes) = value {
            xData = xBytes
        } else if case .negative(-3) = key, case .byteString(let yBytes) = value {
            yData = yBytes
        }
    }
    
    guard let x = xData, let y = yData else {
        return nil
    }
    
    // Validate P-256: each coordinate should be 32 bytes
    guard x.count == 32, y.count == 32 else {
        return nil
    }
    
    // Format as uncompressed: 0x04 || X || Y
    var publicKey = Data([0x04])
    publicKey.append(x)
    publicKey.append(y)
    
    return publicKey
}

// MARK: - ASN.1 DER Encoding Helpers

/// Encodes a 32-byte integer as ASN.1 DER INTEGER
private func encodeASN1Integer(_ data: Data) -> Data {
    var result = Data()
    result.append(0x02) // INTEGER tag
    
    // Remove leading zeros, but keep at least one byte if all zeros
    var trimmed = data
    while trimmed.count > 1 && trimmed[0] == 0 && (trimmed[1] & 0x80) == 0 {
        trimmed = trimmed.dropFirst()
    }
    
    // If high bit is set, prepend zero byte to indicate positive number
    if trimmed[0] & 0x80 != 0 {
        var withSign = Data([0x00])
        withSign.append(trimmed)
        trimmed = withSign
    }
    
    // Encode length
    if trimmed.count < 128 {
        result.append(UInt8(trimmed.count))
    } else {
        let lengthBytes = encodeLength(trimmed.count)
        result.append(0x80 | UInt8(lengthBytes.count))
        result.append(contentsOf: lengthBytes)
    }
    
    result.append(trimmed)
    return result
}

/// Encodes a length value for ASN.1 DER
private func encodeLength(_ length: Int) -> Data {
    if length < 128 {
        return Data([UInt8(length)])
    }
    
    var bytes = Data()
    var value = length
    while value > 0 {
        bytes.insert(UInt8(value & 0xFF), at: 0)
        value >>= 8
    }
    return bytes
}

// MARK: - Key Store

/// In-memory key storage for App Attest public keys.
///
/// **Why RAM-backed storage:**
/// - This backend is a minimal validation layer, not a production service
/// - Eliminates filesystem dependencies and permission issues during development
/// - Keys are ephemeral and reset on server restart (intentional for testing)
///
/// **Production note:** For production deployments, replace with persistent storage:
/// - Database (PostgreSQL, SQLite, etc.)
/// - Filesystem with proper permissions
/// - Key management service (AWS KMS, HashiCorp Vault, etc.)
///
/// **Thread safety:** All access is serialized through a DispatchQueue to prevent race conditions.
struct KeyStore {
    /// In-memory dictionary: keyID (sanitized) → public key (65 bytes, uncompressed: 0x04 || X || Y)
    private static var keyStore: [String: Data] = [:]
    /// Serial queue for thread-safe access to keyStore
    private static let keyStoreQueue = DispatchQueue(label: "appattest.keystore")
    
    /// Stores public key bytes by keyID to server-side store.
    /// Registration is idempotent: re-registering the same keyID is allowed.
    /// - Parameters:
    ///   - keyID: The key identifier (base64 string, may contain / or +)
    ///   - publicKey: Raw 65-byte uncompressed public key (0x04 || X || Y)
    ///   - logger: Logger instance for debug output (optional)
    /// - Returns: true if stored successfully, false otherwise
    static func storePublicKey(keyID: String, publicKey: Data, logger: Logger? = nil) -> Bool {
        // Validate format: must be 65 bytes (uncompressed P-256: 0x04 || X || Y)
        guard publicKey.count == 65, publicKey[0] == 0x04 else {
            logger?.warning("Invalid public key format", metadata: [
                "keyID": "\(keyID)",
                "length": "\(publicKey.count)",
                "firstByte": "\(publicKey.first.map { String(format: "0x%02x", $0) } ?? "nil")"
            ])
            return false
        }
        
        // Sanitize keyID (for consistency, though not needed for in-memory storage)
        let sanitizedKeyID = keyID
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        
        // Store in memory (thread-safe, idempotent)
        return keyStoreQueue.sync {
            // Idempotency: re-registering the same keyID with the same public key is allowed
            if let existingKey = keyStore[sanitizedKeyID] {
                if existingKey == publicKey {
                    // Same key, same keyID - idempotent operation succeeds
                    return true
                } else {
                    // Key rotation: different public key for same keyID (overwrite)
                    logger?.info("Key rotation detected", metadata: ["keyID": "\(sanitizedKeyID)"])
                }
            }
            
            keyStore[sanitizedKeyID] = publicKey
            logger?.info("Public key stored", metadata: [
                "keyID": "\(sanitizedKeyID)",
                "totalKeys": "\(keyStore.count)"
            ])
            return true
        }
    }
    
    /// Fetches public key bytes by keyID from server-side store.
    /// - Parameter keyID: The key identifier (base64 string, may contain / or +)
    /// - Returns: Raw 65-byte uncompressed public key (0x04 || X || Y), or nil if not found/invalid
    static func getPublicKey(keyID: String) -> Data? {
        // Sanitize keyID same way as storePublicKey
        let sanitizedKeyID = keyID
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        
        // Retrieve from memory (thread-safe)
        return keyStoreQueue.sync {
            guard let publicKey = keyStore[sanitizedKeyID] else {
                return nil
            }
            
            // Validate format: must be 65 bytes and start with 0x04
            guard publicKey.count == 65, publicKey[0] == 0x04 else {
                return nil
            }
            
            return publicKey
        }
    }
}

// MARK: - Server Entry Point

@main
enum AppAttestBackend {
    static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)
        
        let app = try await Application.make(env)
        let logger = Logger(label: "appattest-backend")
        
        // Health endpoint
        app.get("health") { _ in
            HealthResponse(status: "ok")
        }
        
        // App Attest registration endpoint
        app.post("app-attest", "register") { req -> RegisterResponse in
            // 1. Decode request JSON
            let registerReq = try req.content.decode(RegisterRequest.self)
            
            // 2. Decode base64 inputs
            guard let attestationObject = Data(base64Encoded: registerReq.attestationObject),
                  let _ = Data(base64Encoded: registerReq.clientDataHash) else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Invalid base64 encoding"
                )
            }
            
            // 3. Decode attestation object using AppAttestDecoder
            let decodedAttestation: AttestationObject
            do {
                let decoder = AppAttestDecoder()
                decodedAttestation = try decoder.decodeAttestation(attestationObject)
            } catch {
                logger.warning("Failed to decode attestation", metadata: ["keyID": "\(registerReq.keyID)"])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to decode attestation object"
                )
            }
            
            // 4. Verify format is "apple-appattest"
            guard decodedAttestation.format == "apple-appattest" else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Invalid attestation format: expected 'apple-appattest'"
                )
            }
            
            // 5. Extract public key from credential data
            guard let credData = decodedAttestation.authenticatorData.attestedCredentialData else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Attestation missing credential data"
                )
            }
            
            // Extract x and y coordinates from COSE key
            guard let publicKeyData = extractPublicKeyFromCOSEKey(credData.credentialPublicKey) else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to extract public key from COSE key structure"
                )
            }
            
            // 6. Store keyID → publicKey mapping
            guard KeyStore.storePublicKey(keyID: registerReq.keyID, publicKey: publicKeyData, logger: logger) else {
                logger.warning("Failed to store public key", metadata: ["keyID": "\(registerReq.keyID)"])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to store public key"
                )
            }
            
            logger.info("Key registered", metadata: ["keyID": "\(registerReq.keyID)"])
            return RegisterResponse(
                status: "registered",
                reason: nil
            )
        }
        
        // App Attest verification endpoint
        app.post("app-attest", "verify") { req -> VerifyResponse in
            // 1. Decode request JSON
            let verifyReq = try req.content.decode(VerifyRequest.self)
            
            // 2. Look up the public key for keyID
            guard let publicKeyData = KeyStore.getPublicKey(keyID: verifyReq.keyID) else {
                logger.warning("Public key not found", metadata: ["keyID": "\(verifyReq.keyID)"])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Public key not found for keyID"
                )
            }
            
            // Convert raw public key to P256.Signing.PublicKey
            let publicKey: P256.Signing.PublicKey
            do {
                publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
            } catch {
                logger.warning("Invalid public key format", metadata: ["keyID": "\(verifyReq.keyID)"])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid public key format"
                )
            }
            
            // Decode base64 inputs
            guard let assertionObject = Data(base64Encoded: verifyReq.assertionObject),
                  let clientDataHash = Data(base64Encoded: verifyReq.clientDataHash) else {
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid base64 encoding"
                )
            }
            
            // Debug logging (metadata only, no private material)
            #if DEBUG
            logger.debug("Received assertion", metadata: [
                "keyID": "\(verifyReq.keyID)",
                "assertionLength": "\(assertionObject.count)",
                "clientDataHashLength": "\(clientDataHash.count)"
            ])
            #endif
            
            // 3. Decode App Attest assertion (CBOR map, NOT COSE_Sign1)
            //
            // **Critical protocol detail:**
            // App Attest assertions are CBOR maps: { "authenticatorData": <bytes>, "signature": <bytes> }
            // They are NOT raw COSE_Sign1 arrays: [ protected, unprotected, payload, signature ]
            //
            // **Why Apple uses maps instead of COSE_Sign1:**
            // - Forces servers to reconstruct the signed bytes server-side
            // - Prevents clients from lying about the payload
            // - Maintains strict trust boundaries (server is the authority)
            //
            // **What this means:**
            // The backend must extract authenticatorData and signature, then reconstruct
            // the exact bytes Apple signed: authenticatorData || clientDataHash
            let authenticatorData: Data
            let signature: Data
            
            do {
                // Decode as CBOR map (not COSE_Sign1 array)
                let cborValue = try AppAttestCore.CBORDecoder.decode(assertionObject)
                guard case .map(let mapPairs) = cborValue else {
                    return VerifyResponse(
                        status: "rejected",
                        reason: "Invalid assertion format: expected CBOR map"
                    )
                }
                
                let map = Dictionary(uniqueKeysWithValues: mapPairs)
                
                // Extract authenticatorData
                guard let authDataValue = map[.textString("authenticatorData")] ?? map[.textString("authData")],
                      let authData = authDataValue.bytes else {
                    return VerifyResponse(
                        status: "rejected",
                        reason: "Missing or invalid authenticatorData in assertion"
                    )
                }
                authenticatorData = authData
                
                // Extract signature (raw ECDSA signature, not COSE format)
                guard let sigValue = map[.textString("signature")],
                      let sig = sigValue.bytes else {
                    return VerifyResponse(
                        status: "rejected",
                        reason: "Missing or invalid signature in assertion"
                    )
                }
                signature = sig
                
            } catch {
                logger.warning("Failed to decode assertion map", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "assertionLength": "\(assertionObject.count)",
                    "error": "\(error.localizedDescription)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Failed to decode assertion object: \(error.localizedDescription)"
                )
            }
            
            // 4. Construct the exact bytes Apple signed (raw payload)
            //
            // **App Attest signature payload:**
            // Apple signs over raw concatenation: authenticatorData || clientDataHash
            // This is NOT a CBOR-wrapped COSE Sig_structure.
            //
            // **Why NOT CBOR Sig_structure:**
            // COSE defines Sig_structure as: ["Signature1", protected_headers, external_aad, payload]
            // App Attest deliberately avoids this format to force server-side reconstruction.
            // The server must verify against the exact bytes Apple signed, not a wrapped structure.
            //
            // **CRITICAL:** Use EXACT bytes as received - do NOT:
            // - Recompute clientDataHash (use the exact bytes from the request)
            // - Rehash the payload (CryptoKit will hash internally)
            // - Modify or normalize any bytes
            let payload = authenticatorData + clientDataHash
            
            // Debug logging (payload metadata only, no private material)
            #if DEBUG
            let payloadHash = SHA256.hash(data: payload)
            let payloadHashHex = payloadHash.map { String(format: "%02x", $0) }.joined()
            logger.debug("App Attest payload construction", metadata: [
                "keyID": "\(verifyReq.keyID)",
                "authenticatorDataLength": "\(authenticatorData.count)",
                "clientDataHashLength": "\(clientDataHash.count)",
                "payloadLength": "\(payload.count)",
                "payloadHash": "\(payloadHashHex)"
            ])
            #endif
            
            // Pass raw payload to validator (CryptoKit will hash it internally)
            let sigStructure = payload
            
            // 5. Normalize signature to ASN.1 DER format
            //
            // **Signature format handling:**
            // App Attest signatures can arrive in two formats:
            //   1. Raw ES256: 64 bytes (32 bytes r || 32 bytes s) → convert to DER
            //   2. ASN.1 DER: variable length (70-72 bytes), starts with 0x30 → use as-is
            //
            // CryptoKit requires ASN.1 DER format, so we normalize here.
            let signatureDER: Data
            
            if signature.count == 64 {
                // Raw r||s format → convert to ASN.1 DER
                // Split into r and s components (32 bytes each)
                let r = signature.prefix(32)
                let s = signature.suffix(32)
                
                // Encode as ASN.1 DER SEQUENCE { INTEGER r, INTEGER s }
                var der = Data()
                der.append(0x30) // SEQUENCE tag
                
                // Calculate total length
                let rDER = encodeASN1Integer(r)
                let sDER = encodeASN1Integer(s)
                let totalLength = rDER.count + sDER.count
                
                if totalLength < 128 {
                    der.append(UInt8(totalLength))
                } else {
                    // Long form length encoding
                    let lengthBytes = encodeLength(totalLength)
                    der.append(0x80 | UInt8(lengthBytes.count))
                    der.append(contentsOf: lengthBytes)
                }
                
                der.append(contentsOf: rDER)
                der.append(contentsOf: sDER)
                
                signatureDER = der
            } else if signature.first == 0x30 {
                // Already ASN.1 DER format (starts with SEQUENCE tag 0x30)
                signatureDER = signature
            } else {
                // Invalid signature format
                let firstBytes = signature.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " ")
                logger.warning("Invalid signature format", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "signatureLength": "\(signature.count)",
                    "firstBytes": "\(firstBytes)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid signature format: length \(signature.count) bytes, first byte: \(signature.first.map { String(format: "%02x", $0) } ?? "nil")"
                )
            }
            
            // 6. Create validation context
            let context: AssertionValidationContext
            do {
                context = try AssertionValidationContext(
                    publicKey: publicKey,
                    sigStructure: sigStructure,
                    signatureDER: signatureDER
                )
            } catch {
                logger.warning("Failed to create validation context", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "error": "\(error.localizedDescription)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid validation context: \(error.localizedDescription)"
                )
            }
            
            // 7. Perform cryptographic verification
            //
            // **Verification process:**
            // - AssertionValidator receives raw payload bytes (sigStructure)
            // - CryptoKit's isValidSignature(_:for: Data) hashes the payload internally
            // - ECDSA signature is verified against the public key
            // - No double-hashing: we pass raw bytes, CryptoKit does the SHA256
            let validationResult = AssertionValidator.validate(context)
            
            // 8. Return verification result (no policy checks, pure crypto result)
            switch validationResult {
            case .verified:
                logger.info("Assertion verified", metadata: [
                    "keyID": "\(verifyReq.keyID)"
                ])
                return VerifyResponse(
                    status: "verified",
                    reason: nil
                )
                
            case .failed(let reason):
                logger.warning("Assertion rejected", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "reason": "\(reason)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: reason
                )
                
            case .cannotValidate(let reason):
                logger.warning("Assertion cannot be validated", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "reason": "\(reason)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: reason
                )
            }
        }
        
        // Configure to listen on 0.0.0.0:8080 (LAN accessible)
        app.http.server.configuration.hostname = "0.0.0.0"
        app.http.server.configuration.port = 8080
        
        try await app.execute()
    }
}
