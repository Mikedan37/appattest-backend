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

struct KeyStore {
    static let keysDirectory = "/opt/appattest/keys"
    
    /// Stores public key bytes by keyID to server-side store.
    /// - Parameters:
    ///   - keyID: The key identifier (base64 string, may contain / or +)
    ///   - publicKey: Raw 65-byte uncompressed public key (0x04 || X || Y)
    /// - Returns: true if stored successfully, false otherwise
    static func storePublicKey(keyID: String, publicKey: Data) -> Bool {
        // Validate format: must be 65 bytes and start with 0x04
        guard publicKey.count == 65, publicKey[0] == 0x04 else {
            return false
        }
        
        // Sanitize keyID for filesystem (replace invalid chars with safe alternatives)
        // Base64 can contain: A-Z, a-z, 0-9, +, /, =
        // Filesystem-safe: A-Z, a-z, 0-9, -, _
        let sanitizedKeyID = keyID
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
        
        // Ensure directory exists with proper permissions
        let fileManager = FileManager.default
        do {
            if !fileManager.fileExists(atPath: keysDirectory) {
                try fileManager.createDirectory(atPath: keysDirectory, withIntermediateDirectories: true, attributes: [
                    .posixPermissions: 0o700
                ])
            }
        } catch {
            // Directory creation failed - log and return false
            print("ERROR: Failed to create keys directory: \(error)")
            return false
        }
        
        let keyPath = "\(keysDirectory)/\(sanitizedKeyID).pub"
        let keyBase64 = publicKey.base64EncodedString()
        
        guard let keyData = keyBase64.data(using: .utf8) else {
            print("ERROR: Failed to encode public key as UTF-8")
            return false
        }
        
        do {
            // Use atomic write to prevent corruption
            try keyData.write(to: URL(fileURLWithPath: keyPath), options: [.atomic])
            return true
        } catch {
            // Log the actual error for debugging
            let currentUser = ProcessInfo.processInfo.environment["USER"] ?? "unknown"
            print("ERROR: Failed to write key file '\(keyPath)': \(error)")
            print("  - Directory exists: \(fileManager.fileExists(atPath: keysDirectory))")
            print("  - Directory writable: \(fileManager.isWritableFile(atPath: keysDirectory))")
            print("  - Current user: \(currentUser)")
            print("  - Sanitized keyID: \(sanitizedKeyID)")
            return false
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
        
        let keyPath = "\(keysDirectory)/\(sanitizedKeyID).pub"
        
        guard let keyData = try? Data(contentsOf: URL(fileURLWithPath: keyPath)),
              let keyBase64 = String(data: keyData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let publicKey = Data(base64Encoded: keyBase64) else {
            return nil
        }
        
        // Validate format: must be 65 bytes and start with 0x04
        guard publicKey.count == 65, publicKey[0] == 0x04 else {
            return nil
        }
        
        return publicKey
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
            guard KeyStore.storePublicKey(keyID: registerReq.keyID, publicKey: publicKeyData) else {
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
            
            // Log assertion structure for debugging
            logger.info("Received assertion", metadata: [
                "keyID": "\(verifyReq.keyID)",
                "assertionLength": "\(assertionObject.count)",
                "firstBytes": "\(assertionObject.prefix(10).map { String(format: "%02x", $0) }.joined(separator: " "))"
            ])
            
            // CRITICAL: Log exact bytes being used for verification
            // These must match exactly what was used during assertion generation
            let clientDataHashHex = clientDataHash.map { String(format: "%02x", $0) }.joined()
            logger.info("Byte fidelity check", metadata: [
                "keyID": "\(verifyReq.keyID)",
                "clientDataHashLength": "\(clientDataHash.count)",
                "clientDataHashHex": "\(clientDataHashHex)",
                "clientDataHashBase64": "\(verifyReq.clientDataHash)"
            ])
            
            // 3. Decode App Attest assertion (CBOR map, not COSE_Sign1)
            // App Attest assertions are CBOR maps: { "authenticatorData": <bytes>, "signature": <bytes> }
            // NOT COSE_Sign1 arrays: [ protected, unprotected, payload, signature ]
            // Apple deliberately uses maps so servers must reconstruct Sig_structure server-side
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
            
            // 4. Construct signedBytes for App Attest verification
            // App Attest signs over raw concatenation: authenticatorData || clientDataHash
            // NOT a CBOR-wrapped COSE Sig_structure. Apple signs the raw bytes directly.
            // CRITICAL: Use EXACT bytes as received - do NOT recompute, rehash, or modify
            let payload = authenticatorData + clientDataHash
            
            // Compute payload hash for logging
            let payloadHash = SHA256.hash(data: payload)
            let payloadHashHex = payloadHash.map { String(format: "%02x", $0) }.joined()
            
            // Log payload for verification
            logger.info("App Attest signed bytes", metadata: [
                "keyID": "\(verifyReq.keyID)",
                "authenticatorDataLength": "\(authenticatorData.count)",
                "clientDataHashLength": "\(clientDataHash.count)",
                "payloadLength": "\(payload.count)",
                "payloadHash": "\(payloadHashHex)",
                "authenticatorDataFirst16": "\(authenticatorData.prefix(16).map { String(format: "%02x", $0) }.joined())",
                "clientDataHashHex": "\(clientDataHash.map { String(format: "%02x", $0) }.joined())"
            ])
            
            // For App Attest, the validator should hash the raw payload (what Apple signed)
            // Not a CBOR-wrapped structure
            let sigStructure = payload
            
            // Convert signature to ASN.1 DER format
            // App Attest signatures can be either:
            //  1. Raw ES256: 64 bytes (32 bytes r + 32 bytes s) → convert to DER
            //  2. ASN.1 DER: variable length (70-72 bytes), starts with 0x30 → use as-is
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
            
            // Helper to convert Data to hex string
            func hex(_ data: Data) -> String {
                data.map { String(format: "%02x", $0) }.joined()
            }
            
            // CRITICAL: Log exact bytes used for verification (autopsy logging)
            // This will reveal any byte-level mismatches
            print("=== VERIFICATION BYTES (AUTOPSY) ===")
            print("authenticatorData: \(hex(authenticatorData))")
            print("clientDataHash: \(hex(clientDataHash))")
            print("payload: \(hex(payload))")
            print("sigStructure: \(hex(sigStructure))")
            print("signature (raw): \(hex(signature))")
            print("signatureDER: \(hex(signatureDER))")
            print("publicKeyRaw: \(hex(publicKeyData))")
            print("authenticatorData length: \(authenticatorData.count)")
            print("clientDataHash length: \(clientDataHash.count)")
            print("payload length: \(payload.count)")
            print("sigStructure length: \(sigStructure.count)")
            print("signature length: \(signature.count)")
            print("signatureDER length: \(signatureDER.count)")
            print("publicKeyRaw length: \(publicKeyData.count)")
            print("payload hash: \(payloadHashHex)")
            print("sigStructure (raw payload) first 16 bytes: \(hex(sigStructure.prefix(16)))")
            print("=====================================")
            
            // 5. Create AssertionValidationContext
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
                    "payloadHash": "\(payloadHashHex)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid validation context"
                )
            }
            
            // 6. Call AssertionValidator.validate(context:)
            let validationResult = AssertionValidator.validate(context)
            
            // 7. Decision Logic (trust decisions happen here, not in validator)
            switch validationResult {
            case .verified:
                logger.info("Assertion verified", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "payloadHash": "\(payloadHashHex)"
                ])
                return VerifyResponse(
                    status: "verified",
                    reason: nil
                )
                
            case .failed:
                logger.info("Assertion rejected: signature invalid", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "payloadHash": "\(payloadHashHex)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "signature invalid"
                )
                
            case .cannotValidate(let reason):
                logger.info("Assertion rejected: cannot validate", metadata: [
                    "keyID": "\(verifyReq.keyID)",
                    "payloadHash": "\(payloadHashHex)",
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
