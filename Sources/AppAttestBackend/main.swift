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
    let flowID: String?  // UUID from register response (optional for backward compatibility)
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
    let flowID: String?  // UUID for correlating register/verify
}

struct HealthResponse: Content {
    let status: String
    let buildSha256: String?
    let buildTime: String?
    
    init(status: String, buildSha256: String? = nil, buildTime: String? = nil) {
        self.status = status
        self.buildSha256 = buildSha256
        self.buildTime = buildTime
    }
}

// MARK: - COSE Key Extraction

/// Extracts P-256 public key from COSE key structure.
/// Returns uncompressed format: 0x04 || X || Y (65 bytes)
func extractPublicKeyFromCOSEKey(_ coseKey: CBORValue) -> Data? {
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

// MARK: - Forensic Dump and OpenSSL Verification

/// Constructs COSE Sig_structure CBOR array: ["Signature1", protected, external_aad, payload]
/// Constructs COSE Sig_structure as CBOR array
/// Sig_structure = [
///   "Signature1",        // text string (item 0)
///   body_protected : bstr,    // byte string (item 1) - contains CBOR encoding of protected headers
///   external_aad : bstr, // byte string (item 2) - NOT a map!
///   payload : bstr       // byte string (item 3)
/// ]
/// CRITICAL COSE GOTCHA: body_protected is a bstr containing the CBOR encoding of protected headers.
/// - If protected headers are empty map {}, then body_protected = h'A0' (CBOR empty map is 0xA0)
/// - NOT h'' (truly empty byte string)
/// - This is the #1 reason COSE Sig_structure verification fails silently
func constructCOSESigStructure(protected: Data, externalAAD: Data, payload: Data) -> Data {
    // CBOR encode: array of 4 items
    var cbor: [UInt8] = []
    
    // Array tag (4 items)
    cbor.append(0x84) // array(4)
    
    // Item 0: "Signature1" (text string, 10 bytes)
    cbor.append(0x6a) // text string(10)
    cbor.append(contentsOf: "Signature1".utf8)
    
    // Item 2: protected (byte string)
    let protectedLen = protected.count
    if protectedLen < 24 {
        cbor.append(0x40 + UInt8(protectedLen)) // byte string(protectedLen)
    } else if protectedLen < 256 {
        cbor.append(0x58) // byte string(24-bit)
        cbor.append(UInt8(protectedLen))
    } else {
        cbor.append(0x59) // byte string(16-bit)
        cbor.append(UInt8((protectedLen >> 8) & 0xFF))
        cbor.append(UInt8(protectedLen & 0xFF))
    }
    cbor.append(contentsOf: protected)
    
    // Item 3: external_aad (byte string)
    let aadLen = externalAAD.count
    if aadLen < 24 {
        cbor.append(0x40 + UInt8(aadLen)) // byte string(aadLen)
    } else if aadLen < 256 {
        cbor.append(0x58) // byte string(24-bit)
        cbor.append(UInt8(aadLen))
    } else {
        cbor.append(0x59) // byte string(16-bit)
        cbor.append(UInt8((aadLen >> 8) & 0xFF))
        cbor.append(UInt8(aadLen & 0xFF))
    }
    cbor.append(contentsOf: externalAAD)
    
    // Item 4: payload (byte string)
    let payloadLen = payload.count
    if payloadLen < 24 {
        cbor.append(0x40 + UInt8(payloadLen)) // byte string(payloadLen)
    } else if payloadLen < 256 {
        cbor.append(0x58) // byte string(24-bit)
        cbor.append(UInt8(payloadLen))
    } else {
        cbor.append(0x59) // byte string(16-bit)
        cbor.append(UInt8((payloadLen >> 8) & 0xFF))
        cbor.append(UInt8(payloadLen & 0xFF))
    }
    cbor.append(contentsOf: payload)
    
    return Data(cbor)
}

/// Dumps verification artifacts to /tmp/appattest/ for forensic analysis
/// This MUST execute unconditionally for every verify request
func dumpVerificationArtifacts(
    keyIDBytes: Data,
    assertionObject: Data,
    publicKey: Data,
    signatureDER: Data,
    message: Data,
    logger: Logger
) -> URL? {
    let dumpDir = URL(fileURLWithPath: "/tmp/appattest")
    
    do {
        // Create directory if missing (unconditionally, no guards)
        try FileManager.default.createDirectory(at: dumpDir, withIntermediateDirectories: true, attributes: nil)
        logger.error("VERIFY forensic dump directory created/verified", metadata: [
            "dumpDir": .string("/tmp/appattest")
        ])
        
        let keyIDHash = SHA256.hash(data: keyIDBytes)
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyyMMdd_HHmmss"
        let timestamp = dateFormatter.string(from: Date())
        let requestID = UUID().uuidString.prefix(8)
        let prefix = "\(timestamp)_\(requestID)_\(keyIDHash.prefix(8).map { String(format: "%02x", $0) }.joined())"
        
        // Construct COSE Sig_structure variants for forensic dump
        // CRITICAL: Test both protected variants (h'' and h'A0')
        let externalAAD = Data() // Empty external_aad
        let payload = message // message is already authenticatorData || clientDataHash
        
        let protectedEmpty = Data() // Empty byte string
        let sigStructureEmpty = constructCOSESigStructure(protected: protectedEmpty, externalAAD: externalAAD, payload: payload)
        
        let protectedA0 = Data([0xA0]) // CBOR empty map {} = 0xA0
        let sigStructureA0 = constructCOSESigStructure(protected: protectedA0, externalAAD: externalAAD, payload: payload)
        
        // Write artifacts - log each write with ERROR level so it can't be missed
        let keyIDFile = dumpDir.appendingPathComponent("\(prefix)_keyid.bytes")
        let assertionFile = dumpDir.appendingPathComponent("\(prefix)_assertion.cbor")
        let pubkeyFile = dumpDir.appendingPathComponent("\(prefix)_pubkey.x963")
        let pubkeyPEMFile = dumpDir.appendingPathComponent("\(prefix)_pubkey.pem")
        let signatureFile = dumpDir.appendingPathComponent("\(prefix)_signature.der")
        let messageFile = dumpDir.appendingPathComponent("\(prefix)_message.bin")
        let sigStructEmptyFile = dumpDir.appendingPathComponent("\(prefix)_sigstruct_protected_empty.cbor")
        let sigStructA0File = dumpDir.appendingPathComponent("\(prefix)_sigstruct_protected_a0.cbor")
        let metaFile = dumpDir.appendingPathComponent("\(prefix)_meta.txt")
        
        try keyIDBytes.write(to: keyIDFile)
        logger.error("VERIFY_DUMP wrote keyid.bytes", metadata: [
            "file": .string(keyIDFile.path),
            "len": .string("\(keyIDBytes.count)"),
            "sha256": .string(SHA256.hash(data: keyIDBytes).map { String(format: "%02x", $0) }.joined())
        ])
        
        try assertionObject.write(to: assertionFile)
        logger.error("VERIFY_DUMP wrote assertion.cbor", metadata: [
            "file": .string(assertionFile.path),
            "len": .string("\(assertionObject.count)"),
            "sha256": .string(SHA256.hash(data: assertionObject).map { String(format: "%02x", $0) }.joined())
        ])
        
        try publicKey.write(to: pubkeyFile)
        logger.error("VERIFY_DUMP wrote pubkey.x963", metadata: [
            "file": .string(pubkeyFile.path),
            "len": .string("\(publicKey.count)"),
            "sha256": .string(SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined())
        ])
        
        try signatureDER.write(to: signatureFile)
        logger.error("VERIFY_DUMP wrote signature.der", metadata: [
            "file": .string(signatureFile.path),
            "len": .string("\(signatureDER.count)"),
            "sha256": .string(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined())
        ])
        
        try message.write(to: messageFile)
        logger.error("VERIFY_DUMP wrote message.bin", metadata: [
            "file": .string(messageFile.path),
            "len": .string("\(message.count)"),
            "sha256": .string(SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined())
        ])
        
        // Convert X9.63 to PEM format for OpenSSL
        let pemData = convertX963ToPEM(publicKey: publicKey)
        try pemData.write(to: pubkeyPEMFile)
        logger.error("VERIFY_DUMP wrote pubkey.pem", metadata: [
            "file": .string(pubkeyPEMFile.path),
            "len": .string("\(pemData.count)")
        ])
        
        // Write both Sig_structure variants
        try sigStructureEmpty.write(to: sigStructEmptyFile)
        logger.error("VERIFY_DUMP wrote sigstruct_protected_empty.cbor", metadata: [
            "file": .string(sigStructEmptyFile.path),
            "len": "\(sigStructureEmpty.count)",
            "sha256": .string(SHA256.hash(data: sigStructureEmpty).map { String(format: "%02x", $0) }.joined())
        ])
        
        try sigStructureA0.write(to: sigStructA0File)
        logger.error("VERIFY_DUMP wrote sigstruct_protected_a0.cbor", metadata: [
            "file": .string(sigStructA0File.path),
            "len": "\(sigStructureA0.count)",
            "sha256": .string(SHA256.hash(data: sigStructureA0).map { String(format: "%02x", $0) }.joined()),
            "protected_is_a0": "\(sigStructureA0[13] == 0xA0 ? "true" : "false")" // Item 1 should be bstr(1) containing 0xA0
        ])
        
        // Write metadata as JSON
        let meta = """
        {
          "request_id": "\(requestID)",
          "keyID_bytes_length": \(keyIDBytes.count),
          "keyID_sha256": "\(keyIDHash.map { String(format: "%02x", $0) }.joined())",
          "assertionObject_length": \(assertionObject.count),
          "assertionObject_sha256": "\(SHA256.hash(data: assertionObject).map { String(format: "%02x", $0) }.joined())",
          "pubkey_length": \(publicKey.count),
          "pubkey_firstByte": "\(String(format: "0x%02x", publicKey[0]))",
          "pubkey_sha256": "\(SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined())",
          "signatureDER_length": \(signatureDER.count),
          "signatureDER_firstByte": "\(String(format: "0x%02x", signatureDER[0]))",
          "signatureDER_sha256": "\(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined())",
          "message_length": \(message.count),
          "message_sha256": "\(SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined())",
          "sigstruct_protected_empty_length": \(sigStructureEmpty.count),
          "sigstruct_protected_empty_sha256": "\(SHA256.hash(data: sigStructureEmpty).map { String(format: "%02x", $0) }.joined())",
          "sigstruct_protected_a0_length": \(sigStructureA0.count),
          "sigstruct_protected_a0_sha256": "\(SHA256.hash(data: sigStructureA0).map { String(format: "%02x", $0) }.joined())"
        }
        """
        try meta.write(to: metaFile, atomically: true, encoding: .utf8)
        logger.error("VERIFY forensic dump: meta.json written", metadata: [
            "file": .string(metaFile.path)
        ])
        
        logger.error("VERIFY_DUMP complete", metadata: [
            "allFiles": .string("keyid.bytes, assertion.cbor, pubkey.x963, pubkey.pem, signature.der, message.bin (raw payload), sigstruct_protected_empty.cbor, sigstruct_protected_a0.cbor, meta.txt"),
            "dumpDir": .string("/tmp/appattest"),
            "prefix": .string(prefix),
            "allFiles": .string("keyid.bytes, assertion.cbor, pubkey.x963, pubkey.pem, signature.der, message.bin (raw payload), sigstruct_protected_empty.cbor, sigstruct_protected_a0.cbor, meta.txt")
        ])
        
        return pubkeyPEMFile
    } catch {
        logger.error("VERIFY forensic dump failed", metadata: [
            "error": .string(error.localizedDescription),
            "dumpDir": "/tmp/appattest",
            "errno": "\(errno)"
        ])
        return nil
    }
}

/// Converts X9.63 uncompressed public key to PEM format
func convertX963ToPEM(publicKey: Data) -> Data {
    // X9.63: 0x04 || X[32] || Y[32] (65 bytes)
    // OpenSSL PEM needs ASN.1 SubjectPublicKeyInfo for prime256v1
    
    // Algorithm identifier for prime256v1 (ecPublicKey + prime256v1)
    let algorithmID: [UInt8] = [
        0x30, 0x13, // SEQUENCE, 19 bytes
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID: ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 // OID: prime256v1
    ]
    
    // Public key bit string: 0x04 || X || Y (uncompressed point)
    var bitString: [UInt8] = [0x03, 0x42, 0x00] // BIT STRING, 66 bytes, unused bits: 0
    bitString.append(contentsOf: publicKey) // 0x04 || X || Y
    
    // SPKI structure
    var spki: [UInt8] = [0x30] // SEQUENCE
    let totalLength = algorithmID.count + bitString.count
    if totalLength < 128 {
        spki.append(UInt8(totalLength))
    } else {
        let lenBytes = encodeLength(totalLength)
        spki.append(0x80 | UInt8(lenBytes.count))
        spki.append(contentsOf: lenBytes)
    }
    spki.append(contentsOf: algorithmID)
    spki.append(contentsOf: bitString)
    
    // Base64 encode and wrap in PEM
    let derData = Data(spki)
    let base64 = derData.base64EncodedString()
    
    var pem = "-----BEGIN PUBLIC KEY-----\n"
    var currentLine = ""
    for char in base64 {
        currentLine.append(char)
        if currentLine.count == 64 {
            pem += currentLine + "\n"
            currentLine = ""
        }
    }
    if !currentLine.isEmpty {
        pem += currentLine + "\n"
    }
    pem += "-----END PUBLIC KEY-----\n"
    
    return pem.data(using: .utf8) ?? Data()
}

/// Verifies signature using OpenSSL command-line tool
/// Returns (verified: Bool, exitCode: Int32, output: String)
func verifyWithOpenSSL(
    pubkeyPEM: URL,
    signatureDER: Data,
    message: Data,
    logger: Logger
) -> (verified: Bool, exitCode: Int32, output: String) {
    let tempDir = URL(fileURLWithPath: "/tmp/appattest")
    let sigFile = tempDir.appendingPathComponent("openssl_sig_\(UUID().uuidString).der")
    let msgFile = tempDir.appendingPathComponent("openssl_msg_\(UUID().uuidString).bin")
    
    defer {
        try? FileManager.default.removeItem(at: sigFile)
        try? FileManager.default.removeItem(at: msgFile)
    }
    
    do {
        try signatureDER.write(to: sigFile)
        try message.write(to: msgFile)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "dgst",
            "-sha256",
            "-verify", pubkeyPEM.path,
            "-signature", sigFile.path,
            msgFile.path
        ]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let trimmedOutput = output.trimmingCharacters(in: .whitespacesAndNewlines)
        
        let verified = process.terminationStatus == 0 && output.contains("Verified OK")
        
            logger.error("VERIFY_OPENSSL", metadata: [
                "command": .string("openssl dgst -sha256 -verify \(pubkeyPEM.path) -signature \(sigFile.path) \(msgFile.path)"),
                "verified": .string("\(verified)"),
                "exitCode": .string("\(process.terminationStatus)"),
                "output": .string(trimmedOutput.isEmpty ? "(empty)" : trimmedOutput)
            ])
        
        return (verified, process.terminationStatus, trimmedOutput)
    } catch {
        logger.error("VERIFY OpenSSL verification exception", metadata: [
            "error": .string(error.localizedDescription)
        ])
        return (false, -1, error.localizedDescription)
    }
}

// MARK: - ASN.1 DER Encoding Helpers

/// Encodes a 32-byte integer as ASN.1 DER INTEGER
func encodeASN1Integer(_ data: Data) -> Data {
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
func encodeLength(_ length: Int) -> Data {
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
/// **Key storage:** Uses raw keyID bytes (SHA256 hash) as the storage key to avoid base64 normalization bugs.

/// Key store entry containing public key and flowID for correlation
struct KeyStoreEntry {
    let publicKey: Data
    let flowID: String
}

struct KeyStore {
    /// In-memory dictionary: storageKey → KeyStoreEntry
    private static var keyStore: [Data: KeyStoreEntry] = [:]
    /// Serial queue for thread-safe access to keyStore
    private static let keyStoreQueue = DispatchQueue(label: "appattest.keystore")
    
    /// Converts keyID string to stable storage key using SHA256 hash of raw bytes.
    /// This avoids base64 normalization bugs (/, +, = handling differences).
    /// - Parameter keyID: The key identifier (base64 string)
    /// - Returns: SHA256 hash of keyID bytes as Data, or nil if keyID is invalid
    private static func keyIDToStorageKey(_ keyID: String) -> Data? {
        // Decode base64 keyID to raw bytes
        guard let keyIDBytes = Data(base64Encoded: keyID) else {
            // If base64 decode fails, try using UTF-8 bytes directly (fallback)
            let hash = SHA256.hash(data: keyID.data(using: .utf8) ?? Data())
            return Data(hash)
        }
        // Use SHA256 of raw bytes as stable storage key
        let hash = SHA256.hash(data: keyIDBytes)
        return Data(hash)
    }
    
    /// Stores public key bytes by keyID to server-side store with flowID for correlation.
    /// Registration is idempotent: re-registering the same keyID is allowed.
    /// - Parameters:
    ///   - keyIDBytes: Canonical keyID bytes (from KeyID.decodeBase64)
    ///   - publicKey: Raw 65-byte uncompressed public key (0x04 || X || Y)
    ///   - flowID: UUID for correlating register/verify
    ///   - logger: Logger instance for debug output (optional)
    /// - Returns: true if stored successfully, false otherwise
    static func storePublicKey(keyIDBytes: Data, publicKey: Data, flowID: String, logger: Logger? = nil) -> Bool {
        // Validate format: must be 65 bytes (uncompressed P-256: 0x04 || X || Y)
        guard publicKey.count == 65, publicKey[0] == 0x04 else {
            logger?.warning("REGISTER invalid public key format", metadata: [
                "keyID_bytes_length": .string("\(keyIDBytes.count)"),
                "publicKey_length": .string("\(publicKey.count)"),
                "publicKey_firstByte": .string(publicKey.first.map { String(format: "0x%02x", $0) } ?? "nil")
            ])
            return false
        }
        
        // Generate canonical storage key
        let storageKey = KeyID.storageKey(keyIDBytes)
        
        // Store in memory (thread-safe, idempotent)
        return keyStoreQueue.sync {
            let entry = KeyStoreEntry(publicKey: publicKey, flowID: flowID)
            
            // Idempotency: re-registering the same keyID with the same public key is allowed
            if let existing = keyStore[storageKey] {
                if existing.publicKey == publicKey {
                    // Same key, same keyID - idempotent operation succeeds
                    logger?.info("REGISTER key already stored (idempotent)", metadata: [
                        "keyID_sha256": .string(storageKey.map { String(format: "%02x", $0) }.joined()),
                        "publicKey_sha256": .string(SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()),
                        "flowID": .string(flowID)
                    ])
                    return true
                } else {
                    // Key rotation: different public key for same keyID (overwrite)
                    logger?.info("REGISTER key rotation detected", metadata: [
                        "keyID_sha256": .string(storageKey.map { String(format: "%02x", $0) }.joined()),
                        "oldPublicKey_sha256": .string(SHA256.hash(data: existing.publicKey).map { String(format: "%02x", $0) }.joined()),
                        "newPublicKey_sha256": .string(SHA256.hash(data: publicKey).map { String(format: "%02x", $0) }.joined()),
                        "oldFlowID": .string(existing.flowID),
                        "newFlowID": .string(flowID)
                    ])
                }
            }
            
            keyStore[storageKey] = entry
            let publicKeyHash = SHA256.hash(data: publicKey)
            logger?.info("REGISTER public key stored", metadata: [
                "keyID_sha256": .string(storageKey.map { String(format: "%02x", $0) }.joined()),
                "storedPublicKey_sha256": .string(publicKeyHash.map { String(format: "%02x", $0) }.joined()),
                "flowID": .string(flowID),
                "totalKeys": .string("\(keyStore.count)")
            ])
            return true
        }
    }
    
    /// Fetches public key and flowID by keyID from server-side store.
    /// - Parameter keyIDBytes: Canonical keyID bytes (from KeyID.decodeBase64)
    /// - Returns: (publicKey: Data, flowID: String) or nil if not found/invalid
    static func getPublicKey(keyIDBytes: Data) -> (publicKey: Data, flowID: String)? {
        // Generate canonical storage key
        let storageKey = KeyID.storageKey(keyIDBytes)
        
        // Retrieve from memory (thread-safe)
        return keyStoreQueue.sync {
            guard let entry = keyStore[storageKey] else {
                return nil
            }
            
            // Validate format: must be 65 bytes and start with 0x04
            guard entry.publicKey.count == 65, entry.publicKey[0] == 0x04 else {
                return nil
            }
            
            return (entry.publicKey, entry.flowID)
        }
    }
}

// MARK: - Single Validator Entrypoint

/// Single validator entrypoint - all verification must go through this function
/// - Parameters:
///   - publicKeyX963: 65-byte uncompressed public key (0x04 || X || Y)
///   - signatureDER: ASN.1 DER-encoded ECDSA signature
///   - message: Raw message bytes to verify (will be hashed internally by swift-crypto)
/// - Returns: true if signature verifies, false otherwise
func verifyAssertion(publicKeyX963: Data, signatureDER: Data, message: Data) -> Bool {
    // Hard invariants - fail fast
    guard publicKeyX963.count == 65, publicKeyX963[0] == 0x04 else {
        return false
    }
    guard signatureDER.count > 0, signatureDER[0] == 0x30 else {
        return false
    }
    guard message.count > 0 else {
        return false
    }
    
    do {
        // Create P256 public key from X9.63 representation
        let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        
        // Parse DER signature
        let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
        
        // Verify signature over message (swift-crypto hashes internally)
        return publicKey.isValidSignature(signature, for: message)
    } catch {
        return false
    }
}

// MARK: - Configuration

func configure(_ app: Application) throws {
    let logger = app.logger
    
    // CANARY: Prove routes are configured with this binary
    logger.critical("CANARY routes configured", metadata: [
        "version": .string("v1-matrix-2026-01-17"),
        "exe_path": .string(ProcessInfo.processInfo.arguments[0])
    ])
    
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
                    reason: "Invalid base64 encoding",
                    flowID: nil
                )
            }
            
            // 3. Decode attestation object using AppAttestDecoder
            let decodedAttestation: AttestationObject
            do {
                let decoder = AppAttestDecoder()
                decodedAttestation = try decoder.decodeAttestation(attestationObject)
            } catch {
                logger.warning("Failed to decode attestation", metadata: ["keyID": .string(registerReq.keyID)])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to decode attestation object",
                    flowID: nil
                )
            }
            
            // 4. Verify format is "apple-appattest"
            guard decodedAttestation.format == "apple-appattest" else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Invalid attestation format: expected 'apple-appattest'",
                    flowID: nil
                )
            }
            
            // 5. Extract public key from credential data
            guard let credData = decodedAttestation.authenticatorData.attestedCredentialData else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Attestation missing credential data",
                    flowID: nil
                )
            }
            
            // Extract x and y coordinates from COSE key
            guard let publicKeyData = extractPublicKeyFromCOSEKey(credData.credentialPublicKey) else {
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to extract public key from COSE key structure",
                    flowID: nil
                )
            }
            
            // Canonical keyID decoding
            let keyIDBytes: Data
            do {
                keyIDBytes = try KeyID.decodeBase64(registerReq.keyID)
            } catch {
                logger.warning("REGISTER invalid keyID format", metadata: [
                    "keyID_base64": .string(registerReq.keyID),
                    "error": .string(error.localizedDescription)
                ])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Invalid keyID format",
                    flowID: nil
                )
            }
            
            // Generate flowID for correlation
            let flowID = UUID().uuidString
            let requestID = req.headers.first(name: "x-request-id") ?? UUID().uuidString
            
            // Log keyID identity (canonical)
            var registerMetadata = KeyID.identityMetadata(keyIDBytes, keyIDBase64: registerReq.keyID)
            registerMetadata["request_id"] = .string(requestID)
            registerMetadata["flowID"] = .string(flowID)
            logger.info("REGISTER keyID identity", metadata: registerMetadata)
            
            // Hard invariants - fail fast
            guard publicKeyData.count == 65, publicKeyData[0] == 0x04 else {
                logger.warning("REGISTER invalid public key format", metadata: [
                    "publicKey_length": .string("\(publicKeyData.count)"),
                    "publicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil")
                ])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Invalid public key format: must be 65 bytes starting with 0x04",
                    flowID: nil
                )
            }
            
            // Log extracted public key details
            let extractedPublicKeyHash = SHA256.hash(data: publicKeyData)
            logger.info("REGISTER public key extracted", metadata: [
                "extractedPublicKey_length": .string("\(publicKeyData.count)"),
                "extractedPublicKey_sha256": .string(extractedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                "extractedPublicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                "extractedPublicKey_format": .string(publicKeyData.count == 65 && publicKeyData[0] == 0x04 ? "X9.63 uncompressed" : "unknown"),
                "source": .string("attestedCredentialData.credentialPublicKey (COSE key -2/-3)")
            ])
            
            // 6. Store keyID → publicKey mapping with flowID
            guard KeyStore.storePublicKey(keyIDBytes: keyIDBytes, publicKey: publicKeyData, flowID: flowID, logger: logger) else {
                logger.warning("REGISTER failed to store public key", metadata: [
                    "keyID_base64": .string(registerReq.keyID),
                    "extractedPublicKey_length": "\(publicKeyData.count)",
                    "extractedPublicKey_sha256": .string(extractedPublicKeyHash.map { String(format: "%02x", $0) }.joined())
                ])
                return RegisterResponse(
                    status: "rejected",
                    reason: "Failed to store public key",
                    flowID: nil
                )
            }
            
            // Verify the key was stored correctly by retrieving it
            if let (storedKey, storedFlowID) = KeyStore.getPublicKey(keyIDBytes: keyIDBytes) {
                let storedKeyHash = SHA256.hash(data: storedKey)
                let keysMatch = storedKeyHash == extractedPublicKeyHash
                logger.info("REGISTER key stored and verified", metadata: [
                    "storedPublicKey_sha256": .string(storedKeyHash.map { String(format: "%02x", $0) }.joined()),
                    "extractedPublicKey_sha256": .string(extractedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                    "keysMatch": .string(keysMatch ? "true" : "false"),
                    "storedFlowID": .string(storedFlowID)
                ])
                
                if !keysMatch {
                    logger.error("REGISTER key mismatch after storage", metadata: [
                        "extractedPublicKey_sha256": .string(extractedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                        "storedPublicKey_sha256": .string(storedKeyHash.map { String(format: "%02x", $0) }.joined())
                    ])
                }
            } else {
                logger.error("REGISTER key not found after storage", metadata: [
                    "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined())
                ])
            }
            
            logger.info("REGISTER complete", metadata: [
                "flowID": .string(flowID),
                "storedPublicKey_sha256": .string(extractedPublicKeyHash.map { String(format: "%02x", $0) }.joined())
            ])
            return RegisterResponse(
                status: "registered",
                reason: nil,
                flowID: flowID
            )
        }
        
        // App Attest verification endpoint
        app.post("app-attest", "verify") { req -> VerifyResponse in
            // CANARY: Prove this handler is being executed
            let exePath = ProcessInfo.processInfo.arguments[0]
            let pid = ProcessInfo.processInfo.processIdentifier
            let buildTime = ISO8601DateFormatter().string(from: Date())
            logger.error("VERIFY_CANARY handler_entered", metadata: [
                "build": .string(buildTime),
                "exe": .string(exePath),
                "pid": "\(pid)",
                "handler": "main.swift:377:app.post(app-attest/verify)"
            ])
            
            // 1. Decode request JSON
            let verifyReq = try req.content.decode(VerifyRequest.self)
            let requestID = req.headers.first(name: "x-request-id") ?? UUID().uuidString
            
            // Canonical keyID decoding
            let keyIDBytes: Data
            do {
                keyIDBytes = try KeyID.decodeBase64(verifyReq.keyID)
            } catch {
                logger.warning("VERIFY invalid keyID format", metadata: [
                    "keyID_base64": .string(verifyReq.keyID),
                    "error": .string(error.localizedDescription)
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid keyID format"
                )
            }
            
            // Log keyID identity (canonical)
            var verifyKeyIDMetadata = KeyID.identityMetadata(keyIDBytes, keyIDBase64: verifyReq.keyID)
            verifyKeyIDMetadata["request_id"] = .string(requestID)
            if let flowID = verifyReq.flowID {
                verifyKeyIDMetadata["flowID"] = .string(flowID)
            }
            logger.info("VERIFY keyID identity", metadata: verifyKeyIDMetadata)
            
            // 2. Look up the public key for keyID
            guard let (publicKeyData, storedFlowID) = KeyStore.getPublicKey(keyIDBytes: keyIDBytes) else {
                logger.warning("VERIFY public key not found", metadata: [
                    "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined())
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Public key not found for keyID"
                )
            }
            
            // FlowID correlation check
            if let requestFlowID = verifyReq.flowID {
                if requestFlowID != storedFlowID {
                    logger.warning("VERIFY flowID mismatch", metadata: [
                        "request_flowID": .string(requestFlowID),
                        "stored_flowID": .string(storedFlowID),
                        "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined())
                    ])
                    return VerifyResponse(
                        status: "rejected",
                        reason: "flowID mismatch: register/verify not same session"
                    )
                }
            } else {
                logger.info("VERIFY flowID not provided (backward compatibility)", metadata: [
                    "stored_flowID": .string(storedFlowID)
                ])
            }
            
            // Log stored public key details and validate invariants
            let storedPublicKeyHash = SHA256.hash(data: publicKeyData)
            
            // Invariant check: public key must be 65 bytes and start with 0x04
            guard publicKeyData.count == 65, publicKeyData[0] == 0x04 else {
                logger.error("VERIFY stored public key format invalid", metadata: [
                    "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                    "storedPublicKey_length": .string("\(publicKeyData.count)"),
                    "storedPublicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "expected": .string("65 bytes, firstByte: 0x04")
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Stored public key format invalid: length=\(publicKeyData.count), firstByte=\(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil")"
                )
            }
            
            logger.info("VERIFY public key retrieved", metadata: [
                "storedPublicKey_length": "\(publicKeyData.count)",
                "storedPublicKey_sha256": .string(storedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                "storedPublicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                "storedPublicKey_format": "X9.63 uncompressed",
                "invariant_check": "passed (65 bytes, 0x04 prefix)"
            ])
            
            // Convert raw public key to P256.Signing.PublicKey
            let publicKey: P256.Signing.PublicKey
            do {
                publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
                logger.info("VERIFY public key converted to CryptoKit format", metadata: [
                    "format": "X9.63 uncompressed (0x04 || X || Y)",
                    "key_length": "65"
                ])
            } catch {
                logger.warning("VERIFY invalid public key format", metadata: [
                    "keyID_sha256": .string(storedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                    "storedPublicKey_length": "\(publicKeyData.count)",
                    "storedPublicKey_firstByte": .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "error": .string(error.localizedDescription)
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid public key format: \(error.localizedDescription)"
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
            
            // Diagnostic logging: fingerprint all inputs
            let assertionObjectHash = SHA256.hash(data: assertionObject)
            let clientDataHashHex = clientDataHash.map { String(format: "%02x", $0) }.joined()
            
            logger.info("VERIFY request received", metadata: [
                "assertionObject_sha256": .string(assertionObjectHash.map { String(format: "%02x", $0) }.joined()),
                "assertionObject_length": "\(assertionObject.count)",
                "clientDataHash_hex": .string(clientDataHashHex),
                "clientDataHash_length": "\(clientDataHash.count)"
            ])
            
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
                // App Attest uses integer CBOR keys per spec:
                // 1 → authenticatorData
                // 2 → signature
                // Try integer keys first (spec-compliant), then fall back to text keys (for compatibility)
                var authData: Data? = nil
                var sig: Data? = nil
                
                // Try integer key 1 for authenticatorData
                if let authDataValue = map[.unsigned(1)], let bytes = authDataValue.bytes {
                    authData = bytes
                }
                // Fallback to text keys for compatibility
                else if let authDataValue = map[.textString("authenticatorData")] ?? map[.textString("authData")],
                        let bytes = authDataValue.bytes {
                    authData = bytes
                }
                
                guard let extractedAuthData = authData else {
                    logger.warning("VERIFY failed to extract authenticatorData", metadata: [
                        "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                        "mapKeys": .string(map.keys.map { "\($0)" }.joined(separator: ", "))
                    ])
                    return VerifyResponse(
                        status: "rejected",
                        reason: "Missing or invalid authenticatorData in assertion"
                    )
                }
                authenticatorData = extractedAuthData
                
                // Try integer key 2 for signature
                if let sigValue = map[.unsigned(2)], let bytes = sigValue.bytes {
                    sig = bytes
                }
                // Fallback to text key for compatibility
                else if let sigValue = map[.textString("signature")], let bytes = sigValue.bytes {
                    sig = bytes
                }
                
                guard let extractedSig = sig else {
                    logger.warning("VERIFY failed to extract signature", metadata: [
                        "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                        "mapKeys": .string(map.keys.map { "\($0)" }.joined(separator: ", "))
                    ])
                    return VerifyResponse(
                        status: "rejected",
                        reason: "Missing or invalid signature in assertion"
                    )
                }
                signature = extractedSig
                
                // Log which key format was used
                let usedIntegerKeys = (map[.unsigned(1)] != nil && map[.unsigned(2)] != nil)
                logger.info("VERIFY assertion CBOR keys", metadata: [
                    "usedIntegerKeys": "\(usedIntegerKeys)",
                    "authenticatorDataKey": usedIntegerKeys ? "1" : "text",
                    "signatureKey": usedIntegerKeys ? "2" : "text"
                ])
                
                // Log decoded assertion structure
                let authenticatorDataHash = SHA256.hash(data: authenticatorData)
                logger.info("VERIFY assertion decoded", metadata: [
                    "authenticatorData_length": "\(authenticatorData.count)",
                    "authenticatorData_sha256": .string(authenticatorDataHash.map { String(format: "%02x", $0) }.joined()),
                    "signature_length": "\(signature.count)",
                    "signature_firstByte": .string(signature.first.map { String(format: "0x%02x", $0) } ?? "nil")
                ])
                
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
            
            // 4. Construct the exact bytes Apple signed (COSE Sig_structure)
            //
            // **App Attest assertion signed bytes:**
            // Apple signs over a COSE Sig_structure (CBOR array), not raw concatenation.
            //
            // **Important:** App Attest assertions are CBOR maps (first byte 0xa2), NOT COSE_Sign1.
            // The assertionObject is: { "authenticatorData": <bytes>, "signature": <bytes> }
            // The signature is computed over: CBOR-encoded Sig_structure containing authenticatorData || clientDataHash
            //
            // **Sig_structure format:**
            // [
            //   "Signature1",              // text string (item 0)
            //   protected_headers,        // bstr (empty for App Attest) (item 1)
            //   external_aad,              // bstr (empty for App Attest) (item 2)
            //   authenticatorData || clientDataHash  // bstr (item 3)
            // ]
            //
            // **CRITICAL:** The signature is over SHA256(CBOR.encode(Sig_structure)), not SHA256(authenticatorData || clientDataHash)
            //
            // **CRITICAL:** Use EXACT bytes as received - do NOT:
            // - Recompute clientDataHash (use the exact bytes from the request)
            // - Pre-hash the payload (swift-crypto's isValidSignature(_:for: Data) hashes internally)
            // - Modify or normalize any bytes
            
            // First, construct the payload (authenticatorData || clientDataHash)
            let payload = authenticatorData + clientDataHash
            
            // Hard invariant: payload length must match
            let expectedPayloadLength = authenticatorData.count + clientDataHash.count
            guard payload.count == expectedPayloadLength else {
                logger.error("VERIFY payload length mismatch", metadata: [
                    "expected": .string("\(expectedPayloadLength)"),
                    "actual": .string("\(payload.count)"),
                    "authenticatorData_length": .string("\(authenticatorData.count)"),
                    "clientDataHash_length": .string("\(clientDataHash.count)")
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Internal error: payload length mismatch"
                )
            }
            
            // Hard invariant: authenticatorData must not be empty
            guard authenticatorData.count > 0 else {
                logger.warning("VERIFY authenticatorData is empty")
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid authenticatorData: must not be empty"
                )
            }
            
            // Construct COSE Sig_structure candidates
            // CRITICAL COSE GOTCHA: body_protected is a bstr containing CBOR encoding of protected headers
            // - Empty protected headers {} → body_protected = h'A0' (CBOR empty map = 0xA0), NOT h''
            // - This is the #1 reason COSE verification fails silently
            
            let externalAAD = Data() // Empty external_aad → encoded as empty bstr h''
            
            // Variant 1: body_protected = h'' (truly empty - what we were doing)
            let protectedEmpty = Data() // Empty byte string
            let sigStructureEmpty = constructCOSESigStructure(protected: protectedEmpty, externalAAD: externalAAD, payload: payload)
            
            // Variant 2: body_protected = h'A0' (CBOR empty map encoding - CORRECT for COSE)
            let protectedA0 = Data([0xA0]) // CBOR empty map {} encoded as single byte 0xA0
            let sigStructureA0 = constructCOSESigStructure(protected: protectedA0, externalAAD: externalAAD, payload: payload)
            
            // Hard invariant: Both Sig_structures must start with CBOR array(4) marker 0x84
            guard sigStructureEmpty.first == 0x84 && sigStructureA0.first == 0x84 else {
                logger.error("VERIFY Sig_structure CBOR encoding error", metadata: [
                    "sigStructureEmpty_firstByte": .string(sigStructureEmpty.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "sigStructureA0_firstByte": .string(sigStructureA0.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "expected": "0x84 (array of 4)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Internal error: Sig_structure CBOR encoding failed"
                )
            }
            
            // Hard-assert: sigStructureA0 item 1 is bstr of length 1 containing 0xA0
            // Structure: 0x84 (array 4) | 0x6a "Signature1" | 0x41 (bstr len 1) | 0xA0 | ...
            let expectedA0Structure = Data([0x84, 0x6a]) + "Signature1".data(using: .utf8)! + Data([0x41, 0xA0])
            guard sigStructureA0.prefix(expectedA0Structure.count) == expectedA0Structure else {
                logger.error("VERIFY Sig_structure A0 variant encoding error", metadata: [
                    "expectedPrefix": .string(expectedA0Structure.map { String(format: "0x%02x", $0) }.joined(separator: " ")),
                    "actualPrefix": .string(sigStructureA0.prefix(expectedA0Structure.count).map { String(format: "0x%02x", $0) }.joined(separator: " "))
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Internal error: Sig_structure A0 variant encoding failed"
                )
            }
            
            // Log signed bytes construction
            logger.info("VERIFY signed bytes constructed", metadata: [
                "payload_length": .string("\(payload.count)"),
                "payload_sha256": .string(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()),
                "authenticatorData_length": .string("\(authenticatorData.count)"),
                "clientDataHash_length": .string("\(clientDataHash.count)"),
                "sigStructureEmpty_length": .string("\(sigStructureEmpty.count)"),
                "sigStructureEmpty_sha256": .string(SHA256.hash(data: sigStructureEmpty).map { String(format: "%02x", $0) }.joined()),
                "sigStructureA0_length": .string("\(sigStructureA0.count)"),
                "sigStructureA0_sha256": .string(SHA256.hash(data: sigStructureA0).map { String(format: "%02x", $0) }.joined()),
                "construction": "Testing both: [\"Signature1\", h'', h'', payload] and [\"Signature1\", h'A0', h'', payload]"
            ])
            
            // We'll test both variants - start with A0 (the correct COSE encoding)
            let messageToVerify = sigStructureA0
            
            // 5. Normalize signature to ASN.1 DER format
            //
            // **Signature format handling:**
            // App Attest signatures can arrive in two formats:
            //   1. Raw ES256: 64 bytes (32 bytes r || 32 bytes s) → convert to DER
            //   2. ASN.1 DER: variable length (70-72 bytes), starts with 0x30 → use as-is
            //
            // CryptoKit requires ASN.1 DER format, so we normalize here.
            let signatureDER: Data
            let signatureParseMode: String
            
            if signature.count == 64 {
                // Raw r||s format → convert to ASN.1 DER
                logger.info("VERIFY signature format: raw 64-byte (r||s), converting to DER", metadata: [
                    "signature_length": "\(signature.count)",
                    "signature_firstByte": .string(signature.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "signature_sha256": .string(SHA256.hash(data: signature).map { String(format: "%02x", $0) }.joined())
                ])
                
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
                signatureParseMode = "RAW_64_CONVERTED_TO_DER_OK"
                
                let derHash = SHA256.hash(data: der)
                logger.info("VERIFY signature converted to DER", metadata: [
                    "raw_signature_length": "64",
                    "raw_signature_sha256": .string(SHA256.hash(data: signature).map { String(format: "%02x", $0) }.joined()),
                    "der_signature_length": "\(der.count)",
                    "der_signature_firstByte": .string(der.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "der_signature_sha256": .string(derHash.map { String(format: "%02x", $0) }.joined()),
                    "r_der_length": "\(rDER.count)",
                    "s_der_length": "\(sDER.count)",
                    "conversion": "raw r||s → ASN.1 DER SEQUENCE"
                ])
            } else if signature.first == 0x30 {
                // Already ASN.1 DER format (starts with SEQUENCE tag 0x30)
                logger.info("VERIFY signature format: ASN.1 DER (already encoded, using as-is)", metadata: [
                    "signature_length": "\(signature.count)",
                    "signature_firstByte": "0x30",
                    "signature_sha256": .string(SHA256.hash(data: signature).map { String(format: "%02x", $0) }.joined()),
                    "conversion": "none (already DER)"
                ])
                signatureDER = signature
                signatureParseMode = "DER_PARSE_OK"
            } else {
                // Invalid signature format
                let firstBytes = signature.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " ")
                logger.warning("VERIFY invalid signature format", metadata: [
                    "signature_length": .string("\(signature.count)"),
                    "signature_firstByte": .string(signature.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "firstBytes": .string(firstBytes)
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Invalid signature format: length \(signature.count) bytes, first byte: \(signature.first.map { String(format: "0x%02x", $0) } ?? "nil")"
                )
            }
            
            // Validate signedBytes construction
            let expectedSignedBytesLength = authenticatorData.count + clientDataHash.count
            if payload.count != expectedSignedBytesLength {
                logger.error("VERIFY signedBytes length mismatch", metadata: [
                    "expected": "\(expectedSignedBytesLength)",
                    "actual": "\(payload.count)",
                    "authenticatorData_length": "\(authenticatorData.count)",
                    "clientDataHash_length": "\(clientDataHash.count)"
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Internal error: signedBytes length mismatch"
                )
            }
            
            // 6. Create validation context (using Sig_structure bytes)
            let context: AssertionValidationContext
            do {
                context = try AssertionValidationContext(
                    publicKey: publicKey,
                    sigStructure: messageToVerify,
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
            // - Backend uses swift-crypto (Linux) not CryptoKit (Apple platforms)
            // - P256.Signing.PublicKey.isValidSignature(_:for: Data) hashes the Data internally using SHA256
            // - We pass COSE Sig_structure bytes (CBOR-encoded array)
            // - Signature is parsed as ASN.1 DER before verification
            //
            // **Platform:** Linux (swift-crypto)
            // **API:** isValidSignature(_:for: Data) - message-based, hashes internally
            // **Signed bytes:** COSE Sig_structure = CBOR array ["Signature1", {}, {}, authenticatorData || clientDataHash]
            
            // Validator identity logging - ensure single code path
            let validatorIdentity = "main.swift:552:verifyAssertion -> AssertionValidator.validate"
            let validatorVersion = "v1-matrix-2026-01-17"
            
            // Single comprehensive verification log block
            // Build metadata in parts to avoid compiler type-checking timeout
            var verifyMetadata: Logger.Metadata = [:]
            verifyMetadata["validator_identity"] = .string(validatorIdentity)
            verifyMetadata["keyID_base64"] = .string(verifyReq.keyID)
            verifyMetadata["keyID_sha256"] = .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["storedPublicKey_length"] = .string("\(publicKeyData.count)")
            verifyMetadata["storedPublicKey_firstByte"] = .string(publicKeyData.first.map { String(format: "0x%02x", $0) } ?? "nil")
            verifyMetadata["storedPublicKey_sha256"] = .string(storedPublicKeyHash.map { String(format: "%02x", $0) }.joined())
            verifyMetadata["authenticatorData_length"] = .string("\(authenticatorData.count)")
            verifyMetadata["authenticatorData_sha256"] = .string(SHA256.hash(data: authenticatorData).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["clientDataHash_length"] = .string("\(clientDataHash.count)")
            verifyMetadata["clientDataHash_hex"] = .string(clientDataHashHex)
            verifyMetadata["payload_length"] = .string("\(payload.count)")
            verifyMetadata["sigStructure_length"] = .string("\(messageToVerify.count)")
            verifyMetadata["sigStructure_sha256"] = .string(SHA256.hash(data: messageToVerify).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["payload_sha256"] = .string(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["signature_length"] = .string("\(signature.count)")
            verifyMetadata["signature_firstByte"] = .string(signature.first.map { String(format: "0x%02x", $0) } ?? "nil")
            verifyMetadata["signature_sha256"] = .string(SHA256.hash(data: signature).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["signatureParseMode"] = .string(signatureParseMode)
            verifyMetadata["signatureDER_length"] = .string("\(signatureDER.count)")
            verifyMetadata["signatureDER_sha256"] = .string(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined())
            verifyMetadata["verifierEngine"] = .string("swift-crypto")
            verifyMetadata["verificationAPI"] = .string("isValidSignature(ECDSASignature, for: Data) - message-based, hashes internally")
            
            logger.info("VERIFY cryptographic verification block", metadata: verifyMetadata)
            
            // Forensic dump: Write exact verification artifacts to /tmp/appattest/
            // This MUST execute unconditionally for every verify request
            let pubkeyPEMFile: URL?
            do {
                pubkeyPEMFile = dumpVerificationArtifacts(
                    keyIDBytes: keyIDBytes,
                    assertionObject: assertionObject,
                    publicKey: publicKeyData,
                    signatureDER: signatureDER,
                    message: payload,
                    logger: logger
                )
                if pubkeyPEMFile == nil {
                    logger.error("VERIFY forensic dump returned nil - dump may have failed")
                }
            } catch {
                logger.error("VERIFY forensic dump exception", metadata: [
                    "error": .string(error.localizedDescription)
                ])
                pubkeyPEMFile = nil
            }
            
            // VERIFICATION MATRIX: Test all candidates exhaustively
            // 1. Raw payload: authenticatorData || clientDataHash
            // 2. Sig_structure with protected = h'' (truly empty)
            // 3. Sig_structure with protected = h'A0' (CBOR empty map - CORRECT for COSE)
            
            // swift-crypto verification: Test all three candidates
            let swiftCryptoValidRawPayload = verifyAssertion(
                publicKeyX963: publicKeyData,
                signatureDER: signatureDER,
                message: payload
            )
            
            let swiftCryptoValidSigStructEmpty = verifyAssertion(
                publicKeyX963: publicKeyData,
                signatureDER: signatureDER,
                message: sigStructureEmpty
            )
            
            let swiftCryptoValidSigStructA0 = verifyAssertion(
                publicKeyX963: publicKeyData,
                signatureDER: signatureDER,
                message: sigStructureA0
            )
            
            // OpenSSL verification: Test all three candidates
            var openSSLValidRawPayload: Bool = false
            var openSSLRawPayloadExitCode: Int32 = -1
            var openSSLRawPayloadOutput: String = ""
            var openSSLValidSigStructEmpty: Bool = false
            var openSSLSigStructEmptyExitCode: Int32 = -1
            var openSSLSigStructEmptyOutput: String = ""
            var openSSLValidSigStructA0: Bool = false
            var openSSLSigStructA0ExitCode: Int32 = -1
            var openSSLSigStructA0Output: String = ""
            
            if let pemFile = pubkeyPEMFile {
                // Test 1: Raw payload
                let (verified, exitCode, output) = verifyWithOpenSSL(
                    pubkeyPEM: pemFile,
                    signatureDER: signatureDER,
                    message: payload,
                    logger: logger
                )
                openSSLValidRawPayload = verified
                openSSLRawPayloadExitCode = exitCode
                openSSLRawPayloadOutput = output
                
                // Test 2: Sig_structure with protected = h''
                let (verifiedEmpty, exitCodeEmpty, outputEmpty) = verifyWithOpenSSL(
                    pubkeyPEM: pemFile,
                    signatureDER: signatureDER,
                    message: sigStructureEmpty,
                    logger: logger
                )
                openSSLValidSigStructEmpty = verifiedEmpty
                openSSLSigStructEmptyExitCode = exitCodeEmpty
                openSSLSigStructEmptyOutput = outputEmpty
                
                // Test 3: Sig_structure with protected = h'A0' (CORRECT)
                let (verifiedA0, exitCodeA0, outputA0) = verifyWithOpenSSL(
                    pubkeyPEM: pemFile,
                    signatureDER: signatureDER,
                    message: sigStructureA0,
                    logger: logger
                )
                openSSLValidSigStructA0 = verifiedA0
                openSSLSigStructA0ExitCode = exitCodeA0
                openSSLSigStructA0Output = outputA0
            }
            
            // Use the A0 variant for primary verification (correct COSE encoding)
            let swiftCryptoValid = swiftCryptoValidSigStructA0
            
            // Log verification matrix - exhaustive test of all candidates
            let interpretation: String
            if openSSLValidSigStructA0 && swiftCryptoValidSigStructA0 {
                interpretation = "✓ Both verify over Sig_structure with protected=h'A0' → CORRECT COSE encoding"
            } else if openSSLValidSigStructEmpty && swiftCryptoValidSigStructEmpty {
                interpretation = "Both verify over Sig_structure with protected=h'' → Apple uses truly empty protected (rare)"
            } else if openSSLValidRawPayload && swiftCryptoValidRawPayload {
                interpretation = "Both verify over raw payload → Apple signs raw concat, not Sig_structure (delete COSE code)"
            } else if openSSLValidSigStructA0 && !swiftCryptoValidSigStructA0 {
                interpretation = "OpenSSL verifies Sig_structure A0 but swift-crypto rejects → API misuse or signature object construction"
            } else if openSSLValidSigStructEmpty && !swiftCryptoValidSigStructEmpty {
                interpretation = "OpenSSL verifies Sig_structure empty but swift-crypto rejects → API misuse"
            } else {
                interpretation = "All candidates fail → signature/key extraction issue (check artifacts for ground truth)"
            }
            
            // Single VERIFY_MATRIX log line - the oracle
            logger.error("VERIFY_MATRIX", metadata: [
                "validatorIdentity": .string(validatorIdentity),
                "validatorVersion": .string(validatorVersion),
                "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                "pubkey_sha256": .string(storedPublicKeyHash.map { String(format: "%02x", $0) }.joined()),
                "sig_sha256": .string(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined()),
                "payload_sha256": .string(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()),
                "sigstructEmpty_sha256": .string(SHA256.hash(data: sigStructureEmpty).map { String(format: "%02x", $0) }.joined()),
                "sigstructA0_sha256": .string(SHA256.hash(data: sigStructureA0).map { String(format: "%02x", $0) }.joined()),
                "swiftcrypto_rawpayload": "\(swiftCryptoValidRawPayload)",
                "swiftcrypto_sigstruct_empty": "\(swiftCryptoValidSigStructEmpty)",
                "swiftcrypto_sigstruct_a0": "\(swiftCryptoValidSigStructA0)",
                "openssl_rawpayload": "\(openSSLValidRawPayload)",
                "openssl_sigstruct_empty": "\(openSSLValidSigStructEmpty)",
                "openssl_sigstruct_a0": "\(openSSLValidSigStructA0)",
                "openssl_rawpayload_exitcode": "\(openSSLRawPayloadExitCode)",
                "openssl_sigstruct_empty_exitcode": "\(openSSLSigStructEmptyExitCode)",
                "openssl_sigstruct_a0_exitcode": "\(openSSLSigStructA0ExitCode)",
                "interpretation": .string(interpretation)
            ])
            
            // Log verification result with comprehensive diagnostics
            // 8. Return verification result (no policy checks, pure crypto result)
            if swiftCryptoValid {
                logger.info("VERIFY result: verified", metadata: [
                    "validator_identity": .string(validatorIdentity),
                    "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                    "signedBytes_sha256": .string(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()),
                    "signatureParseMode": .string(signatureParseMode),
                    "verifierEngine": .string("swift-crypto")
                ])
                return VerifyResponse(
                    status: "verified",
                    reason: nil
                )
            } else {
                logger.warning("VERIFY result: rejected", metadata: [
                    "keyID_sha256": .string(KeyID.storageKey(keyIDBytes).map { String(format: "%02x", $0) }.joined()),
                    "reason": .string("Signature did not verify under the supplied public key"),
                    "assertionObject_sha256": .string(assertionObjectHash.map { String(format: "%02x", $0) }.joined()),
                    "authenticatorData_length": .string("\(authenticatorData.count)"),
                    "signature_length": .string("\(signature.count)"),
                    "signature_firstByte": .string(signature.first.map { String(format: "0x%02x", $0) } ?? "nil"),
                    "signatureParseMode": .string(signatureParseMode),
                    "payload_length": .string("\(payload.count)"),
                    "sigStructure_length": .string("\(messageToVerify.count)"),
                    "sigStructure_sha256": .string(SHA256.hash(data: messageToVerify).map { String(format: "%02x", $0) }.joined()),
                    "storedPublicKey_length": .string("\(publicKeyData.count)"),
                    "storedPublicKey_format": .string(publicKeyData.count == 65 && publicKeyData[0] == 0x04 ? "X9.63" : "unknown")
                ])
                return VerifyResponse(
                    status: "rejected",
                    reason: "Signature did not verify under the supplied public key"
                )
            }
    }
}

// MARK: - Server Entry Point

var env = try Environment.detect()
try LoggingSystem.bootstrap(from: &env)

let app = Application(env)
defer { app.shutdown() }

// Configure to listen on 0.0.0.0:8080 (LAN accessible)
app.http.server.configuration.hostname = "0.0.0.0"
app.http.server.configuration.port = 8080

try configure(app)
try app.run()
