//
//  AssertionVerifier.swift
//  AppAttestBackend
//
//  Assertion crypto: signedBytes = authenticatorData || clientDataHash, ECDSA verification.
//  CRITICAL: Apple App Attest signs signedBytes directly (raw bytes).
//  Apple performs: ECDSA_sign(signedBytes) which internally computes SHA256(signedBytes) and signs that hash.
//  The backend must verify over raw signedBytes (Data) and let CryptoKit hash internally.
//  On Linux SwiftCrypto, isValidSignature(_:for: Data) hashes Data internally using SHA-256, matching Apple's behavior.
//

import Foundation
import Crypto
import Logging
import AppAttestCore

/// Result of ECDSA and message reconstruction. Caller enforces policy and mode gate.
struct AssertionCryptoResult {
    let signedBytes: Data
    let signedBytesSHA256: String
    let nonceSHA256: String
    let ecdsaDigestValid: Bool
    let ecdsaMessageValid: Bool
    let opensslModeA: Bool? // verify over SHA256(signedBytes) - hashing inside OpenSSL
    let opensslModeB: Bool? // verify over raw nonce (32 bytes) - no hashing
    let selectedMode: String? // "A" or "B" if exactly one succeeded
}

struct OpenSSLVerificationResult {
    let modeA: Bool?
    let modeB: Bool?
    let selectedMode: String?
}

/// - Throws: if DER parse or P256 key/signature creation fails.
func verifyAssertionCrypto(
    authenticatorData: Data,
    clientDataHash: Data,
    signatureDER: Data,
    publicKeyX963: Data,
    logger: Logger
) throws -> AssertionCryptoResult {
    // Public key sanity check (ABSOLUTE RULES)
    guard publicKeyX963.count == 65, publicKeyX963[0] == 0x04 else {
        logger.error("INVALID_PUBLIC_KEY_FORMAT [length: \(publicKeyX963.count), firstByte: \(publicKeyX963.first.map { String(format: "0x%02x", $0) } ?? "nil")]")
        throw AssertionVerificationError.invalidPublicKey
    }
    
    // CANONICAL ARTIFACT FREEZE: Log all inputs before any verification
    logger.info("CANONICAL_ARTIFACTS [publicKey_x963_len: \(publicKeyX963.count), publicKey_x963_hex: \(dataToHex(publicKeyX963)), publicKey_x963_sha256: \(sha256Hex(publicKeyX963)), authenticatorData_len: \(authenticatorData.count), authenticatorData_hex: \(dataToHex(authenticatorData)), authenticatorData_sha256: \(sha256Hex(authenticatorData)), clientDataHash_len: \(clientDataHash.count), clientDataHash_hex: \(dataToHex(clientDataHash)), clientDataHash_sha256: \(sha256Hex(clientDataHash))]")
    
    // CRITICAL: Apple App Attest signs signedBytes directly (raw bytes, NOT a hash of them).
    // Apple performs: ECDSA_sign(signedBytes) which internally computes SHA256(signedBytes) and signs that hash.
    // The backend must verify over raw signedBytes (Data) and let CryptoKit hash internally.
    let signedBytes = authenticatorData + clientDataHash
    let signedBytesSHA256 = sha256Hex(signedBytes)
    
    // Validate signedBytes length
    guard signedBytes.count == authenticatorData.count + 32 else {
        logger.error("ASSERT_VERIFY_ERROR [signedBytes length invalid: \(signedBytes.count), expected: \(authenticatorData.count + 32)]")
        throw AssertionVerificationError.invalidSignatureFormat
    }
    
    // Log signedBytes BEFORE verification (required by prompt)
    logger.info("CANONICAL_ARTIFACTS [authenticatorData_sha256: \(sha256Hex(authenticatorData)), clientDataHash_hex: \(dataToHex(clientDataHash)), signedBytes_len: \(signedBytes.count), signedBytes_hex: \(dataToHex(signedBytes)), signedBytes_sha256: \(signedBytesSHA256), signature_der_len: \(signatureDER.count), signature_der_hex: \(dataToHex(signatureDER)), signature_der_sha256: \(sha256Hex(signatureDER))]")
    
    // TEMPORARY: Disable normalization to verify original signature works
    // ECDSA low-S normalization (required for strict verification)
    // Some implementations reject "high-S" signatures (s > n/2) to prevent signature malleability.
    let (normalizedSignatureDER, wasHighS): (Data, Bool) = {
        // TEMPORARY DISABLE: Use original signature to verify App Attest pipeline is correct
        logger.info("ECDSA canonicalization: TEMPORARILY DISABLED - using original signature [signature_length: \(signatureDER.count)]")
        return (signatureDER, false)
        
        /* DISABLED - Re-enable after verifying original signature works
        do {
            // Parse original signature to check if it's high-S
            var reader = ASN1Reader(signatureDER)
            let seqTLV = try reader.readTLV()
            guard seqTLV.tag == ASN1Tag.sequence, seqTLV.tag.constructed else {
                throw AssertionVerificationError.invalidSignatureFormat
            }
            var seqReader = ASN1Reader(signatureDER.subdata(in: seqTLV.valueRange))
            let rTLV = try seqReader.readTLV()
            let sTLV = try seqReader.readTLV()
            guard rTLV.tag == ASN1Tag.integer, sTLV.tag == ASN1Tag.integer else {
                throw AssertionVerificationError.invalidSignatureFormat
            }
            let sBytes = removeLeadingZeros(signatureDER.subdata(in: sTLV.valueRange))
            let nBytes = Data([
                0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
            ])
            let halfN = shiftRight(nBytes, by: 1)
            let isHighS = compareBigEndian(sBytes, halfN) > 0
            
            let normalized = try normalizeECDSASignatureToLowS(signatureDER: signatureDER)
            
            if isHighS {
                logger.info("ECDSA canonicalization: HIGH-S detected, normalized to low-S [original_length: \(signatureDER.count), normalized_length: \(normalized.count)]")
            } else {
                logger.info("ECDSA canonicalization: already low-S [signature_length: \(signatureDER.count)]")
            }
            
            // Debug logging: r and s values (only in debug mode)
            if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_SIGNATURE"] == "1" {
                let rBytes = removeLeadingZeros(signatureDER.subdata(in: rTLV.valueRange))
                let sOriginalBytes = removeLeadingZeros(signatureDER.subdata(in: sTLV.valueRange))
                
                // Extract normalized s
                var normReader = ASN1Reader(normalized)
                let normSeqTLV = try normReader.readTLV()
                var normSeqReader = ASN1Reader(normalized.subdata(in: normSeqTLV.valueRange))
                _ = try normSeqReader.readTLV() // skip r
                let sNormTLV = try normSeqReader.readTLV()
                let sNormalizedBytes = removeLeadingZeros(normalized.subdata(in: sNormTLV.valueRange))
                
                logger.info("ECDSA_SIGNATURE_DEBUG [r_hex: \(dataToHex(rBytes)), s_original_hex: \(dataToHex(sOriginalBytes)), s_normalized_hex: \(dataToHex(sNormalizedBytes)), was_high_s: \(isHighS)]")
            }
            
            return (normalized, isHighS)
        } catch {
            logger.error("ECDSA canonicalization failed: \(error.localizedDescription), using original signature")
            return (signatureDER, false)
        }
        */
    }()
    
    let publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
    let signature = try P256.Signing.ECDSASignature(derRepresentation: normalizedSignatureDER)
    
    // CRITICAL FIX: Apple signs signedBytes directly (raw bytes).
    // Apple performs: ECDSA_sign(signedBytes) which internally computes SHA256(signedBytes) and signs that hash.
    // The backend must verify over raw signedBytes (Data) and let CryptoKit hash internally.
    // On Linux SwiftCrypto, isValidSignature(_:for: Data) hashes Data internally using SHA-256.
    // This matches what Apple does: hash signedBytes internally, then verify.
    //
    // NOTE: On Linux, SwiftCrypto/OpenSSL may reject valid Apple App Attest ECDSA signatures
    // due to implementation differences. Byte-level parity does not guarantee cross-platform verification.
    let ecdsaMessageValid: Bool
    do {
        // Verify signature over raw signedBytes (Data)
        // Apple signs: ECDSA_sign(signedBytes) = sign(SHA256(signedBytes)) [hashing is internal to ECDSA]
        // We pass signedBytes (Data) - CryptoKit will hash it internally with SHA-256, matching Apple's behavior
        ecdsaMessageValid = publicKey.isValidSignature(signature, for: signedBytes)
        logger.info("SWIFTCRYPTO_VERIFY_RESULT: \(ecdsaMessageValid)")
        if ecdsaMessageValid {
            logger.info("ECDSA verification: SUCCESS [signedBytes_sha256: \(signedBytesSHA256)]")
        } else {
            logger.warning("ASSERT_VERIFY_WARNING [ECDSA verification returned false] [signedBytes.count=\(signedBytes.count), signedBytes.sha256=\(signedBytesSHA256), signature.count=\(signatureDER.count), signature.sha256=\(sha256Hex(signatureDER)), publicKey.count=\(publicKeyX963.count), publicKey.prefix=\(publicKeyX963.prefix(4).map { String(format: "%02x", $0) }.joined())]")
        }
    } catch {
        logger.error("ASSERT_VERIFY_ERROR [ECDSA verification threw: \(error.localizedDescription)] [signedBytes.count=\(signedBytes.count), signature.count=\(signatureDER.count), publicKey.count=\(publicKeyX963.count)]")
        ecdsaMessageValid = false
        logger.info("SWIFTCRYPTO_VERIFY_RESULT: false")
    }
    
    // DIGEST mode: diagnostic only, never used as gate. Computes SHA256(signedBytes) and verifies over that digest.
    let ecdsaDigestValid: Bool
    do {
        let messageDigest = SHA256.hash(data: signedBytes)
        ecdsaDigestValid = publicKey.isValidSignature(signature, for: messageDigest)
        if !ecdsaDigestValid {
            logger.warning("ASSERT_VERIFY_WARNING [digest mode verification returned false] [signedBytes.sha256=\(signedBytesSHA256), signature.count=\(signatureDER.count)]")
        }
    } catch {
        logger.error("ASSERT_VERIFY_ERROR [digest mode verification threw: \(error.localizedDescription)] [signedBytes.sha256=\(signedBytesSHA256), signature.count=\(signatureDER.count)]")
        ecdsaDigestValid = false
    }
    
    // Debug logging to verify exact inputs
    if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_NONCE"] == "1" {
        let (signedPrefix, signedSuffix) = hexPrefixSuffix(signedBytes, n: 16)
        let (sigPrefix, sigSuffix) = hexPrefixSuffix(signatureDER, n: 16)
        let (authPrefix, authSuffix) = hexPrefixSuffix(authenticatorData, n: 16)
        logger.info("ASSERT_VERIFY_DEBUG [signedBytes.count=\(signedBytes.count), signedBytes.sha256=\(signedBytesSHA256), signedBytes.prefix=\(signedPrefix), signedBytes.suffix=\(signedSuffix), signature.count=\(signatureDER.count), signature.sha256=\(sha256Hex(signatureDER)), signature.prefix=\(sigPrefix), signature.suffix=\(sigSuffix), authenticatorData.prefix=\(authPrefix), authenticatorData.suffix=\(authSuffix), publicKey.count=\(publicKeyX963.count), publicKey.prefix=\(publicKeyX963.prefix(4).map { String(format: "%02x", $0) }.joined()), ecdsaMessageValid=\(ecdsaMessageValid), ecdsaDigestValid=\(ecdsaDigestValid)]")
    }
    
    // OPENSSL VERIFICATION (MANDATORY when enabled) - Mode A verifies over signedBytes
    // Use normalized signature for consistency with CryptoKit verification
    var opensslResult: OpenSSLVerificationResult? = nil
    if ProcessInfo.processInfo.environment["APP_ATTEST_OPENSSL_VERIFY"] == "1" {
        opensslResult = verifyWithOpenSSL(
            publicKeyX963: publicKeyX963,
            signedBytes: signedBytes,
            signatureDER: normalizedSignatureDER,
            logger: logger
        )
    }
    
    return AssertionCryptoResult(
        signedBytes: signedBytes,
        signedBytesSHA256: signedBytesSHA256,
        nonceSHA256: signedBytesSHA256, // nonceSHA256 is same as signedBytesSHA256 (no separate nonce computation)
        ecdsaDigestValid: ecdsaDigestValid,
        ecdsaMessageValid: ecdsaMessageValid,
        opensslModeA: opensslResult?.modeA,
        opensslModeB: opensslResult?.modeB,
        selectedMode: opensslResult?.selectedMode
    )
}

/// Verifies ECDSA signature using OpenSSL.
/// Mode A: verify signature over signedBytes by hashing inside OpenSSL (correct - matches Apple's behavior)
/// Mode B: kept for diagnostic purposes but should not succeed (verifies over raw hash without hashing)
/// - Returns: OpenSSLVerificationResult with both modes and selected mode if exactly one succeeds
private func verifyWithOpenSSL(
    publicKeyX963: Data,
    signedBytes: Data,
    signatureDER: Data,
    logger: Logger
) -> OpenSSLVerificationResult {
    guard FileManager.default.fileExists(atPath: "/usr/bin/openssl") else {
        logger.warning("OPENSSL_VERIFY [OpenSSL not available at /usr/bin/openssl]")
        return OpenSSLVerificationResult(modeA: nil, modeB: nil, selectedMode: nil)
    }
    
    let tempDir = URL(fileURLWithPath: "/tmp/appattest-openssl-verify")
    do {
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    } catch {
        logger.error("OPENSSL_VERIFY [Failed to create temp directory: \(error.localizedDescription)]")
        return OpenSSLVerificationResult(modeA: nil, modeB: nil, selectedMode: nil)
    }
    
    let pubkeyPEM = tempDir.appendingPathComponent("pubkey.pem")
    let signedBytesBin = tempDir.appendingPathComponent("signedBytes.bin")
    let signatureDERFile = tempDir.appendingPathComponent("signature.der")
    
    // Compute nonce for Mode B diagnostic (should not succeed)
    // Mode B verifies over raw hash without hashing, but Apple signs signedBytes (not the hash)
    let nonce = Data(SHA256.hash(data: signedBytes))
    let nonceBin = tempDir.appendingPathComponent("nonce.bin")
    
    // Convert x963 to PEM SPKI
    guard let pemData = convertX963ToPEM(publicKey: publicKeyX963) else {
        logger.error("OPENSSL_VERIFY [Failed to convert x963 to PEM]")
        return OpenSSLVerificationResult(modeA: nil, modeB: nil, selectedMode: nil)
    }
    
    // Extract SPKI DER from PEM for logging
    let pemString = String(data: pemData, encoding: .utf8) ?? ""
    let spkiDERHex: String
    if let base64Start = pemString.range(of: "-----BEGIN PUBLIC KEY-----\n"),
       let base64End = pemString.range(of: "\n-----END PUBLIC KEY-----") {
        let base64Range = base64Start.upperBound..<base64End.lowerBound
        let base64 = String(pemString[base64Range]).replacingOccurrences(of: "\n", with: "")
        if let der = Data(base64Encoded: base64) {
            let (prefix, suffix) = hexPrefixSuffix(der, n: 16)
            spkiDERHex = "\(prefix)...\(suffix)"
        } else {
            spkiDERHex = "decode_failed"
        }
    } else {
        spkiDERHex = "parse_failed"
    }
    
    logger.info("OPENSSL_PUBKEY_PEM_SHA256: \(sha256Hex(pemData))")
    logger.info("OPENSSL_SPKI_DER_HEX_PREFIX_SUFFIX: \(spkiDERHex)")
    
    // Write temp files
    do {
        try pemData.write(to: pubkeyPEM)
        try signedBytes.write(to: signedBytesBin)
        try nonce.write(to: nonceBin)
        try signatureDER.write(to: signatureDERFile)
    } catch {
        logger.error("OPENSSL_VERIFY [Failed to write temp files: \(error.localizedDescription)]")
        return OpenSSLVerificationResult(modeA: nil, modeB: nil, selectedMode: nil)
    }
    
    // Helper function to run OpenSSL command
    func runOpenSSLCommand(_ args: [String]) -> (success: Bool, stdout: String, stderr: String, exitCode: Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = args
        
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
            let stderr = String(data: stderrData, encoding: .utf8) ?? ""
            let exitCode = process.terminationStatus
            
            return (success: exitCode == 0, stdout: stdout.trimmingCharacters(in: .whitespacesAndNewlines), stderr: stderr.trimmingCharacters(in: .whitespacesAndNewlines), exitCode: exitCode)
        } catch {
            logger.error("OPENSSL_VERIFY [Failed to run OpenSSL: \(error.localizedDescription)]")
            return (success: false, stdout: "", stderr: error.localizedDescription, exitCode: -1)
        }
    }
    
    // Mode A: verify signature over signedBytes by hashing inside OpenSSL (CORRECT - matches Apple's behavior)
    // Apple signs signedBytes, ECDSA internally hashes it. OpenSSL dgst -sha256 does the same.
    let modeAArgs = [
        "dgst", "-sha256",
        "-verify", pubkeyPEM.path,
        "-signature", signatureDERFile.path,
        signedBytesBin.path
    ]
    let modeAResult = runOpenSSLCommand(modeAArgs)
    let modeASuccess = modeAResult.success
    
    logger.info("OPENSSL_MODE_A [exitCode: \(modeAResult.exitCode), stdout: \(modeAResult.stdout), stderr: \(modeAResult.stderr), result: \(modeASuccess ? "success" : "failure")]")
    
    // Mode B: verify signature over RAW hash (32 bytes) without hashing (DIAGNOSTIC ONLY - should not succeed)
    // This mode verifies over SHA256(signedBytes) directly, but Apple signs signedBytes (not the hash).
    // Kept for diagnostic purposes to confirm Mode A is correct.
    let modeBArgs = [
        "pkeyutl", "-verify",
        "-pubin", "-inkey", pubkeyPEM.path,
        "-sigfile", signatureDERFile.path,
        "-in", nonceBin.path
    ]
    let modeBResult = runOpenSSLCommand(modeBArgs)
    let modeBSuccess = modeBResult.success
    
    logger.info("OPENSSL_MODE_B [exitCode: \(modeBResult.exitCode), stdout: \(modeBResult.stdout), stderr: \(modeBResult.stderr), result: \(modeBSuccess ? "success" : "failure")] [DIAGNOSTIC ONLY - should fail]")
    
    // Determine selected mode if exactly one succeeds
    let selectedMode: String?
    if modeASuccess && !modeBSuccess {
        selectedMode = "A"
        logger.info("SELECTED_ASSERTION_VERIFY_MODE: A [OpenSSL Mode A succeeded, Mode B failed]")
    } else if !modeASuccess && modeBSuccess {
        selectedMode = "B"
        logger.info("SELECTED_ASSERTION_VERIFY_MODE: B [OpenSSL Mode B succeeded, Mode A failed]")
    } else if modeASuccess && modeBSuccess {
        selectedMode = "A" // Prefer Mode A if both succeed
        logger.info("SELECTED_ASSERTION_VERIFY_MODE: A [Both modes succeeded, defaulting to Mode A]")
    } else {
        selectedMode = nil
        logger.warning("SELECTED_ASSERTION_VERIFY_MODE: NONE [Both OpenSSL modes failed]")
    }
    
    // Cleanup temp files
    try? FileManager.default.removeItem(at: pubkeyPEM)
    try? FileManager.default.removeItem(at: signedBytesBin)
    try? FileManager.default.removeItem(at: nonceBin)
    try? FileManager.default.removeItem(at: signatureDERFile)
    try? FileManager.default.removeItem(at: tempDir)
    
    return OpenSSLVerificationResult(modeA: modeASuccess, modeB: modeBSuccess, selectedMode: selectedMode)
}

/// Normalizes an ECDSA DER signature to low-S for P-256.
/// ECDSA signatures can have two valid forms: (r, s) and (r, n-s).
/// Some implementations reject "high-S" signatures (s > n/2) to prevent signature malleability.
/// This function normalizes to the canonical low-S form.
/// - Parameter signatureDER: DER-encoded ECDSA signature (SEQUENCE of two INTEGERs)
/// - Returns: Normalized DER signature with s <= n/2
/// - Throws: AssertionVerificationError if DER parsing fails
func normalizeECDSASignatureToLowS(signatureDER: Data) throws -> Data {
    // P-256 curve order: n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    let nBytes = Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ])
    
    // Parse DER SEQUENCE
    var reader = ASN1Reader(signatureDER)
    let seqTLV = try reader.readTLV()
    guard seqTLV.tag == ASN1Tag.sequence, seqTLV.tag.constructed else {
        throw AssertionVerificationError.invalidSignatureFormat
    }
    
    // Parse two INTEGERs: r and s
    var seqReader = ASN1Reader(signatureDER.subdata(in: seqTLV.valueRange))
    let rTLV = try seqReader.readTLV()
    let sTLV = try seqReader.readTLV()
    
    guard rTLV.tag == ASN1Tag.integer else {
        throw AssertionVerificationError.invalidSignatureFormat
    }
    guard sTLV.tag == ASN1Tag.integer else {
        throw AssertionVerificationError.invalidSignatureFormat
    }
    
    // Extract r and s as big-endian integers
    let rBytes = signatureDER.subdata(in: rTLV.valueRange)
    let sBytes = signatureDER.subdata(in: sTLV.valueRange)
    
    // Remove leading zero padding if present (DER INTEGER encoding)
    let r = removeLeadingZeros(rBytes)
    let sOriginal = removeLeadingZeros(sBytes)
    
    // Compare s with n/2 (halfN = n >> 1)
    let halfN = shiftRight(nBytes, by: 1)
    let sNeedsNormalization = compareBigEndian(sOriginal, halfN) > 0
    
    let sNormalized: Data
    if sNeedsNormalization {
        // s > n/2, normalize: s = n - s
        sNormalized = subtractBigEndian(nBytes, sOriginal)
    } else {
        sNormalized = sOriginal
    }
    
    // Re-encode to DER SEQUENCE
    let rDER = encodeIntegerDER(r)
    let sDER = encodeIntegerDER(sNormalized)
    
    // Build SEQUENCE { r, s }
    var sequence = Data()
    sequence.append(0x30) // SEQUENCE tag
    let contentLength = rDER.count + sDER.count
    sequence.append(contentsOf: encodeLength(contentLength))
    sequence.append(contentsOf: rDER)
    sequence.append(contentsOf: sDER)
    
    return sequence
}

// MARK: - Big Integer Helpers

/// Removes leading zero bytes from a big-endian integer, preserving at least one byte if all zeros
private func removeLeadingZeros(_ data: Data) -> Data {
    var start = 0
    while start < data.count - 1 && data[start] == 0 && (data[start + 1] & 0x80 == 0) {
        start += 1
    }
    return data.subdata(in: start..<data.count)
}

/// Compares two big-endian integers
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b
private func compareBigEndian(_ a: Data, _ b: Data) -> Int {
    let aNorm = removeLeadingZeros(a)
    let bNorm = removeLeadingZeros(b)
    
    if aNorm.count < bNorm.count { return -1 }
    if aNorm.count > bNorm.count { return 1 }
    
    for i in 0..<aNorm.count {
        if aNorm[i] < bNorm[i] { return -1 }
        if aNorm[i] > bNorm[i] { return 1 }
    }
    return 0
}

/// Right-shifts a big-endian integer by one bit
private func shiftRight(_ data: Data, by bits: Int) -> Data {
    guard bits == 1 else { fatalError("Only shift by 1 bit supported") }
    var result = Data()
    var carry: UInt8 = 0
    for i in (0..<data.count).reversed() {
        let byte = data[i]
        result.insert((byte >> 1) | carry, at: 0)
        carry = (byte & 0x01) << 7
    }
    // Remove leading zeros
    return removeLeadingZeros(result)
}

/// Subtracts two big-endian integers: a - b (where a >= b)
private func subtractBigEndian(_ a: Data, _ b: Data) -> Data {
    let aNorm = removeLeadingZeros(a)
    let bNorm = removeLeadingZeros(b)
    
    // Ensure a >= b (for n - s, this should always be true)
    guard compareBigEndian(aNorm, bNorm) >= 0 else {
        // This shouldn't happen for n - s, but handle gracefully
        return Data(repeating: 0, count: aNorm.count)
    }
    
    var result = Data()
    var borrow: UInt8 = 0
    
    // Pad b to match a's length
    let bPadded = Data(repeating: 0, count: max(0, aNorm.count - bNorm.count)) + bNorm
    
    for i in (0..<aNorm.count).reversed() {
        let aVal = UInt16(aNorm[i])
        let bVal = UInt16(bPadded[i])
        let borrowVal = UInt16(borrow)
        
        // Check for underflow before subtracting
        if aVal < bVal + borrowVal {
            // Underflow: borrow from next higher byte
            let diff = (256 + aVal) - bVal - borrowVal
            borrow = 1
            result.insert(UInt8(diff & 0xFF), at: 0)
        } else {
            // No underflow
            let diff = aVal - bVal - borrowVal
            borrow = 0
            result.insert(UInt8(diff & 0xFF), at: 0)
        }
    }
    
    return removeLeadingZeros(result)
}

/// Encodes a big-endian integer as DER INTEGER
/// Ensures positive encoding (prepends 0x00 if MSB is set)
private func encodeIntegerDER(_ value: Data) -> Data {
    let normalized = removeLeadingZeros(value)
    var bytes = normalized
    
    // If MSB is set, prepend 0x00 to ensure positive encoding
    if !bytes.isEmpty && (bytes[0] & 0x80) != 0 {
        bytes.insert(0x00, at: 0)
    }
    
    // Ensure at least one byte
    if bytes.isEmpty {
        bytes = Data([0x00])
    }
    
    var der = Data()
    der.append(0x02) // INTEGER tag
    der.append(contentsOf: encodeLength(bytes.count))
    der.append(contentsOf: bytes)
    return der
}

/// Encodes DER length
private func encodeLength(_ length: Int) -> Data {
    if length < 128 {
        return Data([UInt8(length)])
    } else {
        var bytes = Data()
        var len = length
        while len > 0 {
            bytes.insert(UInt8(len & 0xFF), at: 0)
            len >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)]) + bytes
    }
}

// MARK: - Test Helper

/// Test helper to verify ECDSA signature normalization invariants
/// - Parameter signatureDER: DER-encoded ECDSA signature to test
/// - Returns: (normalized: Data, wasHighS: Bool, sNormalized: Data)
/// - Throws: AssertionVerificationError if parsing fails
func testECDSANormalization(signatureDER: Data) throws -> (normalized: Data, wasHighS: Bool, sNormalized: Data) {
    let nBytes = Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    ])
    let halfN = shiftRight(nBytes, by: 1)
    
    // Parse original signature
    var reader = ASN1Reader(signatureDER)
    let seqTLV = try reader.readTLV()
    guard seqTLV.tag == ASN1Tag.sequence, seqTLV.tag.constructed else {
        throw AssertionVerificationError.invalidSignatureFormat
    }
    var seqReader = ASN1Reader(signatureDER.subdata(in: seqTLV.valueRange))
    _ = try seqReader.readTLV() // r
    let sTLV = try seqReader.readTLV()
    guard sTLV.tag == ASN1Tag.integer else {
        throw AssertionVerificationError.invalidSignatureFormat
    }
    let sOriginal = removeLeadingZeros(signatureDER.subdata(in: sTLV.valueRange))
    let wasHighS = compareBigEndian(sOriginal, halfN) > 0
    
    // Normalize
    let normalized = try normalizeECDSASignatureToLowS(signatureDER: signatureDER)
    
    // Extract normalized s
    var normReader = ASN1Reader(normalized)
    let normSeqTLV = try normReader.readTLV()
    var normSeqReader = ASN1Reader(normalized.subdata(in: normSeqTLV.valueRange))
    _ = try normSeqReader.readTLV() // skip r
    let sNormTLV = try normSeqReader.readTLV()
    let sNormalized = removeLeadingZeros(normalized.subdata(in: sNormTLV.valueRange))
    
    // Assert invariant: sNormalized <= halfN
    let sIsLow = compareBigEndian(sNormalized, halfN) <= 0
    if !sIsLow {
        fatalError("ECDSA normalization invariant violated: normalized s > halfN")
    }
    
    return (normalized, wasHighS, sNormalized)
}

enum AssertionVerificationError: Error {
    case invalidPublicKey
    case invalidSignatureFormat
}
