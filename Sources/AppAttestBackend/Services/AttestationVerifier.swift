//
//  AttestationVerifier.swift
//  AppAttestBackend
//
//  Full App Attest attestation verification (Apple semantics).
//

import Foundation
import Crypto
import AppAttestCore
import Logging

enum AttestationVerificationError: Error {
    case invalidCBOR
    case invalidFormat
    case missingCertificates
    case untrustedRoot
    case invalidIntermediateSignature
    case invalidLeafSignature
    case rootNotSelfSigned
    case missingCredentialData
    case invalidPublicKey
    case keyIDMismatch
    case rpIdHashMismatch
    case counterNotZero
    case aaguidMismatch
    case credentialIdMismatch
    case challengeMissing
    case nonceExtensionMissing
    case nonceExtensionDecodeFailed
    case nonceMismatch
    case clientDataHashInvalidLength
    case clientDataHashMismatch
}

struct AttestationVerificationResult {
    let publicKeyX963: Data
    let environment: String?
    let receipt: Data?
}

struct AttestationVerifier {
    static func verify(
        attestationObject: Data,
        keyIDBytes: Data,
        clientDataHash: Data,
        appIDPrefix: String,
        bundleID: String,
        challengeForAudit: Data?,
        logger: Logger
    ) throws -> AttestationVerificationResult {
        let decoder = AppAttestDecoder()
        let decoded: AttestationObject
        do {
            decoded = try decoder.decodeAttestation(attestationObject)
        } catch {
            throw AttestationVerificationError.invalidCBOR
        }
        
        guard decoded.format == "apple-appattest" else {
            throw AttestationVerificationError.invalidFormat
        }
        
        guard !decoded.attestationStatement.x5c.isEmpty else {
            throw AttestationVerificationError.missingCertificates
        }
        
        // Certificate chain validation (leaf -> intermediates -> root)
        let certs = try decoded.attestationStatement.x5c.map { try X509Certificate.parse(der: $0) }
        try verifyCertificateChain(x5c: certs, logger: logger)
        
        // Extract Apple extensions from leaf
        guard !certs.isEmpty else {
            logger.error("Attestation verification failed: certificate chain is empty after verification")
            throw AttestationVerificationError.missingCertificates
        }
        let leafCert = certs[0]
        let extensions = leafCert.extensions
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            logger.info("CERT_EXTENSIONS_DEBUG [leafCert.extensions.count: \(extensions.count)]")
            for (oid, raw) in extensions {
                let ext = X509Extension.decode(oid: oid, rawValue: raw)
                let extType: String
                switch ext {
                case .appleOID(let o, let decoded):
                    switch decoded.type {
                    case .challenge: extType = "challenge"
                    case .receipt: extType = "receipt"
                    case .environment(let e): extType = "environment(\(e))"
                    case .keyPurpose(let p): extType = "keyPurpose(\(p))"
                    case .osVersion(let v): extType = "osVersion(\(v))"
                    case .deviceClass(let d): extType = "deviceClass(\(d))"
                    case .unknown: extType = "unknown"
                    }
                case .unknown(let o, _): 
                    extType = "unknown(\(o))"
                    if oid == "1.2.840.113635.100.8.2" {
                        let prefix = raw.prefix(8).map { String(format: "%02x", $0) }.joined()
                        logger.info("CERT_EXTENSIONS_DEBUG [CHALLENGE_EXT_RAW prefix8: \(prefix), fullLength: \(raw.count)]")
                    }
                default: extType = "standard"
                }
                logger.info("CERT_EXTENSIONS_DEBUG [oid: \(oid), type: \(extType), rawLength: \(raw.count)]")
            }
        }
        var environment: String? = nil
        var receipt: Data? = nil
        var challengeExt: Data? = nil
        var challengeExtRaw: Data? = nil
        var challengeExtOIDFound = false
        
        for (oid, raw) in extensions {
            if oid == "1.2.840.113635.100.8.2" {
                challengeExtOIDFound = true
                challengeExtRaw = raw
            }
            let ext = X509Extension.decode(oid: oid, rawValue: raw)
            if case .appleOID(_, let decoded) = ext {
                switch decoded.type {
                case .environment(let env): environment = env
                case .receipt: receipt = raw
                case .challenge(let c): challengeExt = c
                default: break
                }
            }
        }
        
        // Validate clientDataHash length (must be exactly 32 bytes)
        guard clientDataHash.count == 32 else {
            throw AttestationVerificationError.clientDataHashInvalidLength
        }
        
        // Optional audit check: if challenge is provided, log warning if mismatch (diagnostic only, does not block)
        if let challenge = challengeForAudit {
            let expectedClientDataHash = SHA256.hash(data: challenge)
            if Data(expectedClientDataHash) != clientDataHash {
                logger.warning("CLIENT_DATA_HASH_AUDIT [challenge provided but SHA256(challenge) != clientDataHash; using provided clientDataHash for nonce computation]")
            }
        }
        
        // Nonce validation: nonce = SHA256(authenticatorData || clientDataHash)
        let authDataBytes = decoded.authenticatorData.rawData
        let nonceInput = authDataBytes + clientDataHash
        let nonce = SHA256.hash(data: nonceInput)
        let nonceData = Data(nonce)
        
        // Debug logging (env-gated)
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_NONCE"] == "1" {
            let decodedNonceHex = challengeExt.map { sha256Hex($0) } ?? "nil"
            logger.info("CERT_NONCE_DEBUG [authenticatorData.length: \(authDataBytes.count), clientDataHash.hex: \(clientDataHash.map { String(format: "%02x", $0) }.joined()), nonceInput.length: \(nonceInput.count), computedNonce.hex: \(sha256Hex(nonceData)), decodedNonce.hex: \(decodedNonceHex)]")
        }
        
        guard challengeExtOIDFound else { throw AttestationVerificationError.nonceExtensionMissing }
        guard let challengeValue = challengeExt else { throw AttestationVerificationError.nonceExtensionDecodeFailed }
        guard challengeValue == nonceData else { throw AttestationVerificationError.nonceMismatch }
        
        // Authenticator data checks
        let authData = decoded.authenticatorData
        guard authData.signCount == 0 else { throw AttestationVerificationError.counterNotZero }
        
        guard let credData = authData.attestedCredentialData else {
            throw AttestationVerificationError.missingCredentialData
        }
        
        let expectedAppID = "\(appIDPrefix).\(bundleID)"
        let expectedRpIdHash = SHA256.hash(data: Data(expectedAppID.utf8))
        guard authData.rpIdHash == Data(expectedRpIdHash) else {
            throw AttestationVerificationError.rpIdHashMismatch
        }
        
        let devAAGUID = Data("appattestdevelop".utf8)
        let prodAAGUID = Data("appattest".utf8) + Data(repeating: 0, count: 8)
        guard credData.aaguid == devAAGUID || credData.aaguid == prodAAGUID else {
            throw AttestationVerificationError.aaguidMismatch
        }
        
        guard credData.credentialId == keyIDBytes else {
            throw AttestationVerificationError.credentialIdMismatch
        }
        
        // Extract BOTH candidate keys for comparison (COSE vs Certificate)
        // Key 1: COSE credentialPublicKey (for comparison only, NOT used for verification)
        let cosePublicKeyX963: Data?
        if let coseKey = extractPublicKeyFromCOSEKey(credData.credentialPublicKey, logger: logger),
           coseKey.count == 65, coseKey[0] == 0x04 {
            cosePublicKeyX963 = coseKey
        } else {
            cosePublicKeyX963 = nil
        }
        
        // Key 2: Leaf certificate SubjectPublicKeyInfo (CORRECT - used for assertion verification)
        guard let leafPublicKeyBits = leafCert.subjectPublicKeyBits,
              leafPublicKeyBits.count == 65,
              leafPublicKeyBits[0] == 0x04 else {
            logger.error("Attestation verification failed: leaf certificate public key invalid format [length: \(leafCert.subjectPublicKeyBits?.count ?? 0), firstByte: \(leafCert.subjectPublicKeyBits?.first.map { String(format: "0x%02x", $0) } ?? "nil")]")
            throw AttestationVerificationError.invalidPublicKey
        }
        
        let certificatePublicKeyX963 = leafPublicKeyBits
        
        // DETECT KEYID-AS-PUBLIC-KEY BUG: Only flag actual bugs, NOT keyID == SHA256(publicKey) which is NORMAL
        func detectKeyIDBug(_ key: Data, source: String, keyIDBytes: Data) -> Bool {
            // Bug 1: Wrong length (must be 65 bytes for x963)
            if key.count != 65 {
                logger.error("BUG_DETECTED [\(source) key has wrong length: \(key.count), expected 65]")
                return true
            }
            
            // Bug 2: Wrong format (must start with 0x04 for uncompressed)
            if key[0] != 0x04 {
                logger.error("BUG_DETECTED [\(source) key has wrong format: first byte 0x\(String(format: "%02x", key[0])), expected 0x04]")
                return true
            }
            
            // Bug 3: Public key is exactly 32 bytes (keyID length) - someone used keyID as public key
            if key.count == 32 {
                logger.error("BUG_DETECTED [\(source) key is 32 bytes (keyID length) - keyID was used as public key] [key_hex: \(dataToHex(key)), keyID_hex: \(dataToHex(keyIDBytes))]")
                return true
            }
            
            // Bug 4: Public key starts with keyID bytes (keyID was padded/constructed into public key)
            if key.count >= 32 && key.prefix(32) == keyIDBytes {
                logger.error("BUG_DETECTED [\(source) key starts with keyID bytes - keyID was padded into public key] [key_prefix_hex: \(dataToHex(key.prefix(32))), keyID_hex: \(dataToHex(keyIDBytes))]")
                return true
            }
            
            return false
        }
        
        // Log BOTH keys for cross-check (proves which one we're using)
        if let coseKey = cosePublicKeyX963 {
            let (cosePrefix, coseSuffix) = hexPrefixSuffix(coseKey, n: 16)
            logger.info("REGISTER_KEY_COMPARISON [source: cose, length: \(coseKey.count), firstByte: 0x\(String(format: "%02x", coseKey[0])), hex_prefix: \(cosePrefix), hex_suffix: \(coseSuffix), sha256: \(sha256Hex(coseKey))]")
            
            // Detect keyID bug in COSE key
            if detectKeyIDBug(coseKey, source: "COSE", keyIDBytes: keyIDBytes) {
                throw AttestationVerificationError.invalidPublicKey
            }
        } else {
            logger.warning("REGISTER_KEY_COMPARISON [source: cose, EXTRACTION_FAILED]")
        }
        
        let (certPrefix, certSuffix) = hexPrefixSuffix(certificatePublicKeyX963, n: 16)
        logger.info("REGISTER_KEY_COMPARISON [source: certificate, length: \(certificatePublicKeyX963.count), firstByte: 0x\(String(format: "%02x", certificatePublicKeyX963[0])), hex_prefix: \(certPrefix), hex_suffix: \(certSuffix), sha256: \(sha256Hex(certificatePublicKeyX963)), STORED_PUBLIC_KEY_SOURCE: certificate]")
        
        // Detect keyID bug in certificate key
        if detectKeyIDBug(certificatePublicKeyX963, source: "certificate", keyIDBytes: keyIDBytes) {
            throw AttestationVerificationError.invalidPublicKey
        }
        
        // Verify keys match (they should, but log if they don't)
        if let coseKey = cosePublicKeyX963, coseKey != certificatePublicKeyX963 {
            logger.warning("REGISTER_KEY_MISMATCH [COSE key and certificate key differ - using certificate key for verification]")
        }
        
        // Key binding: keyID == SHA256(publicKeyX963) - verify against certificate key
        let computedKeyID = Data(SHA256.hash(data: certificatePublicKeyX963))
        if computedKeyID == keyIDBytes {
            // This is NORMAL in App Attest - log it as expected
            logger.info("KEYID_DERIVATION: keyIDHex == sha256(pubKeyX963) (expected) [keyID_hex: \(dataToHex(keyIDBytes)), pubKey_sha256: \(sha256Hex(certificatePublicKeyX963))]")
        } else {
            logger.error("Attestation verification failed: keyID mismatch [computed: \(sha256Hex(computedKeyID)), provided: \(sha256Hex(keyIDBytes))]")
            throw AttestationVerificationError.keyIDMismatch
        }
        
        // Store the certificate key (the correct one for assertion verification)
        let publicKeyX963 = certificatePublicKeyX963
        
        return AttestationVerificationResult(publicKeyX963: publicKeyX963, environment: environment, receipt: receipt)
    }
    
    private static func verifyCertificateChain(x5c: [X509Certificate], logger: Logger) throws {
        guard !x5c.isEmpty else { throw AttestationVerificationError.missingCertificates }
        let allowUnverifiedRoot = (ProcessInfo.processInfo.environment["APP_ATTEST_ALLOW_UNVERIFIED_ROOT"] ?? "false").lowercased() == "true"
#if DEBUG
        let skipRootSignatureVerification = allowUnverifiedRoot
        if skipRootSignatureVerification {
            logger.warning("DEV MODE: Skipping App Attestation root signature verification")
        }
#else
        let skipRootSignatureVerification = false
        if allowUnverifiedRoot {
            logger.warning("DEV MODE flag ignored in RELEASE: root verification enforced")
        }
#endif
        
        let pinnedRootDER = try loadPinnedAppAttestationRootDER()
        let pinnedRoot = try X509Certificate.parse(der: pinnedRootDER)
        let pinnedRootDERHash = sha256Hex(pinnedRootDER)
        
        // Log DER hashes for all certs in chain
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            logger.info("CERT_CHAIN_DEBUG [pinnedRootDER.sha256: \(pinnedRootDERHash), x5c.count: \(x5c.count)]")
            for (idx, cert) in x5c.enumerated() {
                let certDERHash = sha256Hex(cert.der)
                let matchesPinnedRoot = cert.der == pinnedRootDER
                logger.info("CERT_CHAIN_DEBUG [x5c[\(idx)].der.sha256: \(certDERHash), matchesPinnedRoot: \(matchesPinnedRoot), subject: \(cert.subject.description)]")
            }
        }
        
        // Identify which cert (if any) matches the pinned root by DER hash
        var rootIndex: Int? = nil
        for (idx, cert) in x5c.enumerated() {
            if cert.der == pinnedRootDER {
                rootIndex = idx
                break
            }
        }
        
        // Verify leaf with intermediate (x5c[1] or next cert after leaf)
        guard x5c.count >= 2 else { throw AttestationVerificationError.missingCertificates }
        let leaf = x5c[0]
        let intermediate = x5c[1]
        
        // Leaf must be signed by intermediate
        try verifyCertificateSignature(child: leaf, issuer: intermediate, failure: .invalidLeafSignature, logger: logger)
        
        // Intermediate must be signed by pinned root (unless intermediate IS the root)
        if rootIndex == 1 {
            // x5c[1] is the root - skip intermediate verification, will verify pinned root self-signature below
            if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
                logger.info("CERT_CHAIN_DEBUG [x5c[1] matches pinned root, skipping intermediate verification (will verify pinned root self-signature)]")
            }
        } else {
            // Intermediate is signed by pinned root
            if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
                logger.info("CERT_CHAIN_DEBUG [x5c[1] does not match pinned root, verifying against pinned root]")
            }
            try verifyCertificateSignature(child: intermediate, issuer: pinnedRoot, failure: .invalidIntermediateSignature, logger: logger)
        }
        
        // If chain includes root (x5c.count >= 3), verify it matches pinned root
        if x5c.count >= 3 {
            guard let chainRoot = x5c.last else {
                logger.error("Attestation verification failed: x5c chain is empty despite count check")
                throw AttestationVerificationError.untrustedRoot
            }
            guard chainRoot.der == pinnedRootDER else {
                throw AttestationVerificationError.untrustedRoot
            }
            if !skipRootSignatureVerification {
                try verifyCertificateSignature(child: chainRoot, issuer: chainRoot, failure: .untrustedRoot, logger: logger)
            }
        }
        
        // Verify pinned root self-signature (optional sanity check)
        // Skip if a chain cert already matched the pinned root (we trust it by pinning, not by self-signature)
        if !skipRootSignatureVerification && rootIndex == nil {
            if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
                logger.info("CERT_CHAIN_DEBUG [no chain cert matched pinned root, verifying pinned root self-signature]")
            }
            try verifyCertificateSignature(child: pinnedRoot, issuer: pinnedRoot, failure: .untrustedRoot, logger: logger)
        } else if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            logger.info("CERT_CHAIN_DEBUG [chain cert matched pinned root, skipping pinned root self-signature verification (trusted by pinning)]")
        }
    }

    private static func isPinnedAppleAppAttestationRoot(cert: X509Certificate) throws -> Bool {
        let pinnedRootDER = try loadPinnedAppAttestationRootDER()
        let pinnedRoot = try X509Certificate.parse(der: pinnedRootDER)
        return cert.der == pinnedRoot.der
    }
    
    private static func verifyCertificateSignature(child: X509Certificate, issuer: X509Certificate, failure: AttestationVerificationError, logger: Logger) throws {
        let parsed: (tbs: Data, sigAlgOID: String, signature: Data, signatureUnusedBits: UInt8)
        do {
            parsed = try extractTBSCertificateAndSignature(certDER: child.der, logger: logger)
        } catch {
            throw failure
        }
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            let tbsSha = sha256Hex(parsed.tbs)
            let sigSha = sha256Hex(parsed.signature)
            logger.info("CERT_SIG_DEBUG [childSubject: \(child.subject.description), issuerSubject: \(issuer.subject.description), sigAlgOID: \(parsed.sigAlgOID), tbsDER.count: \(parsed.tbs.count), tbsDER.sha256: \(tbsSha), signatureDER.count: \(parsed.signature.count), signatureDER.sha256: \(sigSha), signatureUnusedBits: \(parsed.signatureUnusedBits)]")
        }
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            if let issuerKeyBits = issuer.subjectPublicKeyBits {
                let prefix = issuerKeyBits.prefix(4).map { String(format: "%02x", $0) }.joined()
                let curveOID = issuer.subjectPublicKeyCurveOID ?? "unknown"
                logger.info("CERT_SIG_DEBUG_ISSUER [issuerPublicKeyX963.count: \(issuerKeyBits.count), issuerPublicKeyX963.prefix4: \(prefix), curveOID: \(curveOID)]")
            } else {
                logger.info("CERT_SIG_DEBUG_ISSUER [issuerPublicKeyX963: nil, curveOID: \(issuer.subjectPublicKeyCurveOID ?? "unknown")]")
            }
        }
        guard let issuerKeyBits = issuer.subjectPublicKeyBits,
              issuerKeyBits.count >= 1,
              issuerKeyBits[0] == 0x04 else {
            throw failure
        }
        if ProcessInfo.processInfo.environment["APP_ATTEST_DEBUG_CERT_SIG"] == "1" {
            let issuerKeySha = sha256Hex(issuerKeyBits)
            logger.info("CERT_SIG_DEBUG_ISSUER [issuerPublicKeyX963.sha256: \(issuerKeySha), issuerPublicKeyX963.count: \(issuerKeyBits.count)]")
        }

        let curveOID = issuer.subjectPublicKeyCurveOID
        let usesP256 = (issuerKeyBits.count == 65) || (curveOID == "1.2.840.10045.3.1.7")
        let usesP384 = (issuerKeyBits.count == 97) || (curveOID == "1.3.132.0.34")
        guard usesP256 || usesP384 else { throw failure }

        // Determine hash based on signature algorithm OID.
        let isSHA256 = parsed.sigAlgOID == "1.2.840.10045.4.3.2"
        let isSHA384 = parsed.sigAlgOID == "1.2.840.10045.4.3.3"
        guard isSHA256 || isSHA384 else { throw failure }

        if usesP256 {
            let issuerKey = try P256.Signing.PublicKey(x963Representation: issuerKeyBits)
            let signature = try P256.Signing.ECDSASignature(derRepresentation: parsed.signature)
            if isSHA256 {
                let digest = SHA256.hash(data: parsed.tbs)
                guard issuerKey.isValidSignature(signature, for: digest) else { throw failure }
            } else {
                let digest = SHA384.hash(data: parsed.tbs)
                guard issuerKey.isValidSignature(signature, for: digest) else { throw failure }
            }
        } else {
            let issuerKey = try P384.Signing.PublicKey(x963Representation: issuerKeyBits)
            let signature = try P384.Signing.ECDSASignature(derRepresentation: parsed.signature)
            if isSHA256 {
                let digest = SHA256.hash(data: parsed.tbs)
                guard issuerKey.isValidSignature(signature, for: digest) else { throw failure }
            } else {
                let digest = SHA384.hash(data: parsed.tbs)
                guard issuerKey.isValidSignature(signature, for: digest) else { throw failure }
            }
        }
    }
    
    private static func extractTBSCertificateAndSignature(certDER: Data, logger: Logger) throws -> (tbs: Data, sigAlgOID: String, signature: Data, signatureUnusedBits: UInt8) {
        let certTLV = try readTLVRange(from: certDER, at: 0)
        let certBodyStart = certTLV.valueRange.lowerBound
        var cursor = certBodyStart
        
        let tbsTLV = try readTLVRange(from: certDER, at: cursor)
        cursor = tbsTLV.tlvRange.upperBound
        
        let sigAlgTLV = try readTLVRange(from: certDER, at: cursor)
        cursor = sigAlgTLV.tlvRange.upperBound
        
        let sigTLV = try readTLVRange(from: certDER, at: cursor)
        
        let tbsDER = certDER.subdata(in: tbsTLV.tlvRange)
        
        var sigAlgOID: String = ""
        var sigAlgReader = ASN1Reader(certDER.subdata(in: sigAlgTLV.valueRange))
        sigAlgOID = (try? sigAlgReader.readOID()) ?? ""
        
        let sigBytes = certDER.subdata(in: sigTLV.valueRange)
        guard sigBytes.count > 1 else { throw AttestationVerificationError.invalidLeafSignature }
        let signatureUnusedBits = sigBytes[0]
        let signature = sigBytes.subdata(in: sigBytes.startIndex + 1..<sigBytes.endIndex)
        
        return (tbsDER, sigAlgOID, signature, signatureUnusedBits)
    }

    private struct TLVRange {
        let tag: UInt8
        let length: Int
        let headerLen: Int
        let valueRange: Range<Int>
        let tlvRange: Range<Int>
    }

    private static func readTLVRange(from data: Data, at offset: Int) throws -> TLVRange {
        guard offset < data.count, offset + 1 < data.count else {
            throw AttestationVerificationError.invalidLeafSignature
        }
        let tag = data[offset]
        let lenByte = data[offset + 1]
        var length = 0
        var headerLen = 2
        
        if lenByte & 0x80 == 0 {
            length = Int(lenByte)
        } else {
            let count = Int(lenByte & 0x7F)
            guard count > 0, count <= 4 else { throw AttestationVerificationError.invalidLeafSignature }
            guard offset + 2 + count <= data.count else { throw AttestationVerificationError.invalidLeafSignature }
            headerLen = 2 + count
            var v = 0
            for i in 0..<count {
                v = (v << 8) | Int(data[offset + 2 + i])
            }
            length = v
        }
        
        let valueStart = offset + headerLen
        let valueEnd = valueStart + length
        guard valueEnd <= data.count else { throw AttestationVerificationError.invalidLeafSignature }
        return TLVRange(
            tag: tag,
            length: length,
            headerLen: headerLen,
            valueRange: valueStart..<valueEnd,
            tlvRange: offset..<valueEnd
        )
    }
}
