//
//  Utilities.swift
//  AppAttestBackend
//
//  Shared helpers (hashing, storage keys, COSE key extraction).
//

import Foundation
import Crypto
import AppAttestCore
import Logging

// Pinning is required to anchor App Attest trust to Apple PKI.
private let pinnedAppleAppAttestationRootPEM = """
-----BEGIN CERTIFICATE-----
MIICQzCCAcigAwIBAgIQCbrF4bxAGtnUU5W8OBoIVDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODM5NTVa
Fw0zMDAzMTMwMDAwMDBaME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlv
biBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlh
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAErls3oHdNebI1j0Dn0fImJvHCX+8XgC3q
s4JqWYdP+NKtFSV4mqJmBBkSSLY8uWcGnpjTY71eNw+/oI4ynoBzqYXndG6jWaL2
bynbMq9FXiEWWNVnr54mfrJhTcIaZs6Zo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEA
MB8GA1UdIwQYMBaAFKyREFMzvb5oQf+nDKnl+url5YqhMB0GA1UdDgQWBBQ+410c
BBmpybQx+IR01uHhV3LjmzAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaQAw
ZgIxALu+iI1zjQUCz7z9Zm0JV1A1vNaHLD+EMEkmKe3R+RToeZkcmui1rvjTqFQz
97YNBgIxAKs47dDMge0ApFLDukT5k2NlU/7MKX8utN+fXr5aSsq2mVxLgg35BDhv
eAe7WJQ5tw==
-----END CERTIFICATE-----
"""

func loadPinnedAppAttestationRootDER() throws -> Data {
    if let envPem = ProcessInfo.processInfo.environment["APP_ATTEST_ROOT_PEM"], !envPem.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
        return try pemToDER(envPem)
    }
    return try pemToDER(pinnedAppleAppAttestationRootPEM)
}

func pemToDER(_ pem: String) throws -> Data {
    let lines = pem
        .split(whereSeparator: \.isNewline)
        .filter { !$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END") }
        .joined()
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard !lines.isEmpty, !lines.contains("REPLACE_WITH") else {
        throw AttestationVerificationError.untrustedRoot
    }
    guard let der = Data(base64Encoded: lines) else {
        throw AttestationVerificationError.untrustedRoot
    }
    return der
}

func derToPEM(_ der: Data) -> String {
    let b64 = der.base64EncodedString()
    var lines: [String] = []
    lines.reserveCapacity((b64.count / 64) + 1)
    var index = b64.startIndex
    while index < b64.endIndex {
        let end = b64.index(index, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
        lines.append(String(b64[index..<end]))
        index = end
    }
    return (["-----BEGIN CERTIFICATE-----"] + lines + ["-----END CERTIFICATE-----"]).joined(separator: "\n")
}

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func hexPrefixSuffix(_ data: Data, n: Int = 16) -> (prefix: String, suffix: String) {
    let prefix = data.prefix(n).map { String(format: "%02x", $0) }.joined()
    let suffix = data.suffix(n).map { String(format: "%02x", $0) }.joined()
    return (prefix: prefix, suffix: suffix)
}

func dataToHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func dataFromHex(_ hex: String) -> Data? {
    let h = hex.trimmingCharacters(in: .whitespaces).lowercased()
    guard h.count % 2 == 0 else { return nil }
    var d = Data(capacity: h.count / 2)
    var i = h.startIndex
    while i < h.endIndex {
        let j = h.index(i, offsetBy: 2)
        guard let b = UInt8(h[i..<j], radix: 16) else { return nil }
        d.append(b)
        i = j
    }
    return d
}

func firstDifferingByteIndex(_ a: Data, _ b: Data) -> Int {
    let n = min(a.count, b.count)
    for i in 0..<n { if a[i] != b[i] { return i } }
    return n
}

func makeStorageKey(keyIDBytes: Data, flowID: String) -> String? {
    guard keyIDBytes.count == 32 else { return nil }
    guard !flowID.isEmpty else { return nil }
    let keyIDHex = keyIDBytes.map { String(format: "%02x", $0) }.joined()
    return "\(keyIDHex):\(flowID)"
}

func storageKeyHex(from keyIDBytes: Data) -> String {
    sha256Hex(keyIDBytes)
}

func base64urlEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func buildClientDataJSON(challenge: Data, bundleID: String) -> Data {
    let challengeBase64url = base64urlEncode(challenge)
    let jsonString = "{\"type\":\"apple-appattest\",\"challenge\":\"\(challengeBase64url)\",\"origin\":\"\(bundleID)\"}"
    guard let data = jsonString.data(using: .utf8) else {
        // This should never happen with valid UTF-8 strings, but handle gracefully
        return Data() // Return empty data as fallback
    }
    return data
}

func extractPublicKeyFromCOSEKey(_ coseKey: CBORValue, logger: Logger? = nil) -> Data? {
    guard case .map(let pairs) = coseKey else { return nil }
    var xData: Data? = nil
    var yData: Data? = nil
    var kty: UInt64? = nil
    var crv: UInt64? = nil
    for (key, value) in pairs {
        if case .unsigned(1) = key, case .unsigned(let ktyVal) = value { kty = ktyVal }
        else if case .negative(-1) = key, case .unsigned(let crvVal) = value { crv = crvVal }
        else if case .negative(-2) = key, case .byteString(let xBytes) = value { xData = xBytes }
        else if case .negative(-3) = key, case .byteString(let yBytes) = value { yData = yBytes }
    }
    guard kty == 2, crv == 1 else { return nil }
    guard let x = xData, let y = yData else { return nil }
    
    func normalize(_ coord: Data) -> Data? {
        if coord.count == 32 { return coord }
        if coord.count < 32 {
            var normalized = Data(count: 32 - coord.count)
            normalized.append(coord)
            return normalized
        }
        return nil
    }
    guard let xNorm = normalize(x), let yNorm = normalize(y) else { return nil }
    var publicKey = Data([0x04])
    publicKey.append(xNorm)
    publicKey.append(yNorm)
    guard publicKey.count == 65, publicKey[0] == 0x04 else { return nil }
    return publicKey
}

/// Converts x963 uncompressed public key (0x04 || X || Y) to PEM SPKI format for OpenSSL.
/// Uses OpenSSL command-line tool to perform the conversion (more reliable than manual ASN.1 encoding).
/// - Parameter publicKey: 65-byte x963 format public key
/// - Returns: PEM-encoded SubjectPublicKeyInfo, or nil if conversion fails
func convertX963ToPEM(publicKey: Data) -> Data? {
    guard publicKey.count == 65, publicKey[0] == 0x04 else { return nil }
    
    // Use OpenSSL to convert x963 to PEM SPKI
    // Write x963 key to temp file
    let tempDir = URL(fileURLWithPath: "/tmp/appattest-keyconv")
    try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    
    let x963File = tempDir.appendingPathComponent("key.x963")
    let pemFile = tempDir.appendingPathComponent("key.pem")
    
    do {
        try publicKey.write(to: x963File)
    } catch {
        return nil
    }
    
    // Use openssl ec -inform DER -pubin to convert
    // But x963 is not DER, so we need to construct SPKI manually or use a different approach
    // Actually, let's use openssl ecparam to generate a key and then replace the public point
    // Or better: construct the SPKI DER manually
    
    // Manual SPKI construction for P-256
    // AlgorithmIdentifier OIDs:
    // 1.2.840.10045.2.1 (ecPublicKey) = 06 07 2a 86 48 ce 3d 02 01
    // 1.2.840.10045.3.1.7 (secp256r1) = 06 08 2a 86 48 ce 3d 03 01 07
    
    // AlgorithmIdentifier SEQUENCE
    let algID: Data = Data([
        0x30, 0x13, // SEQUENCE, length 19
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID: 1.2.840.10045.2.1
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 // OID: 1.2.840.10045.3.1.7
    ])
    
    // BIT STRING: 0x03 || length || unusedBits(0) || publicKey
    var bitString = Data([0x03]) // BIT STRING tag
    let bitStringValueLen = 1 + publicKey.count // unusedBits byte + 65 bytes
    if bitStringValueLen < 0x80 {
        bitString.append(UInt8(bitStringValueLen))
    } else if bitStringValueLen < 0x100 {
        bitString.append(0x81)
        bitString.append(UInt8(bitStringValueLen))
    } else {
        bitString.append(0x82)
        bitString.append(UInt8(bitStringValueLen >> 8))
        bitString.append(UInt8(bitStringValueLen & 0xFF))
    }
    bitString.append(0x00) // unusedBits = 0
    bitString.append(contentsOf: publicKey)
    
    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    var spki = Data([0x30]) // SEQUENCE tag
    let spkiLen = algID.count + bitString.count
    if spkiLen < 0x80 {
        spki.append(UInt8(spkiLen))
    } else if spkiLen < 0x100 {
        spki.append(0x81)
        spki.append(UInt8(spkiLen))
    } else {
        spki.append(0x82)
        spki.append(UInt8(spkiLen >> 8))
        spki.append(UInt8(spkiLen & 0xFF))
    }
    spki.append(contentsOf: algID)
    spki.append(contentsOf: bitString)
    
    // Convert to PEM
    let base64 = spki.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
    let pem = "-----BEGIN PUBLIC KEY-----\n\(base64)\n-----END PUBLIC KEY-----\n"
    
    // Cleanup
    try? FileManager.default.removeItem(at: x963File)
    
    return pem.data(using: .utf8)
}
