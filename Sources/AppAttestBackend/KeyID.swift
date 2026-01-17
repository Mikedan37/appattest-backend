import Foundation
import Crypto
import Logging

/// Canonical keyID decoding and storage key generation
/// Ensures register and verify use identical keyID handling
enum KeyID {
    /// Decodes a base64-encoded keyID string to raw bytes
    /// - Throws if base64 decoding fails
    /// - Trims whitespace/newlines before decoding
    static func decodeBase64(_ s: String) throws -> Data {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Data(base64Encoded: trimmed) else {
            throw KeyIDError.invalidBase64
        }
        return data
    }
    
    /// Generates a canonical storage key from keyID bytes
    /// Uses SHA256 hash of raw bytes for deterministic storage
    static func storageKey(_ keyIDBytes: Data) -> Data {
        let hash = SHA256.hash(data: keyIDBytes)
        return Data(hash)
    }
    
    /// Logs keyID identity for correlation between register and verify
    static func identityMetadata(_ keyIDBytes: Data, keyIDBase64: String) -> Logger.Metadata {
        let keyIDHash = SHA256.hash(data: keyIDBytes)
        let prefixHex = keyIDBytes.prefix(16).map { String(format: "%02x", $0) }.joined()
        let storageKeyHash = SHA256.hash(data: keyIDBytes)
        
        return [
            "keyID_base64": .string(keyIDBase64),
            "keyID_bytes_length": .string("\(keyIDBytes.count)"),
            "keyID_bytes_prefix_hex": .string(prefixHex),
            "keyID_sha256_hex": .string(keyIDHash.map { String(format: "%02x", $0) }.joined()),
            "storageKey_sha256_hex": .string(storageKeyHash.map { String(format: "%02x", $0) }.joined())
        ]
    }
}

enum KeyIDError: Error {
    case invalidBase64
}
