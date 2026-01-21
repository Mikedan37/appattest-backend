import Foundation
import Crypto

/// Public key fingerprint for lineage tracking across REGISTER → STORE → VERIFY.
///
/// This struct provides a stable, comparable representation of a public key
/// that can be used to prove key identity across the entire App Attest flow.
struct PublicKeyFingerprint {
    let x963Len: Int
    let firstByteHex: String
    let sha256Hex: String
    let prefixHex: String  // First 16 bytes as hex
    
    /// Creates a fingerprint from raw X9.63 public key bytes.
    /// - Parameter data: 65-byte uncompressed public key (0x04 || X || Y)
    /// - Returns: Fingerprint or nil if data is invalid
    static func fromX963(_ data: Data) -> PublicKeyFingerprint? {
        guard data.count == 65, data[0] == 0x04 else {
            return nil
        }
        
        let sha256Hash = SHA256.hash(data: data)
        let sha256Hex = sha256Hash.map { String(format: "%02x", $0) }.joined()
        let prefixHex = data.prefix(16).map { String(format: "%02x", $0) }.joined()
        let firstByteHex = String(format: "%02x", data[0])
        
        return PublicKeyFingerprint(
            x963Len: data.count,
            firstByteHex: firstByteHex,
            sha256Hex: sha256Hex,
            prefixHex: prefixHex
        )
    }
    
    /// Compares two fingerprints for equality.
    /// - Parameter other: Another fingerprint to compare
    /// - Returns: true if all fields match
    func matches(_ other: PublicKeyFingerprint) -> Bool {
        return x963Len == other.x963Len &&
               firstByteHex == other.firstByteHex &&
               sha256Hex == other.sha256Hex &&
               prefixHex == other.prefixHex
    }
}
