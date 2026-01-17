import XCTest
@testable import AppAttestBackend
import Crypto
import Foundation

/// Optional test for real Apple App Attest vectors captured from successful end-to-end verification.
///
/// **Purpose:**
/// - Tests backend verifier with real Apple-generated signatures
/// - Validates that backend correctly verifies actual App Attest assertions
/// - Only runs when explicitly enabled via RUN_APPLE_VECTORS=1 environment variable
///
/// **Test Design:**
/// - Uses hardcoded Base64-encoded vectors from real App Attest verification
/// - Extracted from `/tmp/appattest/` artifacts after successful end-to-end verification
/// - Tests the same verification path as production
///
/// **How to populate:**
/// 1. Fix frontend clientDataHash lifecycle bug
/// 2. Get successful end-to-end verification
/// 3. Extract vectors from `/tmp/appattest/` artifacts:
///    ```bash
///    latest=$(ls -t /tmp/appattest/*_pubkey.x963 | head -1 | sed 's/_pubkey.x963//')
///    base64 -w 0 "${latest}_pubkey.x963"
///    base64 -w 0 "${latest}_message.bin" | head -c <N>  # authenticatorData
///    base64 -w 0 "${latest}_message.bin" | tail -c 32   # clientDataHash
///    base64 -w 0 "${latest}_signature.der"
///    ```
/// 4. Update test vectors below
/// 5. Run: `RUN_APPLE_VECTORS=1 swift test --filter AppleGoldenVectorTests`
///
/// **Interpretation:**
/// - ✅ Pass → Backend correctly verifies real Apple signatures
/// - ❌ Fail → Backend may have issues with real App Attest format (check vectors are correct)
final class AppleGoldenVectorTests: XCTestCase {
    
    // MARK: - Test Vectors (Base64-encoded from real App Attest verification)
    
    // Public key (X9.63 uncompressed, 65 bytes)
    // Extract from: /tmp/appattest/*_pubkey.x963
    let testPublicKeyX963Base64 = "PLACEHOLDER_REPLACE_WITH_REAL_KEY"
    
    // AuthenticatorData (variable length, typically 37+ bytes)
    // Extract from: /tmp/appattest/*_message.bin (first N bytes)
    let testAuthenticatorDataBase64 = "PLACEHOLDER_REPLACE_WITH_REAL_AUTHDATA"
    
    // ClientDataHash (32 bytes, SHA256)
    // Extract from: /tmp/appattest/*_message.bin (last 32 bytes)
    // CRITICAL: Must be the EXACT same clientDataHash used when signature was created
    let testClientDataHashBase64 = "PLACEHOLDER_REPLACE_WITH_REAL_CLIENTDATAHASH"
    
    // Signature (DER-encoded ECDSA, typically 70-72 bytes)
    // Extract from: /tmp/appattest/*_signature.der
    let testSignatureDERBase64 = "PLACEHOLDER_REPLACE_WITH_REAL_SIGNATURE"
    
    // MARK: - Test
    
    func testVerificationWithRealAppleVectors() throws {
        // Skip unless explicitly enabled
        guard ProcessInfo.processInfo.environment["RUN_APPLE_VECTORS"] == "1" else {
            throw XCTSkip("Apple golden vector test skipped. Set RUN_APPLE_VECTORS=1 to enable.")
        }
        
        // Validate vectors are populated
        guard !testPublicKeyX963Base64.contains("PLACEHOLDER"),
              !testAuthenticatorDataBase64.contains("PLACEHOLDER"),
              !testClientDataHashBase64.contains("PLACEHOLDER"),
              !testSignatureDERBase64.contains("PLACEHOLDER") else {
            throw XCTSkip("Apple golden vectors not populated. Extract from /tmp/appattest/ artifacts after successful verification.")
        }
        
        // Decode vectors
        guard let publicKey = Data(base64Encoded: testPublicKeyX963Base64),
              let authenticatorData = Data(base64Encoded: testAuthenticatorDataBase64),
              let clientDataHash = Data(base64Encoded: testClientDataHashBase64),
              let signatureDER = Data(base64Encoded: testSignatureDERBase64) else {
            XCTFail("Failed to decode Base64 test vectors")
            return
        }
        
        // Validate format
        XCTAssertEqual(publicKey.count, 65, "Public key must be 65 bytes")
        XCTAssertEqual(publicKey[0], 0x04, "Public key must start with 0x04")
        XCTAssertEqual(clientDataHash.count, 32, "clientDataHash must be 32 bytes")
        XCTAssertEqual(signatureDER[0], 0x30, "Signature must be DER")
        
        // Construct payload
        let payload = authenticatorData + clientDataHash
        
        // Construct COSE Sig_structure
        let protectedA0 = Data([0xA0])
        let externalAAD = Data()
        let sigStructureBytes = constructCOSESigStructure(
            protected: protectedA0,
            externalAAD: externalAAD,
            payload: payload
        )
        
        // Verify
        let result = verifyAssertion(
            publicKeyX963: publicKey,
            signatureDER: signatureDER,
            message: sigStructureBytes
        )
        
        XCTAssertTrue(result, "Real Apple vector verification should pass")
    }
}
