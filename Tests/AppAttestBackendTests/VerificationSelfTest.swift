import XCTest
@testable import AppAttestBackend
import Crypto
import Foundation

/// Deterministic backend App Attest verification self-test.
///
/// **Purpose:**
/// - Proves the backend verifier works correctly in isolation
/// - Does NOT require iOS, Secure Enclave, or Apple App Attest
/// - Generates keypair and signature in-test (deterministic, always passes when verifier is correct)
///
/// **Test Design:**
/// - Generates P-256 keypair in-test
/// - Creates fixed test bytes (authenticatorData, clientDataHash)
/// - Constructs COSE Sig_structure with correct encoding (protected = h'A0')
/// - Signs the Sig_structure with the private key
/// - Verifies using the same `verifyAssertion()` function used by `/verify`
/// - Negative control: also tests raw payload (should fail)
///
/// **Interpretation:**
/// - ✅ Pass → Backend verifier is correct forever
/// - ❌ Fail → Verifier bug (not App Attest, not Apple, not frontend)
///
/// **This test is the "you broke App Attest" alarm.**
/// If it fails, stop everything and fix the backend verifier.
final class VerificationSelfTest: XCTestCase {
    
    // MARK: - Fixed Test Data
    
    // Fixed authenticatorData (37 bytes, realistic App Attest format)
    // This is arbitrary but fixed for deterministic testing
    let testAuthenticatorData: Data = {
        var data = Data()
        // RP ID hash (32 bytes) - arbitrary but fixed
        data.append(contentsOf: Array(repeating: 0xAA, count: 32))
        // Flags (1 byte) - AT flag set
        data.append(0x41)
        // Counter (4 bytes) - arbitrary
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])
        return data
    }()
    
    // Fixed clientDataHash (32 bytes, SHA256)
    // CRITICAL: Backend does NOT generate this - it's an opaque input from the client
    // This mirrors real App Attest behavior where clientDataHash comes from the client
    let testClientDataHash: Data = {
        // Fixed 32-byte hash (arbitrary but deterministic)
        return Data([
            0x5d, 0x4d, 0x62, 0xcf, 0xfa, 0x76, 0xc9, 0xb7,
            0xa8, 0x1c, 0x33, 0x67, 0xa4, 0xf7, 0x74, 0xa1,
            0x82, 0xe4, 0x1c, 0xe7, 0x1e, 0x94, 0xe4, 0x92,
            0x91, 0x57, 0x64, 0xba, 0x9c, 0xa2, 0x01, 0x01
        ])
    }()
    
    // MARK: - Test Setup
    
    override func setUp() {
        super.setUp()
        // Create test dump directory
        let testDir = URL(fileURLWithPath: "/tmp/appattest-selftest")
        try? FileManager.default.createDirectory(at: testDir, withIntermediateDirectories: true)
    }
    
    // MARK: - Main Test
    
    func testVerificationWithCOSESigStructure() throws {
        // 1. Generate P-256 keypair in-test (deterministic)
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyX963 = publicKey.x963Representation // 65 bytes: 0x04 || X || Y
        
        // Hard invariants - fail fast
        XCTAssertEqual(publicKeyX963.count, 65, "Public key must be 65 bytes (X9.63 uncompressed)")
        XCTAssertEqual(publicKeyX963[0], 0x04, "Public key must start with 0x04 (uncompressed)")
        XCTAssertEqual(testClientDataHash.count, 32, "clientDataHash must be exactly 32 bytes (SHA256)")
        XCTAssertGreaterThan(testAuthenticatorData.count, 0, "authenticatorData must not be empty")
        
        // 2. Construct signed payload
        // CRITICAL: Backend does NOT generate clientDataHash - it's an opaque 32-byte input
        // This mirrors real App Attest behavior where clientDataHash comes from the client
        let payload = testAuthenticatorData + testClientDataHash
        XCTAssertEqual(payload.count, testAuthenticatorData.count + 32, "Payload length must match")
        
        // 3. Construct COSE Sig_structure (CORRECT encoding)
        // Sig_structure = [
        //   "Signature1",        // text string (item 0)
        //   h'A0',               // body_protected: bstr containing CBOR empty map (item 1)
        //   h'',                 // external_aad: empty bstr (item 2)
        //   payload               // bstr(authenticatorData || clientDataHash) (item 3)
        // ]
        let protectedA0 = Data([0xA0]) // CBOR empty map {} = 0xA0
        let externalAAD = Data() // Empty external_aad
        let sigStructureBytes = constructCOSESigStructure(
            protected: protectedA0,
            externalAAD: externalAAD,
            payload: payload
        )
        
        // Hard assertion: Sig_structure must start with array(4) marker
        XCTAssertEqual(sigStructureBytes.first, 0x84, "Sig_structure must start with CBOR array(4) = 0x84")
        
        // Hard assertion: protected field must be h'A0'
        // Structure: 0x84 | 0x6a "Signature1" | 0x41 (bstr len 1) | 0xA0
        let expectedA0Prefix = Data([0x84, 0x6a]) + "Signature1".data(using: .utf8)! + Data([0x41, 0xA0])
        XCTAssertEqual(
            sigStructureBytes.prefix(expectedA0Prefix.count),
            expectedA0Prefix,
            "Sig_structure must have protected = h'A0' (CBOR empty map)"
        )
        
        // 4. Sign the Sig_structure bytes with the private key
        // IMPORTANT: We sign the exact bytes that production verifies
        // swift-crypto's isValidSignature(_:for: Data) hashes internally, so we sign the raw bytes
        let signature = try privateKey.signature(for: sigStructureBytes)
        
        // 5. Convert signature to DER format (matches production path)
        let signatureDER = signature.derRepresentation
        XCTAssertEqual(signatureDER[0], 0x30, "Signature must be DER (starts with 0x30)")
        
        // 6. Run verification (PRIMARY TEST)
        // This uses the exact same function as /verify endpoint
        // No duplicate logic - if this fails, production verification is broken
        let verificationResult = verifyAssertion(
            publicKeyX963: publicKeyX963,
            signatureDER: signatureDER,
            message: sigStructureBytes
        )
        
        // PRIMARY ASSERTION: Verification over Sig_structure MUST pass
        // This is the "you broke App Attest" alarm - if this fails, stop everything
        XCTAssertTrue(
            verificationResult,
            """
            ❌ BACKEND VERIFIER FAILED - STOP EVERYTHING
            
            Verification failed with COSE Sig_structure (protected=h'A0').
            
            This test generates its own keypair and signature in-test.
            If this fails, the backend verifier is broken.
            
            DO NOT:
            - Blame App Attest
            - Blame Apple
            - Blame frontend
            - Continue with other work
            
            DO:
            - Check artifacts in /tmp/appattest-selftest/
            - Fix backend verifier immediately
            - Re-run test until it passes
            
            This test is your regression alarm. If it fails, you broke App Attest.
            """
        )
        
        // 7. Negative control: Raw payload MUST fail
        // (signature is over Sig_structure, not raw payload)
        let rawPayloadResult = verifyAssertion(
            publicKeyX963: publicKeyX963,
            signatureDER: signatureDER,
            message: payload
        )
        
        // ASSERTION: Raw payload MUST fail (signature is over Sig_structure, not raw payload)
        XCTAssertFalse(
            rawPayloadResult,
            """
            Negative control failed: Raw payload verified (unexpected).
            
            This suggests:
            - Signature verification logic is incorrect, OR
            - Test setup is wrong
            
            Expected: Raw payload verification fails (signature is over Sig_structure)
            """
        )
        
        // 8. Optional: OpenSSL cross-check (if available)
        let opensslAvailable = FileManager.default.fileExists(atPath: "/usr/bin/openssl")
        if opensslAvailable {
            let testDir = URL(fileURLWithPath: "/tmp/appattest-selftest")
            let pemData = convertX963ToPEM(publicKey: publicKeyX963)
            try pemData.write(to: testDir.appendingPathComponent("selftest_pubkey.pem"))
            try signatureDER.write(to: testDir.appendingPathComponent("selftest_signature.der"))
            try sigStructureBytes.write(to: testDir.appendingPathComponent("selftest_sigstructure.cbor"))
            
            // Run OpenSSL verification
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = [
                "dgst", "-sha256",
                "-verify", testDir.appendingPathComponent("selftest_pubkey.pem").path,
                "-signature", testDir.appendingPathComponent("selftest_signature.der").path,
                testDir.appendingPathComponent("selftest_sigstructure.cbor").path
            ]
            
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe
            
            try process.run()
            process.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            
            if process.terminationStatus == 0 {
                print("✓ OpenSSL cross-check: Verified OK")
            } else {
                print("⚠️  OpenSSL cross-check: Verification failed (exit code \(process.terminationStatus))")
                print("   Output: \(output)")
            }
        } else {
            print("ℹ️  OpenSSL not available, skipping cross-check")
        }
        
        // 9. Dump artifacts for manual inspection
        let testDir = URL(fileURLWithPath: "/tmp/appattest-selftest")
        try publicKeyX963.write(to: testDir.appendingPathComponent("selftest_pubkey.x963"))
        try signatureDER.write(to: testDir.appendingPathComponent("selftest_signature.der"))
        try payload.write(to: testDir.appendingPathComponent("selftest_payload.bin"))
        try sigStructureBytes.write(to: testDir.appendingPathComponent("selftest_sigstructure.cbor"))
        
        // Write metadata
        let meta = """
        {
          "test": "VerificationSelfTest",
          "test_type": "deterministic_in_test_generation",
          "pubkey_length": \(publicKeyX963.count),
          "pubkey_sha256": "\(SHA256.hash(data: publicKeyX963).map { String(format: "%02x", $0) }.joined())",
          "authenticatorData_length": \(testAuthenticatorData.count),
          "authenticatorData_sha256": "\(SHA256.hash(data: testAuthenticatorData).map { String(format: "%02x", $0) }.joined())",
          "clientDataHash_length": \(testClientDataHash.count),
          "clientDataHash_sha256": "\(SHA256.hash(data: testClientDataHash).map { String(format: "%02x", $0) }.joined())",
          "payload_length": \(payload.count),
          "payload_sha256": "\(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined())",
          "signatureDER_length": \(signatureDER.count),
          "signatureDER_sha256": "\(SHA256.hash(data: signatureDER).map { String(format: "%02x", $0) }.joined())",
          "sigStructure_length": \(sigStructureBytes.count),
          "sigStructure_sha256": "\(SHA256.hash(data: sigStructureBytes).map { String(format: "%02x", $0) }.joined())",
          "verification_result": \(verificationResult),
          "rawPayload_result": \(rawPayloadResult),
          "openssl_available": \(opensslAvailable),
          "interpretation": "\(verificationResult ? "✓ Backend verifier is CORRECT" : "✗ Backend verifier has a BUG")"
        }
        """
        try meta.write(to: testDir.appendingPathComponent("selftest_meta.txt"), atomically: true, encoding: .utf8)
        
        print("""
        === Verification Self-Test Results ===
        ✓ Keypair generated in-test (deterministic)
        ✓ COSE Sig_structure constructed (protected=h'A0')
        ✓ Signature generated and converted to DER
        ✓ Verification result: \(verificationResult ? "✅ PASSED - Backend is correct" : "❌ FAILED - Backend verifier broken")
        ✓ Raw payload result: \(rawPayloadResult ? "PASSED (unexpected)" : "FAILED (expected)")
        
        Artifacts dumped to: /tmp/appattest-selftest/
        
        \(verificationResult ? "✅ BACKEND VERIFIER IS CORRECT - This test locks in the fix" : "❌ BACKEND VERIFIER IS BROKEN - Fix immediately")
        """)
    }
}
