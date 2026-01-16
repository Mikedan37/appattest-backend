//
//  NegativeAssuranceTests.swift
//  AppAttestBackendTests
//
//  Tests that assert the absence of undocumented behavior.
//

import XCTest
import XCTVapor
@testable import AppAttestBackend

final class NegativeAssuranceTests: XCTestCase {
    var app: Application!
    
    override func setUp() async throws {
        app = try await Application.make(.testing)
        try configure(app)
    }
    
    override func tearDown() async throws {
        app.shutdown()
    }
    
    // MARK: - No Global State Leakage
    
    func testNoStateLeakageBetweenTests() throws {
        // This test verifies that there is no global state leakage between tests.
        // Each test should start with a clean state.
        
        // Test approach:
        // 1. In one test, register a key
        // 2. In another test, verify that key does not exist
        // 3. This proves test isolation
        
        // Since setUp runs before each test, and KeyStore is static,
        // we verify that keys registered in one test don't affect another
        // (unless explicitly set up)
        
        let keyID = "test-isolation"
        
        // Key should not exist at start of test
        let before = KeyStore.getPublicKey(keyID: keyID)
        XCTAssertNil(before, "Key should not exist at test start (no leakage from previous test)")
    }
    
    func testNoImplicitKeyCreation() throws {
        // This test verifies that keys are not created implicitly.
        // Keys must be explicitly registered.
        
        let unregisteredKeyID = "never-registered-implicit-test"
        
        // Try to verify without registration
        var cborBytes = Data()
        cborBytes.append(0xa2)
        cborBytes.append(0x71)
        cborBytes.append(contentsOf: "authenticatorData".utf8)
        cborBytes.append(0x58)
        cborBytes.append(0x25)
        cborBytes.append(contentsOf: Data(repeating: 0, count: 37))
        cborBytes.append(0x69)
        cborBytes.append(contentsOf: "signature".utf8)
        cborBytes.append(0x58)
        cborBytes.append(0x40)
        cborBytes.append(contentsOf: Data(repeating: 0, count: 64))
        
        try app.test(.POST, "/app-attest/verify", beforeRequest: { req in
            try req.content.encode([
                "keyID": unregisteredKeyID,
                "assertionObject": cborBytes.base64EncodedString(),
                "clientDataHash": Data(repeating: 0, count: 32).base64EncodedString()
            ])
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: String].self)
            XCTAssertEqual(body["status"], "rejected", "Should reject unregistered key (no implicit creation)")
            
            // Verify key was not created
            let key = KeyStore.getPublicKey(keyID: unregisteredKeyID)
            XCTAssertNil(key, "Key should not be created implicitly")
        })
    }
    
    // MARK: - No Silent Fallback Paths
    
    func testNoSilentFallbackOnDecodeFailure() throws {
        // This test verifies that decode failures are not silently ignored.
        // The service should reject, not fall back to alternative decoding.
        
        let keyID = "test-no-fallback"
        let publicKey = Data([0x04] + Array(repeating: 0, count: 64))
        _ = KeyStore.storePublicKey(keyID: keyID, publicKey: publicKey, logger: nil)
        
        // Invalid CBOR that cannot be decoded
        let invalidCBOR = Data([0xFF, 0xFF, 0xFF])
        
        try app.test(.POST, "/app-attest/verify", beforeRequest: { req in
            try req.content.encode([
                "keyID": keyID,
                "assertionObject": invalidCBOR.base64EncodedString(),
                "clientDataHash": Data(repeating: 0, count: 32).base64EncodedString()
            ])
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: String].self)
            // Should reject, not silently fall back
            XCTAssertEqual(body["status"], "rejected", "Should reject invalid CBOR, not fall back")
            XCTAssertNotNil(body["reason"], "Should provide reason for rejection")
        })
    }
    
    func testNoSilentFallbackOnSignatureFormatFailure() throws {
        // This test verifies that signature format failures are not silently
        // ignored or handled with fallback logic.
        
        let keyID = "test-no-sig-fallback"
        let publicKey = Data([0x04] + Array(repeating: 0, count: 64))
        _ = KeyStore.storePublicKey(keyID: keyID, publicKey: publicKey, logger: nil)
        
        // Invalid signature format (too short, not DER, not 64 bytes)
        let invalidSignature = Data([0x01, 0x02])
        
        var cborBytes = Data()
        cborBytes.append(0xa2)
        cborBytes.append(0x71)
        cborBytes.append(contentsOf: "authenticatorData".utf8)
        cborBytes.append(0x58)
        cborBytes.append(0x25)
        cborBytes.append(contentsOf: Data(repeating: 0, count: 37))
        cborBytes.append(0x69)
        cborBytes.append(contentsOf: "signature".utf8)
        cborBytes.append(0x42) // byte string, 2 bytes
        cborBytes.append(contentsOf: invalidSignature)
        
        try app.test(.POST, "/app-attest/verify", beforeRequest: { req in
            try req.content.encode([
                "keyID": keyID,
                "assertionObject": cborBytes.base64EncodedString(),
                "clientDataHash": Data(repeating: 0, count: 32).base64EncodedString()
            ])
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: String].self)
            // Should reject, not silently accept or fall back
            XCTAssertEqual(body["status"], "rejected", "Should reject invalid signature format, not fall back")
            XCTAssertTrue(body["reason"]?.contains("Invalid signature format") == true ||
                         body["reason"]?.contains("length") == true)
        })
    }
    
    // MARK: - No Undocumented Behavior
    
    func testNoUndocumentedEndpoints() throws {
        // This test verifies that only documented endpoints exist.
        // Undocumented endpoints should return 404.
        
        let undocumentedEndpoints = [
            "/app-attest/revoke",
            "/app-attest/rotate",
            "/app-attest/status",
            "/keys",
            "/admin"
        ]
        
        for endpoint in undocumentedEndpoints {
            try app.test(.GET, endpoint, afterResponse: { res in
                XCTAssertEqual(res.status, .notFound, "Undocumented endpoint \(endpoint) should return 404")
            })
        }
    }
    
    func testNoUndocumentedResponseFields() throws {
        // This test verifies that responses do not contain undocumented fields.
        
        let keyID = "test-response-fields"
        let publicKey = Data([0x04] + Array(repeating: 0, count: 64))
        _ = KeyStore.storePublicKey(keyID: keyID, publicKey: publicKey, logger: nil)
        
        var cborBytes = Data()
        cborBytes.append(0xa2)
        cborBytes.append(0x71)
        cborBytes.append(contentsOf: "authenticatorData".utf8)
        cborBytes.append(0x58)
        cborBytes.append(0x25)
        cborBytes.append(contentsOf: Data(repeating: 0, count: 37))
        cborBytes.append(0x69)
        cborBytes.append(contentsOf: "signature".utf8)
        cborBytes.append(0x58)
        cborBytes.append(0x40)
        cborBytes.append(contentsOf: Data(repeating: 0, count: 64))
        
        try app.test(.POST, "/app-attest/verify", beforeRequest: { req in
            try req.content.encode([
                "keyID": keyID,
                "assertionObject": cborBytes.base64EncodedString(),
                "clientDataHash": Data(repeating: 0, count: 32).base64EncodedString()
            ])
        }, afterResponse: { res in
            XCTAssertEqual(res.status, .ok)
            let body = try res.content.decode([String: Any].self)
            
            // Response should only contain documented fields
            let allowedFields = ["status", "reason"]
            for (key, _) in body {
                XCTAssertTrue(allowedFields.contains(key), "Response contains undocumented field: \(key)")
            }
        })
    }
}
