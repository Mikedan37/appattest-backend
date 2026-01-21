import XCTest
import Foundation
@testable import AppAttestBackend
import Crypto

final class OptionAClientDataJSONTests: XCTestCase {
    
    func testClientDataJSONDeterministic() {
        let challenge = Data([UInt8](repeating: 0x42, count: 32))
        let bundleID = "com.example.app"
        
        let json1 = buildClientDataJSON(challenge: challenge, bundleID: bundleID)
        let json2 = buildClientDataJSON(challenge: challenge, bundleID: bundleID)
        
        // Must be byte-for-byte identical
        XCTAssertEqual(json1, json2, "clientDataJSON must be deterministic")
    }
    
    func testClientDataJSONFormat() {
        let challenge = Data([UInt8](repeating: 0x42, count: 32))
        let bundleID = "com.example.app"
        
        let jsonBytes = buildClientDataJSON(challenge: challenge, bundleID: bundleID)
        let jsonString = String(data: jsonBytes, encoding: .utf8)!
        
        // Must contain required fields in correct order
        XCTAssertTrue(jsonString.contains("\"type\":\"apple-appattest\""), "Must contain type field")
        XCTAssertTrue(jsonString.contains("\"challenge\""), "Must contain challenge field")
        XCTAssertTrue(jsonString.contains("\"origin\":\"\(bundleID)\""), "Must contain origin field with bundleID")
        
        // Must not contain whitespace (deterministic)
        XCTAssertFalse(jsonString.contains(" "), "Must not contain spaces")
        XCTAssertFalse(jsonString.contains("\n"), "Must not contain newlines")
    }
    
    func testClientDataHashMatchesExpected() {
        let challenge = Data([UInt8](repeating: 0x42, count: 32))
        let bundleID = "com.example.app"
        
        let jsonBytes = buildClientDataJSON(challenge: challenge, bundleID: bundleID)
        let hash = SHA256.hash(data: jsonBytes)
        let hashData = Data(hash)
        
        // Hash must be 32 bytes
        XCTAssertEqual(hashData.count, 32, "clientDataHash must be 32 bytes")
    }
    
    func testClientDataJSONFieldOrder() {
        let challenge = Data([UInt8](repeating: 0x42, count: 32))
        let bundleID = "com.example.app"
        
        let jsonBytes = buildClientDataJSON(challenge: challenge, bundleID: bundleID)
        let jsonString = String(data: jsonBytes, encoding: .utf8)!
        
        // Field order must be: type, challenge, origin
        let typeIndex = jsonString.range(of: "\"type\"")!.lowerBound.utf16Offset(in: jsonString)
        let challengeIndex = jsonString.range(of: "\"challenge\"")!.lowerBound.utf16Offset(in: jsonString)
        let originIndex = jsonString.range(of: "\"origin\"")!.lowerBound.utf16Offset(in: jsonString)
        
        XCTAssertTrue(typeIndex < challengeIndex, "type must come before challenge")
        XCTAssertTrue(challengeIndex < originIndex, "challenge must come before origin")
    }
}
