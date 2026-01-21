import XCTest
@testable import AppAttestBackend
import AppAttestCore

/// Tests for COSE key extraction and X9.63 assembly
/// Validates coordinate normalization (left-padding) and key assembly correctness
final class COSEKeyExtractionTests: XCTestCase {
    
    /// Test COSE key extraction with full 32-byte coordinates
    func testCOSEKeyExtractionFullCoordinates() throws {
        // Create a valid COSE key with full 32-byte x and y
        let x = Data([UInt8](repeating: 0xAA, count: 32))
        let y = Data([UInt8](repeating: 0xBB, count: 32))
        
        let coseKey: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),  // kty = EC2
            (.negative(-1), .unsigned(1)), // crv = P-256
            (.negative(-2), .byteString(x)), // x coordinate
            (.negative(-3), .byteString(y))  // y coordinate
        ])
        
        let extracted = extractPublicKeyFromCOSEKey(coseKey)
        
        XCTAssertNotNil(extracted, "Should extract public key from valid COSE key")
        XCTAssertEqual(extracted?.count, 65, "Public key should be 65 bytes (0x04 || X || Y)")
        XCTAssertEqual(extracted?.first, 0x04, "Public key should start with 0x04")
        
        // Verify x and y are in correct positions
        let extractedX = extracted!.subdata(in: 1..<33)
        let extractedY = extracted!.subdata(in: 33..<65)
        
        XCTAssertEqual(extractedX, x, "X coordinate should match")
        XCTAssertEqual(extractedY, y, "Y coordinate should match")
    }
    
    /// Test COSE key extraction with short coordinates (must be left-padded)
    func testCOSEKeyExtractionShortCoordinates() throws {
        // Create COSE key with 31-byte x and 30-byte y (should be left-padded to 32)
        let xShort = Data([UInt8](repeating: 0xCC, count: 31))
        let yShort = Data([UInt8](repeating: 0xDD, count: 30))
        
        let coseKey: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),  // kty = EC2
            (.negative(-1), .unsigned(1)), // crv = P-256
            (.negative(-2), .byteString(xShort)), // x coordinate (31 bytes)
            (.negative(-3), .byteString(yShort))  // y coordinate (30 bytes)
        ])
        
        let extracted = extractPublicKeyFromCOSEKey(coseKey)
        
        XCTAssertNotNil(extracted, "Should extract and pad short coordinates")
        XCTAssertEqual(extracted?.count, 65, "Public key should be 65 bytes after padding")
        XCTAssertEqual(extracted?.first, 0x04, "Public key should start with 0x04")
        
        // Verify padding: first byte should be 0x00, then original data
        let extractedX = extracted!.subdata(in: 1..<33)
        let extractedY = extracted!.subdata(in: 33..<65)
        
        XCTAssertEqual(extractedX.first, 0x00, "X should be left-padded with 0x00")
        XCTAssertEqual(extractedX.suffix(31), xShort, "X suffix should match original")
        
        XCTAssertEqual(extractedY.prefix(2), Data([0x00, 0x00]), "Y should be left-padded with 0x00")
        XCTAssertEqual(extractedY.suffix(30), yShort, "Y suffix should match original")
    }
    
    /// Test COSE key extraction rejects coordinates longer than 32 bytes
    func testCOSEKeyExtractionRejectsLongCoordinates() throws {
        // Create COSE key with 33-byte x (should be rejected)
        let xLong = Data([UInt8](repeating: 0xEE, count: 33))
        let y = Data([UInt8](repeating: 0xFF, count: 32))
        
        let coseKey: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),  // kty = EC2
            (.negative(-1), .unsigned(1)), // crv = P-256
            (.negative(-2), .byteString(xLong)), // x coordinate (33 bytes - INVALID)
            (.negative(-3), .byteString(y))  // y coordinate
        ])
        
        let extracted = extractPublicKeyFromCOSEKey(coseKey)
        
        XCTAssertNil(extracted, "Should reject coordinates longer than 32 bytes")
    }
    
    /// Test COSE key extraction validates kty and crv
    func testCOSEKeyExtractionValidatesKeyType() throws {
        let x = Data([UInt8](repeating: 0x11, count: 32))
        let y = Data([UInt8](repeating: 0x22, count: 32))
        
        // Test with wrong kty (should reject)
        let wrongKty: CBORValue = .map([
            (.unsigned(1), .unsigned(1)),  // kty = OKP (wrong)
            (.negative(-1), .unsigned(1)), // crv = P-256
            (.negative(-2), .byteString(x)),
            (.negative(-3), .byteString(y))
        ])
        
        XCTAssertNil(extractPublicKeyFromCOSEKey(wrongKty), "Should reject wrong kty")
        
        // Test with wrong crv (should reject)
        let wrongCrv: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),  // kty = EC2
            (.negative(-1), .unsigned(2)), // crv = P-384 (wrong)
            (.negative(-2), .byteString(x)),
            (.negative(-3), .byteString(y))
        ])
        
        XCTAssertNil(extractPublicKeyFromCOSEKey(wrongCrv), "Should reject wrong crv")
    }
    
    /// Test COSE key extraction handles missing coordinates
    func testCOSEKeyExtractionRejectsMissingCoordinates() throws {
        // Missing y coordinate
        let x = Data([UInt8](repeating: 0x33, count: 32))
        let incompleteKey: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),  // kty = EC2
            (.negative(-1), .unsigned(1)), // crv = P-256
            (.negative(-2), .byteString(x))
            // Missing y coordinate
        ])
        
        XCTAssertNil(extractPublicKeyFromCOSEKey(incompleteKey), "Should reject missing y coordinate")
    }
    
    /// Test X9.63 assembly: 0x04 || X || Y
    func testX963Assembly() throws {
        let x = Data([UInt8](repeating: 0x44, count: 32))
        let y = Data([UInt8](repeating: 0x55, count: 32))
        
        let coseKey: CBORValue = .map([
            (.unsigned(1), .unsigned(2)),
            (.negative(-1), .unsigned(1)),
            (.negative(-2), .byteString(x)),
            (.negative(-3), .byteString(y))
        ])
        
        let extracted = extractPublicKeyFromCOSEKey(coseKey)
        
        XCTAssertNotNil(extracted)
        
        // Verify exact X9.63 format: 0x04 || X || Y
        var expected = Data([0x04])
        expected.append(x)
        expected.append(y)
        
        XCTAssertEqual(extracted, expected, "X9.63 assembly should match expected format")
    }
}
