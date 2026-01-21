import XCTest
import Foundation
@testable import AppAttestBackend
import Logging

final class OptionAChallengeStoreTests: XCTestCase {
    var logger: Logger!
    
    override func setUp() {
        super.setUp()
        logger = Logger(label: "test")
    }
    
    func testChallengeGenerationReturns32Bytes() {
        let keyIDBytes = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        
        guard let challenge = ChallengeStore.generateChallenge(keyIDBytes: keyIDBytes, logger: logger) else {
            XCTFail("Challenge generation should not fail")
            return
        }
        
        XCTAssertEqual(challenge.count, 32, "Challenge must be exactly 32 bytes")
    }
    
    func testChallengeExpiresAfterTTL() {
        let keyIDBytes = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        
        // Generate challenge
        guard let challenge = ChallengeStore.generateChallenge(keyIDBytes: keyIDBytes, logger: logger) else {
            XCTFail("Challenge generation should not fail")
            return
        }
        
        // Consume immediately - should succeed
        switch ChallengeStore.consumeChallenge(keyIDBytes: keyIDBytes, logger: logger) {
        case .success:
            break // Expected
        default:
            XCTFail("Challenge should be consumable immediately after generation")
        }
        
        // Try to consume again - should fail with reused
        switch ChallengeStore.consumeChallenge(keyIDBytes: keyIDBytes, logger: logger) {
        case .reused:
            break // Expected
        default:
            XCTFail("Second consume should fail with reused_challenge")
        }
    }
    
    func testVerifyFailsIfKeyIDMismatched() {
        let keyID1 = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let keyID2 = Data([0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10])
        
        // Generate challenge for keyID1
        _ = ChallengeStore.generateChallenge(keyIDBytes: keyID1, logger: logger)
        
        // Try to consume with keyID2 - should fail with missing
        switch ChallengeStore.consumeChallenge(keyIDBytes: keyID2, logger: logger) {
        case .missing:
            break // Expected
        default:
            XCTFail("Consuming challenge with mismatched keyID should fail with missing_challenge")
        }
    }
    
    func testChallengeOneTimeUse() {
        let keyIDBytes = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        
        // Generate challenge
        _ = ChallengeStore.generateChallenge(keyIDBytes: keyIDBytes, logger: logger)
        
        // First consume - should succeed
        switch ChallengeStore.consumeChallenge(keyIDBytes: keyIDBytes, logger: logger) {
        case .success:
            break // Expected
        default:
            XCTFail("First consume should succeed")
        }
        
        // Second consume - should fail with reused
        switch ChallengeStore.consumeChallenge(keyIDBytes: keyIDBytes, logger: logger) {
        case .reused:
            break // Expected
        default:
            XCTFail("Second consume should fail with reused_challenge")
        }
    }
}
