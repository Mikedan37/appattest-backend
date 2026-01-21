//
//  ChallengeStore.swift
//  AppAttestBackend
//
//  Challenge issuance, TTL, and one-time consumption.
//

import Foundation
import Crypto
import Logging

struct ChallengeEntry {
    let challenge: Data
    let challengeID: String
    let keyID: Data
    let flowID: String
    let generatedAt: Date
    var consumedAt: Date?
    var used: Bool
    let expiresAt: Date
}

struct ChallengeStore {
    private static var challenges: [String: ChallengeEntry] = [:] // keyed by challenge_id
    private static var challengesByFlowKey: [String: String] = [:] // flowKey -> challenge_id
    private static let challengeQueue = DispatchQueue(label: "appattest.challenge.store")
    private static let challengeExpiry: TimeInterval = 300 // 5 minutes
    
    static func generateChallenge(keyIDBytes: Data, flowID: String, logger: Logger? = nil) -> (challenge: Data, challengeID: String, expiresAt: Date)? {
        // Generate random 32-byte challenge
        var challengeBytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { challengeBytes[i] = UInt8.random(in: 0...255) }
        let challenge = Data(challengeBytes)
        
        let challengeID = UUID().uuidString
        let expiresAt = Date().addingTimeInterval(challengeExpiry)
        let generatedAt = Date()
        
        guard let flowKey = makeStorageKey(keyIDBytes: keyIDBytes, flowID: flowID) else { return nil }
        let keyIDHex = keyIDBytes.map { String(format: "%02x", $0) }.joined()
        
        return challengeQueue.sync {
            // Check if challenge already exists for this flowKey
            if let existingChallengeID = challengesByFlowKey[flowKey],
               let existing = challenges[existingChallengeID],
               Date().timeIntervalSince(existing.generatedAt) < challengeExpiry {
                logger?.warning("Challenge already exists for (keyID, flowID) - returning existing", metadata: [
                    "flowKey": .string(flowKey),
                    "keyIDHex": .string(keyIDHex),
                    "flowID": .string(flowID),
                    "existing_challengeID": .string(existingChallengeID),
                    "existing_generatedAt": .string(ISO8601DateFormatter().string(from: existing.generatedAt))
                ])
                return (challenge: existing.challenge, challengeID: existingChallengeID, expiresAt: existing.expiresAt)
            }
            
            let entry = ChallengeEntry(
                challenge: challenge,
                challengeID: challengeID,
                keyID: keyIDBytes,
                flowID: flowID,
                generatedAt: generatedAt,
                consumedAt: nil,
                used: false,
                expiresAt: expiresAt
            )
            
            challenges[challengeID] = entry
            challengesByFlowKey[flowKey] = challengeID
            
            // Cleanup expired entries
            cleanupExpired()
            
            let challengeHex = challenge.map { String(format: "%02x", $0) }.joined()
            logger?.info("Challenge generated and stored", metadata: [
                "challengeID": .string(challengeID),
                "flowKey": .string(flowKey),
                "keyIDHex": .string(keyIDHex),
                "flowID": .string(flowID),
                "challenge_hex": .string(challengeHex),
                "challenge_sha256": .string(sha256Hex(challenge)),
                "generatedAt": .string(ISO8601DateFormatter().string(from: generatedAt)),
                "expiresAt": .string(ISO8601DateFormatter().string(from: expiresAt))
            ])
            
            return (challenge: challenge, challengeID: challengeID, expiresAt: expiresAt)
        }
    }
    
    enum ChallengeConsumeResult {
        case success(challenge: Data)
        case missing
        case expired
        case reused
        case keyIDMismatch
        case flowIDMismatch
    }
    
    static func consumeChallenge(challengeID: String, keyIDBytes: Data, flowID: String, logger: Logger? = nil) -> ChallengeConsumeResult {
        let consumedAt = Date()
        let keyIDHex = keyIDBytes.map { String(format: "%02x", $0) }.joined()
        
        return challengeQueue.sync {
            guard var entry = challenges[challengeID] else {
                logger?.warning("Challenge not found", metadata: [
                    "challengeID": .string(challengeID),
                    "keyIDHex": .string(keyIDHex),
                    "flowID": .string(flowID)
                ])
                return .missing
            }
            
            // Check expiry
            if Date().timeIntervalSince(entry.generatedAt) > challengeExpiry {
                challenges.removeValue(forKey: challengeID)
                if let flowKey = makeStorageKey(keyIDBytes: entry.keyID, flowID: entry.flowID),
                   challengesByFlowKey[flowKey] == challengeID {
                    challengesByFlowKey.removeValue(forKey: flowKey)
                }
                return .expired
            }
            
            // Check if already used
            if entry.used {
                return .reused
            }
            
            // Verify keyID matches
            if entry.keyID != keyIDBytes {
                logger?.error("Challenge keyID mismatch", metadata: [
                    "challengeID": .string(challengeID),
                    "request_keyIDHex": .string(keyIDHex),
                    "stored_keyIDHex": .string(entry.keyID.map { String(format: "%02x", $0) }.joined())
                ])
                return .keyIDMismatch
            }
            
            // Verify flowID matches
            if entry.flowID != flowID {
                logger?.error("Challenge flowID mismatch", metadata: [
                    "challengeID": .string(challengeID),
                    "request_flowID": .string(flowID),
                    "stored_flowID": .string(entry.flowID)
                ])
                return .flowIDMismatch
            }
            
            // Mark as used
            entry.used = true
            entry.consumedAt = consumedAt
            challenges[challengeID] = entry
            
            logger?.info("Challenge consumed (one-time use enforced)", metadata: [
                "challengeID": .string(challengeID),
                "keyIDHex": .string(keyIDHex),
                "flowID": .string(flowID),
                "consumedAt": .string(ISO8601DateFormatter().string(from: consumedAt))
            ])
            
            return .success(challenge: entry.challenge)
        }
    }
    
    static func getChallenge(challengeID: String) -> ChallengeEntry? {
        return challengeQueue.sync {
            guard let entry = challenges[challengeID] else { return nil }
            if Date().timeIntervalSince(entry.generatedAt) > challengeExpiry {
                challenges.removeValue(forKey: challengeID)
                return nil
            }
            return entry
        }
    }
    
    private static func cleanupExpired() {
        let now = Date()
        let expiredIDs = challenges.compactMap { (id, entry) -> String? in
            now.timeIntervalSince(entry.generatedAt) > challengeExpiry ? id : nil
        }
        for id in expiredIDs {
            if let entry = challenges[id],
               let flowKey = makeStorageKey(keyIDBytes: entry.keyID, flowID: entry.flowID) {
                challengesByFlowKey.removeValue(forKey: flowKey)
            }
            challenges.removeValue(forKey: id)
        }
    }
    
    static func getStats() -> Int {
        challengeQueue.sync {
            cleanupExpired()
            return challenges.count
        }
    }
}
