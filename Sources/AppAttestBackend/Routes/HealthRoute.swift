//
//  HealthRoute.swift
//  AppAttestBackend
//

import Foundation
import Vapor

struct BuildInfo {
    let sha256: String?
    let timestamp: String?
}

func registerHealthRoute(_ app: Application, buildInfo: BuildInfo) {
    app.get("health") { _ in
        let processStart = KeyStore.getProcessStartTime()
        let uptime = Date().timeIntervalSince(processStart)
        let challengeCount = ChallengeStore.getStats()
        let keyCount = KeyStore.getAllStorageKeys().count
        return HealthResponse(
            status: "ok",
            buildSha256: buildInfo.sha256,
            buildTime: buildInfo.timestamp,
            storageBackend: "RAM",
            keyCount: keyCount,
            clientDataHashCount: challengeCount, // Using challengeCount for backward compatibility
            uptimeSeconds: uptime,
            lastVerifyRunIDSeen: nil // No longer tracking verifyRunID
        )
    }
}
