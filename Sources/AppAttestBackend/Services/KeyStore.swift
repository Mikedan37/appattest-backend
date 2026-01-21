//
//  KeyStore.swift
//  AppAttestBackend
//
//  In-memory public key store + per-key signCount.
//

import Foundation
import Crypto
import Logging

struct KeyStoreEntry {
    let publicKey: Data
    let flowID: String
    let fingerprint: PublicKeyFingerprint
    let registeredAt: Date
    let source: String
    let environment: String?
    let receipt: Data?
}

struct KeyStore {
    private static var keyStore: [String: KeyStoreEntry] = [:]
    private static var lastSignCountByKey: [String: UInt32] = [:]
    private static let keyStoreQueue = DispatchQueue(label: "appattest.keystore")
    private static let queueKey = DispatchSpecificKey<Bool>()
    private static let processStartTime = Date()
    
    static func initialize() {
        keyStoreQueue.setSpecific(key: queueKey, value: true)
    }
    
    private static func assertNotOnKeyStoreQueue(_ function: StaticString = #function) {
        #if DEBUG
        if DispatchQueue.getSpecific(key: queueKey) == true {
            print("DEADLOCK RISK: \(function) called while already on keyStoreQueue.")
        }
        #endif
    }
    
    static func storePublicKey(
        keyIDBytes: Data,
        publicKey: Data,
        flowID: String,
        source: String,
        environment: String?,
        receipt: Data?,
        logger: Logger? = nil
    ) -> Bool {
        guard keyIDBytes.count == 32 else { return false }
        guard !flowID.isEmpty else { return false }
        guard publicKey.count == 65, publicKey[0] == 0x04 else { return false }
        guard let storageKey = makeStorageKey(keyIDBytes: keyIDBytes, flowID: flowID) else { return false }
        guard let fingerprint = PublicKeyFingerprint.fromX963(publicKey) else { return false }
        
        return keyStoreQueue.sync {
            let entry = KeyStoreEntry(
                publicKey: publicKey,
                flowID: flowID,
                fingerprint: fingerprint,
                registeredAt: Date(),
                source: source,
                environment: environment,
                receipt: receipt
            )
            
            if let existing = keyStore[storageKey], existing.publicKey == publicKey {
                return true
            }
            keyStore[storageKey] = entry
            return true
        }
    }
    
    static func getPublicKey(keyIDBytes: Data, flowID: String) -> KeyStoreEntry? {
        assertNotOnKeyStoreQueue()
        guard keyIDBytes.count == 32, !flowID.isEmpty else { return nil }
        guard let storageKey = makeStorageKey(keyIDBytes: keyIDBytes, flowID: flowID) else { return nil }
        return keyStoreQueue.sync {
            guard let entry = keyStore[storageKey] else { return nil }
            guard entry.publicKey.count == 65, entry.publicKey[0] == 0x04 else { return nil }
            return entry
        }
    }
    
    static func checkSignCount(storageKey: String, signCount: UInt32) -> Bool {
        return keyStoreQueue.sync {
            guard let last = lastSignCountByKey[storageKey] else { return true }
            return signCount > last
        }
    }
    
    static func updateSignCount(storageKey: String, signCount: UInt32) {
        keyStoreQueue.sync { lastSignCountByKey[storageKey] = signCount }
    }
    
    static func getAllStorageKeys() -> [String] {
        assertNotOnKeyStoreQueue()
        return keyStoreQueue.sync { Array(keyStore.keys).sorted() }
    }
    
    static func hasKeyID(_ keyIDBytes: Data) -> Bool {
        assertNotOnKeyStoreQueue()
        let keyIDHex = keyIDBytes.map { String(format: "%02x", $0) }.joined()
        return keyStoreQueue.sync {
            keyStore.keys.contains { $0.hasPrefix("\(keyIDHex):") }
        }
    }
    
    static func getProcessStartTime() -> Date {
        processStartTime
    }
}
