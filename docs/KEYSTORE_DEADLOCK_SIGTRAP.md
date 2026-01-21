# KeyStore Concurrency Safety

## Deadlock Pattern

Nested synchronization in `KeyStore.storePublicKey()` causes deadlock:

```swift
// ❌ WRONG: Nested sync causes deadlock
func storePublicKey(...) {
    keyStoreQueue.sync {
        keyStore[storageKey] = entry
        
        // This calls getPublicKey() which also does keyStoreQueue.sync
        // → Deadlock: serial queue cannot re-enter itself
        guard let (key, flowID) = getPublicKey(...) else { ... }
    }
}

func getPublicKey(...) {
    return keyStoreQueue.sync {  // ← Tries to sync while already syncing
        keyStore[storageKey]
    }
}
```

### Why It Deadlocks

1. `storePublicKey()` acquires `keyStoreQueue.sync`
2. Inside that sync block, it calls `getPublicKey()`
3. `getPublicKey()` tries to acquire `keyStoreQueue.sync` again
4. Serial queues cannot re-enter themselves → deadlock
5. Watchdog/systemd detects hang → kills process with `SIGTRAP`
6. Service restarts → keys lost → iOS sees connection errors

## Solution: Direct Dictionary Access

```swift
// ✅ CORRECT: Access dictionary directly while already synchronized
func storePublicKey(...) {
    keyStoreQueue.sync {
        keyStore[storageKey] = entry
        
        // Read directly from dictionary - no nested sync
        guard let retrievedEntry = keyStore[storageKey] else {
            return false
        }
        
        guard retrievedEntry.publicKey == publicKey else {
            return false
        }
        
        return true
    }
}
```

### Key Principle

Inside a `keyStoreQueue.sync` block, access `keyStore[...]` directly. Never call methods that also do `keyStoreQueue.sync`.

## Regression Prevention

### DispatchSpecificKey Guardrail

A debug-only guardrail using `DispatchSpecificKey` detects re-entrancy:

```swift
private static let queueKey = DispatchSpecificKey<Bool>()

static func initialize() {
    keyStoreQueue.setSpecific(key: queueKey, value: true)
}

private static func assertNotOnKeyStoreQueue(_ function: StaticString = #function) {
    #if DEBUG
    if DispatchQueue.getSpecific(key: queueKey) == true {
        // Log error but don't crash - return error to caller
        logger?.error("DEADLOCK RISK: \(function) called while already on keyStoreQueue. This will cause a deadlock. Access keyStore[...] directly instead of calling locking methods.")
    }
    #endif
}

func getPublicKey(...) {
    assertNotOnKeyStoreQueue()  // ← Catches nested sync at development time
    return keyStoreQueue.sync { ... }
}
```

### How It Works

1. `initialize()` sets a queue-specific value when on `keyStoreQueue`
2. `assertNotOnKeyStoreQueue()` checks if we're already on the queue
3. If called from inside a sync block, it logs an error with a clear message
4. This catches the bug at development time, not in production

### Usage

All locking methods (`getPublicKey()`, `getAllStorageKeys()`) call `assertNotOnKeyStoreQueue()` before syncing.

## Related Patterns to Avoid

### ❌ Don't Do This

```swift
keyStoreQueue.sync {
    // Calling another method that syncs
    let keys = getAllStorageKeys()  // ← Deadlock!
    
    // Calling helper that syncs
    let key = getPublicKey(...)  // ← Deadlock!
}
```

### ✅ Do This Instead

```swift
keyStoreQueue.sync {
    // Direct dictionary access
    let keys = Array(keyStore.keys).sorted()
    
    // Direct dictionary access
    let entry = keyStore[storageKey]
}
```

## Testing

Concurrency safety behavior:
- Service survives repeated REGISTER calls without SIGTRAP
- Keys persist for process lifetime
- iOS does not get -1005/-1004 during stable Wi-Fi
- Debug builds catch nested sync attempts immediately

## References

- **File:** `Sources/AppAttestBackend/main.swift`
- **Functions:** `KeyStore.storePublicKey()`, `KeyStore.getPublicKey()`
- **Related:** `ClientDataHashStore` uses separate `hashQueue` (no deadlock risk)

## Lessons

1. Serial queues cannot re-enter themselves - this is fundamental to GCD
2. Helper methods hide locking - be explicit about what locks you hold
3. Network errors can mask deadlocks - always check backend logs for crashes
4. Guardrails catch bugs early - `DispatchSpecificKey` is cheap and effective
5. "Verify via helper" is a trap - verify by reading the data structure directly
