//
//  DebugRoute.swift
//  AppAttestBackend
//

import Vapor
import Crypto

private struct DebugEchoResponse: Content {
    let method: String
    let contentLength: Int?
    let contentType: String?
    let bodySize: Int
}

private struct OpenSSLVerifyRequest: Content {
    let publicKeyX963_hex: String
    let signedBytes_hex: String
    let signatureDER_hex: String
}

private struct OpenSSLVerifyResponse: Content {
    let openssl: Bool
    let stdout: String
    let stderr: String
    let exitCode: Int32
    let error: String?
}

func registerDebugRoute(_ app: Application) {
    app.post("debug", "echo") { req -> DebugEchoResponse in
        let bodySize = req.body.data?.readableBytes ?? 0
        let contentLength = req.headers.first(name: .contentLength).flatMap(Int.init)
        let contentType = req.headers.first(name: .contentType)

        return DebugEchoResponse(
            method: req.method.rawValue,
            contentLength: contentLength,
            contentType: contentType,
            bodySize: bodySize
        )
    }
    
    app.post("debug", "openssl-verify") { req -> OpenSSLVerifyResponse in
        let logger = req.logger
        let verifyReq = try req.content.decode(OpenSSLVerifyRequest.self)
        
        // Decode hex strings to bytes
        guard let publicKeyX963 = dataFromHex(verifyReq.publicKeyX963_hex),
              let signedBytes = dataFromHex(verifyReq.signedBytes_hex),
              let signatureDER = dataFromHex(verifyReq.signatureDER_hex) else {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Failed to decode hex strings",
                exitCode: -1,
                error: "Invalid hex encoding"
            )
        }
        
        // Validate public key format
        guard publicKeyX963.count == 65, publicKeyX963[0] == 0x04 else {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Invalid public key format",
                exitCode: -1,
                error: "Public key must be 65 bytes starting with 0x04"
            )
        }
        
        // Use the same OpenSSL verification logic as AssertionVerifier
        guard FileManager.default.fileExists(atPath: "/usr/bin/openssl") else {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "OpenSSL not available at /usr/bin/openssl",
                exitCode: -1,
                error: "OpenSSL not found"
            )
        }
        
        let tempDir = URL(fileURLWithPath: "/tmp/appattest-openssl-verify-debug")
        do {
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        } catch {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Failed to create temp directory: \(error.localizedDescription)",
                exitCode: -1,
                error: error.localizedDescription
            )
        }
        
        let pubkeyPEM = tempDir.appendingPathComponent("pubkey.pem")
        let signedBytesBin = tempDir.appendingPathComponent("signedBytes.bin")
        let signatureDERFile = tempDir.appendingPathComponent("signature.der")
        
        // Convert x963 to PEM SPKI
        guard let pemData = convertX963ToPEM(publicKey: publicKeyX963) else {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Failed to convert x963 to PEM",
                exitCode: -1,
                error: "PEM conversion failed"
            )
        }
        
        // Write temp files
        do {
            try pemData.write(to: pubkeyPEM)
            try signedBytes.write(to: signedBytesBin)
            try signatureDER.write(to: signatureDERFile)
        } catch {
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Failed to write temp files: \(error.localizedDescription)",
                exitCode: -1,
                error: error.localizedDescription
            )
        }
        
        // Run OpenSSL verification
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "dgst", "-sha256",
            "-verify", pubkeyPEM.path,
            "-signature", signatureDERFile.path,
            signedBytesBin.path
        ]
        
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        
        do {
            try process.run()
            process.waitUntilExit()
            
            let exitCode = process.terminationStatus
            let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
            let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
            let stderr = String(data: stderrData, encoding: .utf8) ?? ""
            
            let isValid = exitCode == 0
            
            // Cleanup temp files
            try? FileManager.default.removeItem(at: pubkeyPEM)
            try? FileManager.default.removeItem(at: signedBytesBin)
            try? FileManager.default.removeItem(at: signatureDERFile)
            try? FileManager.default.removeItem(at: tempDir)
            
            logger.info("DEBUG_OPENSSL_VERIFY [publicKey_sha256: \(sha256Hex(publicKeyX963)), signedBytes_sha256: \(sha256Hex(signedBytes)), signature_sha256: \(sha256Hex(signatureDER)), result: \(isValid), exitCode: \(exitCode)]")
            
            return OpenSSLVerifyResponse(
                openssl: isValid,
                stdout: stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                stderr: stderr.trimmingCharacters(in: .whitespacesAndNewlines),
                exitCode: exitCode,
                error: nil
            )
        } catch {
            // Cleanup on error
            try? FileManager.default.removeItem(at: pubkeyPEM)
            try? FileManager.default.removeItem(at: signedBytesBin)
            try? FileManager.default.removeItem(at: signatureDERFile)
            try? FileManager.default.removeItem(at: tempDir)
            
            return OpenSSLVerifyResponse(
                openssl: false,
                stdout: "",
                stderr: "Failed to run OpenSSL: \(error.localizedDescription)",
                exitCode: -1,
                error: error.localizedDescription
            )
        }
    }
    
    struct AssertionVerifyDebugRequest: Content {
        let publicKeyX963_hex: String
        let signedBytes_hex: String
        let nonce_hex: String
        let signatureDER_hex: String
    }
    
    struct AssertionVerifyDebugResponse: Content {
        let openssl_modeA: Bool?
        let openssl_modeB: Bool?
        let selected_mode: String?
        let modeA_stdout: String
        let modeA_stderr: String
        let modeA_exitCode: Int32
        let modeB_stdout: String
        let modeB_stderr: String
        let modeB_exitCode: Int32
        let error: String?
    }
    
    app.post("debug", "assertion-verify") { req -> AssertionVerifyDebugResponse in
        let logger = req.logger
        let verifyReq = try req.content.decode(AssertionVerifyDebugRequest.self)
        
        // Decode hex strings to bytes
        guard let publicKeyX963 = dataFromHex(verifyReq.publicKeyX963_hex),
              let signedBytes = dataFromHex(verifyReq.signedBytes_hex),
              let nonce = dataFromHex(verifyReq.nonce_hex),
              let signatureDER = dataFromHex(verifyReq.signatureDER_hex) else {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Failed to decode hex strings",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: "Invalid hex encoding"
            )
        }
        
        // Validate public key format
        guard publicKeyX963.count == 65, publicKeyX963[0] == 0x04 else {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Invalid public key format",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: "Public key must be 65 bytes starting with 0x04"
            )
        }
        
        // Validate nonce is 32 bytes
        guard nonce.count == 32 else {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Invalid nonce length",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: "Nonce must be 32 bytes"
            )
        }
        
        // Use the same OpenSSL verification logic as AssertionVerifier
        guard FileManager.default.fileExists(atPath: "/usr/bin/openssl") else {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "OpenSSL not available",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: "OpenSSL not found"
            )
        }
        
        let tempDir = URL(fileURLWithPath: "/tmp/appattest-openssl-verify-debug")
        do {
            try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        } catch {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Failed to create temp directory",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: error.localizedDescription
            )
        }
        
        let pubkeyPEM = tempDir.appendingPathComponent("pubkey.pem")
        let signedBytesBin = tempDir.appendingPathComponent("signedBytes.bin")
        let nonceBin = tempDir.appendingPathComponent("nonce.bin")
        let signatureDERFile = tempDir.appendingPathComponent("signature.der")
        
        // Convert x963 to PEM SPKI
        guard let pemData = convertX963ToPEM(publicKey: publicKeyX963) else {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Failed to convert x963 to PEM",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: "PEM conversion failed"
            )
        }
        
        // Write temp files
        do {
            try pemData.write(to: pubkeyPEM)
            try signedBytes.write(to: signedBytesBin)
            try nonce.write(to: nonceBin)
            try signatureDER.write(to: signatureDERFile)
        } catch {
            return AssertionVerifyDebugResponse(
                openssl_modeA: nil,
                openssl_modeB: nil,
                selected_mode: nil,
                modeA_stdout: "",
                modeA_stderr: "Failed to write temp files",
                modeA_exitCode: -1,
                modeB_stdout: "",
                modeB_stderr: "",
                modeB_exitCode: -1,
                error: error.localizedDescription
            )
        }
        
        // Helper function to run OpenSSL command
        func runOpenSSLCommand(_ args: [String]) -> (success: Bool, stdout: String, stderr: String, exitCode: Int32) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
            process.arguments = args
            
            let stdoutPipe = Pipe()
            let stderrPipe = Pipe()
            process.standardOutput = stdoutPipe
            process.standardError = stderrPipe
            
            do {
                try process.run()
                process.waitUntilExit()
                
                let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
                let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
                let stderr = String(data: stderrData, encoding: .utf8) ?? ""
                let exitCode = process.terminationStatus
                
                return (success: exitCode == 0, stdout: stdout.trimmingCharacters(in: .whitespacesAndNewlines), stderr: stderr.trimmingCharacters(in: .whitespacesAndNewlines), exitCode: exitCode)
            } catch {
                return (success: false, stdout: "", stderr: error.localizedDescription, exitCode: -1)
            }
        }
        
        // Mode A: verify signature over SHA256(signedBytes) by hashing inside OpenSSL
        let modeAArgs = [
            "dgst", "-sha256",
            "-verify", pubkeyPEM.path,
            "-signature", signatureDERFile.path,
            signedBytesBin.path
        ]
        let modeAResult = runOpenSSLCommand(modeAArgs)
        
        // Mode B: verify signature over RAW nonce (32 bytes) without hashing
        let modeBArgs = [
            "pkeyutl", "-verify",
            "-pubin", "-inkey", pubkeyPEM.path,
            "-sigfile", signatureDERFile.path,
            "-in", nonceBin.path
        ]
        let modeBResult = runOpenSSLCommand(modeBArgs)
        
        // Determine selected mode
        let selectedMode: String?
        if modeAResult.success && !modeBResult.success {
            selectedMode = "A"
        } else if !modeAResult.success && modeBResult.success {
            selectedMode = "B"
        } else if modeAResult.success && modeBResult.success {
            selectedMode = "A" // Prefer Mode A if both succeed
        } else {
            selectedMode = nil
        }
        
        // Cleanup temp files
        try? FileManager.default.removeItem(at: pubkeyPEM)
        try? FileManager.default.removeItem(at: signedBytesBin)
        try? FileManager.default.removeItem(at: nonceBin)
        try? FileManager.default.removeItem(at: signatureDERFile)
        try? FileManager.default.removeItem(at: tempDir)
        
        logger.info("DEBUG_ASSERTION_VERIFY [publicKey_sha256: \(sha256Hex(publicKeyX963)), signedBytes_sha256: \(sha256Hex(signedBytes)), nonce_sha256: \(sha256Hex(nonce)), signature_sha256: \(sha256Hex(signatureDER)), modeA: \(modeAResult.success), modeB: \(modeBResult.success), selected: \(selectedMode ?? "none")]")
        
        return AssertionVerifyDebugResponse(
            openssl_modeA: modeAResult.success,
            openssl_modeB: modeBResult.success,
            selected_mode: selectedMode,
            modeA_stdout: modeAResult.stdout,
            modeA_stderr: modeAResult.stderr,
            modeA_exitCode: modeAResult.exitCode,
            modeB_stdout: modeBResult.stdout,
            modeB_stderr: modeBResult.stderr,
            modeB_exitCode: modeBResult.exitCode,
            error: nil
        )
    }
}
