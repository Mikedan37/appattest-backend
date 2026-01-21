//
//  main.swift
//  AppAttestBackend
//

import Foundation
import Vapor

func configure(_ app: Application) throws {
    let logger = app.logger
    KeyStore.initialize()
    
    let exePath = ProcessInfo.processInfo.arguments.first ?? "unknown"
    var binarySHA256: String? = nil
    var binaryTimestamp: String? = nil
    var binarySize: Int64? = nil
    
    let exeURL = URL(fileURLWithPath: exePath)
    if let exeData = try? Data(contentsOf: exeURL) {
        binarySHA256 = sha256Hex(exeData)
        binarySize = Int64(exeData.count)
        if let attrs = try? FileManager.default.attributesOfItem(atPath: exePath),
           let modDate = attrs[.modificationDate] as? Date {
            binaryTimestamp = ISO8601DateFormatter().string(from: modDate)
        }
    }
    
    var canaryMetadata: Logger.Metadata = [
        "version": .string("v1-matrix-2026-01-17"),
        "exe_path": .string(exePath),
        "process_start_time": .string(ISO8601DateFormatter().string(from: KeyStore.getProcessStartTime())),
        "note": .string("In-memory storage - keys lost on restart")
    ]
    if let sha256 = binarySHA256 { canaryMetadata["binary_sha256"] = .string(sha256) }
    if let timestamp = binaryTimestamp { canaryMetadata["binary_timestamp"] = .string(timestamp) }
    if let size = binarySize { canaryMetadata["binary_size_bytes"] = .string("\(size)") }
    logger.critical("CANARY routes configured", metadata: canaryMetadata)
    
    app.middleware.use(RequestTraceMiddleware())

    let buildInfo = BuildInfo(sha256: binarySHA256, timestamp: binaryTimestamp)
    registerHealthRoute(app, buildInfo: buildInfo)
    registerDebugRoute(app)
    registerChallengeRoute(app)
    registerRegisterRoute(app)
    registerVerifyRoute(app)
}

var env = try Environment.detect()
try LoggingSystem.bootstrap(from: &env)

let app = Application(env)
defer { app.shutdown() }

app.http.server.configuration.hostname = "0.0.0.0"
app.http.server.configuration.port = 8080

try configure(app)
try app.run()
