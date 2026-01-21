//
//  RequestTraceMiddleware.swift
//  AppAttestBackend
//

import Foundation
import Vapor

struct RequestTraceMiddleware: Middleware {
    private static let dateFormatter = ISO8601DateFormatter()

    func respond(to req: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        let startTime = DispatchTime.now()
        let startedAt = Self.dateFormatter.string(from: Date())
        let requestID = req.headers.first(name: "X-Request-Id") ?? UUID().uuidString

        let method = req.method.rawValue
        let path = req.url.path
        let remote = req.remoteAddress?.description ?? "unknown"
        let userAgent = req.headers.first(name: .userAgent) ?? "unknown"
        let contentType = req.headers.first(name: .contentType) ?? "unknown"
        let contentLength = req.headers.first(name: .contentLength) ?? "unknown"

        return next.respond(to: req).map { res in
            let elapsedNs = DispatchTime.now().uptimeNanoseconds - startTime.uptimeNanoseconds
            let durationMs = Double(elapsedNs) / 1_000_000.0

            res.headers.replaceOrAdd(name: "X-Request-Id", value: requestID)
            let durationString = String(format: "%.2f", durationMs)
            let logMessage = "REQUEST_TRACE method=\(method) path=\(path) status=\(res.status.code) duration_ms=\(durationString) remote=\(remote) content_type=\(contentType) content_length=\(contentLength) ua=\"\(userAgent)\" request_id=\(requestID) started_at=\(startedAt)"
            req.logger.info("\(logMessage)")
            return res
        }
    }
}
