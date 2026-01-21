//
//  ChallengeRoute.swift
//  AppAttestBackend
//

import Foundation
import Vapor

struct ChallengeErrorResponse: Content {
    let error: Bool
    let reason: String
    
    enum CodingKeys: String, CodingKey {
        case error
        case reason
    }
}

struct ChallengeResponse: Content {
    let challenge_b64: String
    let challenge_id: String
    let expiresAt: String
    
    // Explicit CodingKeys to guarantee JSON key names match exactly
    enum CodingKeys: String, CodingKey {
        case challenge_b64
        case challenge_id
        case expiresAt
    }
}

func registerChallengeRoute(_ app: Application) {
    app.get("app-attest", "challenge") { req -> Response in
        let logger = req.logger
        
        // Log incoming request
        let method = req.method.rawValue
        let path = req.url.path
        let query = req.url.query ?? ""
        logger.info("CHALLENGE_REQUEST [method: \(method), path: \(path), query: \(query)]")
        
        // Parse query parameters
        guard let flowID = req.query[String.self, at: "flowID"],
              let keyID = req.query[String.self, at: "keyID"] else {
            logger.error("CHALLENGE_ERROR [reason: Missing flowID or keyID query parameters]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "flowID and keyID query parameters required")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .badRequest, body: .init(data: body))
        }
        
        logger.info("CHALLENGE_REQUEST_PARAMS [flowID: \(flowID), keyID_length: \(keyID.count), keyID_prefix: \(keyID.prefix(10))]")
        
        // Validate flowID is UUID format
        guard UUID(uuidString: flowID) != nil else {
            logger.error("CHALLENGE_ERROR [reason: Invalid flowID format, flowID: \(flowID)]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "flowID must be a valid UUID")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .badRequest, body: .init(data: body))
        }
        
        // Validate keyID is not empty
        guard !keyID.isEmpty else {
            logger.error("CHALLENGE_ERROR [reason: keyID is empty]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "keyID must not be empty")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .badRequest, body: .init(data: body))
        }
        
        // Decode and validate keyID
        let keyIDBytes: Data
        do {
            keyIDBytes = try KeyID.decodeBase64(keyID)
        } catch {
            logger.error("CHALLENGE_ERROR [reason: Invalid keyID format, keyID: \(keyID)]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "Invalid keyID format")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .badRequest, body: .init(data: body))
        }
        
        // Validate keyID length (must be 32 bytes for App Attest)
        guard keyIDBytes.count == 32 else {
            logger.error("CHALLENGE_ERROR [reason: keyID length invalid, length: \(keyIDBytes.count), expected: 32]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "keyID must decode to 32 bytes")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .badRequest, body: .init(data: body))
        }
        
        logger.info("CHALLENGE_VALIDATION [flowID_valid: true, keyID_length: \(keyIDBytes.count), keyID_hex_prefix: \(keyIDBytes.prefix(8).map { String(format: "%02x", $0) }.joined())]")
        
        // Generate challenge
        guard let (challenge, challengeID, expiresAt) = ChallengeStore.generateChallenge(
            keyIDBytes: keyIDBytes,
            flowID: flowID,
            logger: logger
        ) else {
            logger.error("CHALLENGE_ERROR [reason: Failed to generate challenge]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "Failed to generate challenge")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .internalServerError, body: .init(data: body))
        }
        
        // Validate challenge length (must be 32 bytes)
        guard challenge.count == 32 else {
            logger.error("CHALLENGE_ERROR [reason: Generated challenge has invalid length, length: \(challenge.count), expected: 32]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "Challenge generation failed")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .internalServerError, body: .init(data: body))
        }
        
        let challengeBase64 = challenge.base64EncodedString()
        let expiresAtString = ISO8601DateFormatter().string(from: expiresAt)
        
        // Validate challengeID is UUID format
        guard UUID(uuidString: challengeID) != nil else {
            logger.error("CHALLENGE_ERROR [reason: Generated challengeID is not UUID, challengeID: \(challengeID)]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "Challenge generation failed")
            let body = try JSONEncoder().encode(errorResp)
            return Response(status: .internalServerError, body: .init(data: body))
        }
        
        // Create response
        let response = ChallengeResponse(
            challenge_b64: challengeBase64,
            challenge_id: challengeID,
            expiresAt: expiresAtString
        )
        
        // Encode to JSON and log the exact bytes that will be sent
        let jsonData = try JSONEncoder().encode(response)
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            logger.error("CHALLENGE_ERROR [reason: Failed to encode response to UTF-8]")
            let errorResp = ChallengeErrorResponse(error: true, reason: "Response encoding failed")
            let errorBody = try JSONEncoder().encode(errorResp)
            return Response(status: .internalServerError, body: .init(data: errorBody))
        }
        
        // Log canonical response before sending
        logger.info("CHALLENGE_RESPONSE [status: 200, challenge_length: \(challenge.count), challenge_b64_length: \(challengeBase64.count), challenge_id: \(challengeID), expiresAt: \(expiresAtString), json_body: \(jsonString)]")
        
        // Verify JSON keys match expected format
        if let jsonDict = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any] {
            let keys = Set(jsonDict.keys)
            let expectedKeys = Set(["challenge_b64", "challenge_id", "expiresAt"])
            if keys != expectedKeys {
                logger.error("CHALLENGE_JSON_KEY_MISMATCH [actual_keys: \(keys), expected_keys: \(expectedKeys)]")
            } else {
                logger.info("CHALLENGE_JSON_KEYS_VALID [keys: \(keys)]")
            }
        }
        
        // Return response with explicit Content-Type
        var responseHeaders = HTTPHeaders()
        responseHeaders.add(name: .contentType, value: "application/json; charset=utf-8")
        
        return Response(status: .ok, headers: responseHeaders, body: .init(data: jsonData))
    }
}

/*
 CURL TEST COMMAND:
 
 curl -i "http://10.0.0.108:8080/app-attest/challenge?flowID=37E22BB6-EA70-47C9-B7A8-D8CA2655D50A&keyID=vpWD8c%2BBNjzcZqRPB7Ehg1GMJGpmwzyz3y2QW079LWs%3D"
 
 EXPECTED RESPONSE:
 HTTP/1.1 200 OK
 Content-Type: application/json; charset=utf-8
 Content-Length: <length>
 
 {
   "challenge_b64": "<base64-string>",
   "challenge_id": "<uuid>",
   "expiresAt": "<iso8601-timestamp>"
 }
 
 ERROR RESPONSE (400):
 HTTP/1.1 400 Bad Request
 Content-Type: application/json; charset=utf-8
 
 {
   "error": true,
   "reason": "<error-message>"
 }
 */
