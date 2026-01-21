//
//  RootExtractor.swift
//  AppAttestBackend
//
//  Dev-only helper to extract and pin the App Attestation Root CA.
//

#if DEBUG
import Foundation
import AppAttestCore

enum AppAttestRootExtractor {
    /// Extracts the root certificate PEM from a base64 attestationObject.
    /// Usage (debug-only): print(try AppAttestRootExtractor.extractRootPEM(attestationObjectBase64: "<b64>"))
    static func extractRootPEM(attestationObjectBase64: String) throws -> String {
        guard let attestationData = Data(base64Encoded: attestationObjectBase64) else {
            throw AttestationVerificationError.invalidCBOR
        }
        let decoder = AppAttestDecoder()
        let decoded = try decoder.decodeAttestation(attestationData)
        guard let rootDER = decoded.attestationStatement.x5c.last else {
            throw AttestationVerificationError.missingCertificates
        }
        return derToPEM(rootDER)
    }
}
#endif
