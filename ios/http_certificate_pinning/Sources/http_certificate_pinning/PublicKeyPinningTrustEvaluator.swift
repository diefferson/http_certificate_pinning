//
//  PublicKeyPinningTrustEvaluator.swift
//
//  Created by Kevin ASSI on 29/07/2026.
//

import Foundation
import Alamofire

/// The position of a certificate in the server's trust chain.
enum CertificatePosition {
    /// The end-entity certificate presented by the server (index 0 in the chain).
    case leaf
    /// A CA certificate between the leaf and the root.
    case intermediate
    /// The self-signed trust anchor at the end of the chain.
    case root

    /// The certificate at this position in an evaluated trust chain, if present.
    /// The chain is expected to be ordered leaf first, root last.
    func certificate(in chain: [SecCertificate]) -> SecCertificate? {
        switch self {
        case .leaf:
            return chain.first
        case .intermediate:
            return chain.count > 2 ? chain[1] : nil
        case .root:
            return chain.count > 1 ? chain.last : nil
        }
    }
}

/// The outcome of comparing a pinned public key against the one presented by the server.
enum PublicKeyComparisonResult {
    /// The server's key matches the pinned key.
    case match
    /// A key was found at the requested chain position but does not match.
    case mismatch
    /// The chain has no certificate at the requested position.
    case certificateNotFound
    /// The certificate's public key could not be extracted.
    case keyExtractionFailed
    /// The certificate uses a key algorithm this evaluator cannot hash.
    case unsupportedKeyAlgorithm
}

/// The key algorithms supported for pinning. `SecKeyCopyExternalRepresentation` returns
/// raw key bytes without the SubjectPublicKeyInfo wrapper, so each algorithm carries the
/// ASN.1 header to prepend before hashing — making the hash match standard SPKI pins
/// (e.g. `openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`).
enum PublicKeyAlgorithm {
    case rsa2048
    case rsa4096
    case ecdsaSecp256r1
    case ecdsaSecp384r1

    /// DER header for the SubjectPublicKeyInfo structure of this key type:
    /// SEQUENCE, AlgorithmIdentifier (OID + parameters), and BIT STRING length prefix.
    var asn1Header: [UInt8] {
        switch self {
        case .rsa2048:
            return [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
                    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00]
        case .rsa4096:
            return [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09,
                    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00]
        case .ecdsaSecp256r1:
            return [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                    0x42, 0x00]
        case .ecdsaSecp384r1:
            return [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
                    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
                    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
        }
    }

    /// Identifies the algorithm of a key from its Security framework attributes.
    init?(key: SecKey) {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              let keySize = attributes[kSecAttrKeySizeInBits] as? Int else {
            return nil
        }

        let rsa = kSecAttrKeyTypeRSA as String
        let ec = kSecAttrKeyTypeECSECPrimeRandom as String

        switch (keyType, keySize) {
        case (rsa, 2048):
            self = .rsa2048
        case (rsa, 4096):
            self = .rsa4096
        case (ec, 256):
            self = .ecdsaSecp256r1
        case (ec, 384):
            self = .ecdsaSecp384r1
        default:
            return nil
        }
    }
}

final class PublicKeyPinningTrustEvaluator: ServerTrustEvaluating {
    /// Base64-encoded SHA-256 hashes of allowed SubjectPublicKeyInfo structures, keyed
    /// by the chain position they apply to (standard SPKI pins, as produced by
    /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`).
    /// The evaluation passes when the key at any pinned position matches one of its pins.
    let allowedPublicKeyHashes: [CertificatePosition: Set<String>]

    init(allowedPublicKeyHashes: [CertificatePosition: Set<String>]) {
        self.allowedPublicKeyHashes = allowedPublicKeyHashes
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        let policies: [SecPolicy] = [SecPolicyCreateSSL(true, host as CFString)]
        SecTrustSetPolicies(trust, policies as CFTypeRef)

        // The chain must pass standard X.509 evaluation before any pin is considered.
        guard SecTrustEvaluateWithError(trust, nil) else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .trustEvaluationFailed(error: nil)
            )
        }

        let chain = certificateChain(of: trust)

        let pinMatches = allowedPublicKeyHashes.contains { position, hashes in
            compare(allowedPublicKeyHashes: hashes, position: position, in: chain) == .match
        }

        if !pinMatches {
            throw AFError.serverTrustEvaluationFailed(
                reason: .noCertificatesFound
            )
        }
    }

    /// The evaluated trust chain, ordered leaf first, root last.
    private func certificateChain(of trust: SecTrust) -> [SecCertificate] {
        if #available(iOS 15.0, *) {
            return SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        }
        return (0..<SecTrustGetCertificateCount(trust)).compactMap { index in
            SecTrustGetCertificateAtIndex(trust, index)
        }
    }

    /// Hashes the public key presented by the server at the given position in the trust
    /// chain (SHA-256 of the SubjectPublicKeyInfo, base64-encoded) once, then checks it
    /// against the allowed hashes.
    private func compare(allowedPublicKeyHashes: Set<String>, position: CertificatePosition, in chain: [SecCertificate]) -> PublicKeyComparisonResult {
        guard let certificate = position.certificate(in: chain) else {
            return .certificateNotFound
        }

        guard let serverPublicKey = SecCertificateCopyKey(certificate),
              let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) as Data? else {
            return .keyExtractionFailed
        }

        guard let algorithm = PublicKeyAlgorithm(key: serverPublicKey) else {
            return .unsupportedKeyAlgorithm
        }

        var subjectPublicKeyInfo = Data(algorithm.asn1Header)
        subjectPublicKeyInfo.append(serverPublicKeyData)

        let serverPublicKeyHash = subjectPublicKeyInfo.sha256().base64EncodedString()
        return allowedPublicKeyHashes.contains(serverPublicKeyHash) ? .match : .mismatch
    }
}
