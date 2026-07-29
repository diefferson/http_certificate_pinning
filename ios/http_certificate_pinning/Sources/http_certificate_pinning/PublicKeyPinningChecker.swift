//
//  PublicKeyPinningChecker.swift
//
//  Created by Kevin ASSI on 29/07/2026.
//

import Foundation
import Alamofire

/// Wraps a `PublicKeyPinningTrustEvaluator` in a configured Alamofire session and performs
/// a single probe request against the pinned host, mapping the outcome to the platform
/// channel codes shared with the Android implementation.
final class PublicKeyPinningChecker {

    /// A failed check, carrying the platform channel error code and message.
    enum Failure: Error {
        /// The TLS handshake was rejected: pin mismatch or untrusted chain.
        case connectionNotSecure(String)
        /// The device has no usable network connection.
        case noInternet(String)
        /// The request timed out before the handshake completed.
        case timeout(String)
        /// Any other transport-level failure (DNS, connection reset, ...).
        case networkError(String)
        /// A failure that is none of the above.
        case unknown(String)

        var code: String {
            switch self {
            case .connectionNotSecure:
                return "CONNECTION_NOT_SECURE"
            case .noInternet:
                return "NO_INTERNET"
            case .timeout:
                return "TIMEOUT"
            case .networkError:
                return "NETWORK_ERROR"
            case .unknown:
                return "UNKNOWN_ERROR"
            }
        }

        var message: String {
            switch self {
            case .connectionNotSecure(let message),
                 .noInternet(let message),
                 .timeout(let message),
                 .networkError(let message),
                 .unknown(let message):
                return message
            }
        }
    }

    private let session: Session

    init(host: String,
         allowedPublicKeyHashes: [CertificatePosition: Set<String>],
         timeout: Int,
         allowCache: Bool = true) {
        let evaluator = PublicKeyPinningTrustEvaluator(allowedPublicKeyHashes: allowedPublicKeyHashes)
        // Fail closed: any host other than the pinned one is rejected instead of
        // falling back to default trust evaluation.
        let serverTrustManager = ServerTrustManager(allHostsMustBeEvaluated: true,
                                                    evaluators: [host: evaluator])
        // With allowCache disabled the probe may never be answered from an HTTP
        // cache, so it always observes a real handshake. Note that the OS-level TLS
        // session cache can still resume a recent TLS session without re-issuing the
        // trust challenge; it is per process and cannot be flushed through public API.
        let configuration: URLSessionConfiguration
        if allowCache {
            configuration = URLSessionConfiguration.default
        } else {
            configuration = URLSessionConfiguration.ephemeral
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        }
        configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        session = Session(configuration: configuration, serverTrustManager: serverTrustManager)
    }

    /// Requests the URL through the pinned session. Any HTTP response — whatever its
    /// status code — means the handshake, and therefore the pin, was accepted.
    func check(url: String, headers: [String: String], completion: @escaping (Result<Void, Failure>) -> Void) {
        // Redirects are not followed: the handshake with the pinned host is the only
        // thing being verified, and a redirect target would be a different host.
        // Capturing the session keeps it alive until the response arrives, even if
        // this checker is released by the caller.
        session.request(url, method: .get, headers: HTTPHeaders(headers))
            .redirect(using: Redirector.doNotFollow)
            .responseData { [session] response in
            let _ = session

            switch response.result {
            case .success:
                completion(.success(()))
            case .failure(let error):
                if response.response != nil {
                    completion(.success(()))
                } else {
                    completion(.failure(Self.failure(from: error)))
                }
            }
        }
    }

    private static func failure(from error: AFError) -> Failure {
        if error.isServerTrustEvaluationError {
            return .connectionNotSecure(error.localizedDescription)
        }

        guard let urlError = error.underlyingError as? URLError else {
            return .unknown(error.localizedDescription)
        }

        switch urlError.code {
        case .notConnectedToInternet, .dataNotAllowed, .internationalRoamingOff:
            return .noInternet(urlError.localizedDescription)
        case .timedOut:
            return .timeout(urlError.localizedDescription)
        case .cancelled, .serverCertificateUntrusted, .secureConnectionFailed, .clientCertificateRejected:
            // A trust challenge rejected outside the evaluator surfaces as a generic
            // TLS or cancellation error instead of a server trust evaluation error.
            return .connectionNotSecure(urlError.localizedDescription)
        default:
            return .networkError(urlError.localizedDescription)
        }
    }
}
