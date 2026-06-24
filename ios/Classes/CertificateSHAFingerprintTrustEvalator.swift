import Foundation
import CryptoKit
import CommonCrypto
import Alamofire


final class CertificateSHAFingerprintTrustEvaluator: ServerTrustEvaluating {
    private static let certificatePinningTargetRoot = "root"

    let pinnedFingerprints: [String]
    let type: String
    let certificatePinningTarget: String
    
    init(
        pinnedFingerprints: [String],
        type: String,
        certificatePinningTarget: String
    ) {
        self.type = type.uppercased()
        self.certificatePinningTarget = certificatePinningTarget.lowercased()
        self.pinnedFingerprints = pinnedFingerprints.map { $0.lowercased() }
    }
    
    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        let policies: [SecPolicy] = [SecPolicyCreateSSL(true, host as CFString)]
        SecTrustSetPolicies(trust, policies as CFTypeRef)
        
        var result: SecTrustResultType = .invalid
        SecTrustEvaluate(trust, &result)
        
        let isServerTrusted = (result == .unspecified || result == .proceed)
        let certificateCount = SecTrustGetCertificateCount(trust)
        guard isServerTrusted, certificateCount > 0 else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .trustEvaluationFailed(error: nil)
            )
        }

        let certificateIndex: CFIndex
        if certificatePinningTarget == Self.certificatePinningTargetRoot {
            certificateIndex = certificateCount - 1
        } else {
            certificateIndex = 0
        }

        guard let certificate = SecTrustGetCertificateAtIndex(trust, certificateIndex) else {
            throw AFError.serverTrustEvaluationFailed(
                reason: .trustEvaluationFailed(error: nil)
            )
        }
        
        let serverCertData = SecCertificateCopyData(certificate) as Data
        var serverCertSha = serverCertData.sha256().toHexString()
        
        if(type == "SHA1"){
            serverCertSha = serverCertData.sha1().toHexString()
        }
        
        var isSecure = false
        let fps = self.pinnedFingerprints.compactMap { (val) -> String? in
            val.replacingOccurrences(of: " ", with: "")
        }
        
        isSecure = fps.contains(where: { (value) -> Bool in
            value.caseInsensitiveCompare(serverCertSha) == .orderedSame
        })
        
        if !isSecure {
            throw AFError.serverTrustEvaluationFailed(
                reason: .noCertificatesFound
            )
        }
        
    }
}

extension Data {
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        
        _ = self.withUnsafeBytes { buffer in
            CC_SHA256(buffer.baseAddress, CC_LONG(self.count), &digest)
        }
        
        return Data(bytes: digest, count: digest.count)
    }
    
    func sha1() -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        
        _ = self.withUnsafeBytes { buffer in
            CC_SHA1(buffer.baseAddress, CC_LONG(self.count), &digest)
        }
        
        return Data(bytes: digest, count: digest.count)
    }
    
    func toHexString() -> String {
        return self.map { String(format: "%02hhx", $0) }.joined()
    }
}
