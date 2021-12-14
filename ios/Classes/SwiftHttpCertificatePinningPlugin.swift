import Flutter
import UIKit
import CryptoSwift
import CommonCrypto
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {
    
    let manager = Alamofire.SessionManager.default
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?
    let rsa2048Asn1Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch (call.method) {
        case "check":
            if let _args = call.arguments as? Dictionary<String, AnyObject> {
                self.check(call: call, args: _args, flutterResult: result)
            } else {
                result(
                    FlutterError(
                        code: "Invalid Arguments",
                        message: "Please specify arguments",
                        details: nil)
                )
            }
            break
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    public func check(
        call: FlutterMethodCall,
        args: Dictionary<String, AnyObject>,
        flutterResult: @escaping FlutterResult
    ){
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? Dictionary<String, String>,
              let fingerprints = args["fingerprints"] as? Array<String>,
              let type = args["type"] as? String
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "Les params sont incorrect",
                    details: nil
                )
            )
            return
        }
        
        self.fingerprints = fingerprints
        
        var timeout = 60
        if let timeoutArg = args["timeout"] as? Int {
            timeout = timeoutArg
        }
        
        let manager = Alamofire.SessionManager(
            configuration: URLSessionConfiguration.default
        )
        
        var resultDispatched = false;
        
        manager.session.configuration.timeoutIntervalForRequest = TimeInterval(timeout)
        
        manager.request(urlString, method: .get, parameters: headers).validate().responseJSON() { response in
            switch response.result {
            case .success:
                break
            case .failure(let error):
                if (!resultDispatched) {
                    flutterResult(
                        FlutterError(
                            code: "URL Format",
                            message: error.localizedDescription,
                            details: nil
                        )
                    )
                }
                break
            }
            
            // To retain
            let _ = manager
        }
        
        manager.delegate.sessionDidReceiveChallenge = { session, challenge in
            
            guard let serverTrust = challenge.protectionSpace.serverTrust else {
                flutterResult(
                    FlutterError(
                        code: "ERROR CERT",
                        message: "Invalid Certificate",
                        details: nil
                    )
                )
                
                return (.cancelAuthenticationChallenge, nil)
            }
            
            let certCount = SecTrustGetCertificateCount(serverTrust)
            if certCount <= 0 {
                flutterResult(
                    FlutterError(
                        code: "ERROR CERT",
                        message: "Invalid Certificate",
                        details: nil
                    )
                )
                
                return (.cancelAuthenticationChallenge, nil)
            }
            
            // Set SSL policies for domain name check
            let policies: [SecPolicy] = [SecPolicyCreateSSL(true, (challenge.protectionSpace.host as CFString))]
            SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
            
            var result: SecTrustResultType = .invalid
            SecTrustEvaluate(serverTrust, &result)
            let isServerTrusted: Bool = (result == .unspecified || result == .proceed)
            
            var success = false
            for index in 0..<certCount {
                guard let certificate = SecTrustGetCertificateAtIndex(serverTrust, index),
                      let serverPublicKey = self.publicKey(for: certificate),
                      let serverPublicKeyCFData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) else {
                          break
                      }
                // Evaluate server certificate
                
                let serverPublicKeyData: Data = serverPublicKeyCFData as Data
                var serverPublicKeySha = self.sha256(data: serverPublicKeyData)
                
                if type == "SHA1" {
                    serverPublicKeySha = self.sha1(data: serverPublicKeyData)
                }
                
                var isSecure = false
                if var fp = self.fingerprints {
                    fp = fp.compactMap { (val) -> String? in
                        val.replacingOccurrences(of: " ", with: "")
                    }
                    
                    isSecure = fp.contains(where: { (value) -> Bool in
                        value.caseInsensitiveCompare(serverPublicKeySha) == .orderedSame
                    })
                }
                
                if isServerTrusted && isSecure {
                    success = true
                    break
                }
            }
            
            if success {
                flutterResult("CONNECTION_SECURE")
                resultDispatched = true
            } else {
                flutterResult(
                    FlutterError(
                        code: "CONNECTION_INSECURE",
                        message: nil,
                        details: nil
                    )
                )
                resultDispatched = true
            }
            
            return (.cancelAuthenticationChallenge, nil)
        }
    }
    
    private func publicKey(for certificate: SecCertificate) -> SecKey? {
        if #available(iOS 12.0, *) {
            return SecCertificateCopyKey(certificate)
        } else if #available(iOS 10.3, *) {
            return SecCertificateCopyPublicKey(certificate)
        } else {
            var possibleTrust: SecTrust?
            SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &possibleTrust)
            
            guard let trust = possibleTrust else { return nil }
            var result: SecTrustResultType = .unspecified
            SecTrustEvaluate(trust, &result)
            
            return SecTrustCopyPublicKey(trust)
        }
    }
    
    private func sha256(data: Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(keyWithHeader.count), &hash)
        }
        
        return Data(hash).base64EncodedString()
    }
    
    private func sha1(data: Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(keyWithHeader.count), &hash)
        }
        
        return Data(hash).base64EncodedString()
    }
}
