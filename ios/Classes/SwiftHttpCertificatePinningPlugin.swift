import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    let manager = Alamofire.SessionManager.default
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?

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
            guard let serverTrust = challenge.protectionSpace.serverTrust, let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
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

            // Evaluate server certificate
            var result: SecTrustResultType = .invalid
            SecTrustEvaluate(serverTrust, &result)
            let isServerTrusted: Bool = (result == .unspecified || result == .proceed)

            let serverCertData = SecCertificateCopyData(certificate) as Data
            var serverCertSha = serverCertData.sha256().toHexString()

            if(type == "SHA1"){
                serverCertSha = serverCertData.sha1().toHexString()
            }

            var isSecure = false
            if var fp = self.fingerprints {
                fp = fp.compactMap { (val) -> String? in
                    val.replacingOccurrences(of: " ", with: "")
            }

                isSecure = fp.contains(where: { (value) -> Bool in
                    value.caseInsensitiveCompare(serverCertSha) == .orderedSame
                })
            }

            if isServerTrusted && isSecure {
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
}
