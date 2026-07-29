import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class HttpCertificatePinningPlugin: NSObject, FlutterPlugin {
    var fingerprints: Array<String>?
    var flutterResult: FlutterResult?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = HttpCertificatePinningPlugin()
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
        case "checkPublicKeys":
            if let _args = call.arguments as? Dictionary<String, AnyObject> {
                self.checkPublicKeys(args: _args, flutterResult: result)
            } else {
                result(
                    FlutterError(
                        code: "Invalid Arguments",
                        message: "Please specify arguments",
                        details: nil)
                )
            }
            break
        case "checkLeaf":
            self.checkPublicKeys(at: .leaf, call: call, flutterResult: result)
            break
        case "checkIntermediate":
            self.checkPublicKeys(at: .intermediate, call: call, flutterResult: result)
            break
        case "checkRoot":
            self.checkPublicKeys(at: .root, call: call, flutterResult: result)
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
              let host = URL(string: urlString)?.host,
              let headers = args["headers"] as? Dictionary<String, String>,
              let fingerprints = args["fingerprints"] as? Array<String>,
              let type = args["type"] as? String
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "The provided parameters are incorrect",
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

        let evaluator =   CertificateSHAFingerprintTrustEvaluator(pinnedFingerprints: fingerprints, type: type)
        let serverTrustManager = ServerTrustManager(allHostsMustBeEvaluated: false, evaluators: [host: evaluator])
        let manager = Alamofire.Session(configuration: URLSessionConfiguration.default,
                                                serverTrustManager:   serverTrustManager)

        manager.session.configuration.timeoutIntervalForRequest = TimeInterval(timeout)

        manager.request(urlString, method: .get, parameters: headers).validate().responseData() { response in
            switch response.result {
            case .success:
                flutterResult("CONNECTION_SECURE")
                break
            case .failure(let error):
                if let responseCode = error.responseCode, (200...599).contains(responseCode) {
                    flutterResult("CONNECTION_SECURE")
                } else {
                    flutterResult(
                        FlutterError(
                            code: "CONNECTION_NOT_SECURE",
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
    }

    public func checkPublicKeys(
        args: Dictionary<String, AnyObject>,
        flutterResult: @escaping FlutterResult
    ){
        guard let urlString = args["url"] as? String,
              let host = URL(string: urlString)?.host,
              let headers = args["headers"] as? Dictionary<String, String>,
              let leafPublicKeyHashes = args["leafPublicKeyHashes"] as? Array<String>
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "The provided parameters are incorrect",
                    details: nil
                )
            )
            return
        }

        let intermediatePublicKeyHashes = args["intermediatePublicKeyHashes"] as? Array<String> ?? []

        self.performPublicKeyCheck(
            urlString: urlString,
            host: host,
            headers: headers,
            allowedPublicKeyHashes: [
                .leaf: Set(leafPublicKeyHashes),
                .intermediate: Set(intermediatePublicKeyHashes)
            ],
            timeout: args["timeout"] as? Int ?? 60,
            allowCache: args["allowCache"] as? Bool ?? true,
            flutterResult: flutterResult
        )
    }

    /// Handles the position-specific check methods (`checkLeaf`, `checkIntermediate`,
    /// `checkRoot`), which pin a single chain position through `publicKeyHashes`.
    func checkPublicKeys(
        at position: CertificatePosition,
        call: FlutterMethodCall,
        flutterResult: @escaping FlutterResult
    ){
        guard let args = call.arguments as? Dictionary<String, AnyObject> else {
            flutterResult(
                FlutterError(
                    code: "Invalid Arguments",
                    message: "Please specify arguments",
                    details: nil
                )
            )
            return
        }

        guard let urlString = args["url"] as? String,
              let host = URL(string: urlString)?.host,
              let headers = args["headers"] as? Dictionary<String, String>,
              let publicKeyHashes = args["publicKeyHashes"] as? Array<String>
        else {
            flutterResult(
                FlutterError(
                    code: "Params incorrect",
                    message: "The provided parameters are incorrect",
                    details: nil
                )
            )
            return
        }

        self.performPublicKeyCheck(
            urlString: urlString,
            host: host,
            headers: headers,
            allowedPublicKeyHashes: [position: Set(publicKeyHashes)],
            timeout: args["timeout"] as? Int ?? 60,
            allowCache: args["allowCache"] as? Bool ?? true,
            flutterResult: flutterResult
        )
    }

    private func performPublicKeyCheck(
        urlString: String,
        host: String,
        headers: Dictionary<String, String>,
        allowedPublicKeyHashes: [CertificatePosition: Set<String>],
        timeout: Int,
        allowCache: Bool,
        flutterResult: @escaping FlutterResult
    ){
        let checker = PublicKeyPinningChecker(
            host: host,
            allowedPublicKeyHashes: allowedPublicKeyHashes,
            timeout: timeout,
            allowCache: allowCache
        )

        checker.check(url: urlString, headers: headers) { result in
            switch result {
            case .success:
                flutterResult("CONNECTION_SECURE")
            case .failure(let failure):
                flutterResult(
                    FlutterError(
                        code: failure.code,
                        message: failure.message,
                        details: nil
                    )
                )
            }
        }
    }
}
