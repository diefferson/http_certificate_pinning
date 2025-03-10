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
}
