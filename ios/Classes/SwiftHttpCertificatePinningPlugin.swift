import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    var fingerprints: [String]?
    var flutterResult: FlutterResult?
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "http_certificate_pinning", binaryMessenger: registrar.messenger())
        let instance = SwiftHttpCertificatePinningPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "check":
            if let args = call.arguments as? [String: Any] {
                self.check(call: call, args: args, flutterResult: result)
            } else {
                result(FlutterError(code: "Invalid Arguments", message: "Please specify arguments", details: nil))
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    public func check(call: FlutterMethodCall, args: [String: Any], flutterResult: @escaping FlutterResult) {
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? [String: String],
              let fingerprints = args["fingerprints"] as? [String],
              let type = args["type"] as? String else {
            flutterResult(FlutterError(code: "Params incorrect", message: "Invalid parameters", details: nil))
            return
        }

        self.fingerprints = fingerprints.map { $0.replacingOccurrences(of: " ", with: "") }
        let timeout = (args["timeout"] as? Int) ?? 60
        
        // Configuração do ServerTrustManager para validar o certificado
        let serverTrustManager = ServerTrustManager(evaluators: [
            urlString: CustomServerTrustEvaluator(allowedFingerprints: self.fingerprints!, hashType: type)
        ])
        
        let session = Session(configuration: .default, serverTrustManager: serverTrustManager)
        
        session.request(urlString, method: .get, headers: HTTPHeaders(headers)).validate().responseJSON { response in
            switch response.result {
            case .success:
                flutterResult("CONNECTION_SECURE")
            case .failure(let error):
                flutterResult(FlutterError(code: "CONNECTION_NOT_SECURE", message: error.localizedDescription, details: nil))
            }
        }
    }
}

// Classe personalizada para validar o certificado com SHA-256 ou SHA-1
class CustomServerTrustEvaluator: ServerTrustEvaluating {
    let allowedFingerprints: [String]
    let hashType: String
    
    init(allowedFingerprints: [String], hashType: String) {
        self.allowedFingerprints = allowedFingerprints
        self.hashType = hashType
    }

    func evaluate(_ trust: SecTrust, forHost host: String) throws {
        guard let certificate = SecTrustGetCertificateAtIndex(trust, 0) else {
            throw AFError.serverTrustEvaluationFailed(reason: .noCertificatesFound)
        }

        let serverCertData = SecCertificateCopyData(certificate) as Data
        var serverCertSha = serverCertData.sha256().toHexString()

        if hashType == "SHA1" {
            serverCertSha = serverCertData.sha1().toHexString()
        }

        let isSecure = allowedFingerprints.contains { $0.caseInsensitiveCompare(serverCertSha) == .orderedSame }

        if !isSecure {
            throw AFError.serverTrustEvaluationFailed(reason: .noPublicKeysFound)
        }
    }
}
