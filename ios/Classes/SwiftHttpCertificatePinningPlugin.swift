import Flutter
import UIKit
import CryptoSwift
import Alamofire

public class SwiftHttpCertificatePinningPlugin: NSObject, FlutterPlugin {

    var session: Session!
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
                result(
                    FlutterError(
                        code: "Invalid Arguments",
                        message: "Please specify arguments",
                        details: nil
                    )
                )
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    public func check(
        call: FlutterMethodCall,
        args: [String: Any],
        flutterResult: @escaping FlutterResult
    ) {
        guard let urlString = args["url"] as? String,
              let headers = args["headers"] as? [String: String],
              let fingerprints = args["fingerprints"] as? [String],
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

        let timeout = args["timeout"] as? Int ?? 60

        // Configuração da sessão com delegate personalizado
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = TimeInterval(timeout)

        session = Session(configuration: configuration)

        var resultDispatched = false

        session.request(urlString, method: .get, headers: HTTPHeaders(headers)).validate().responseJSON { response in
            switch response.result {
            case .success:
                if !resultDispatched {
                    flutterResult("CONNECTION_SECURE")
                    resultDispatched = true
                }
            case .failure(let error):
                if !resultDispatched {
                    flutterResult(
                        FlutterError(
                            code: "URL Format",
                            message: error.localizedDescription,
                            details: nil
                        )
                    )
                    resultDispatched = true
                }
            }
        }

        // Configuração do delegate para lidar com desafios de autenticação
        session.delegate.taskDidReceiveChallenge = { session, task, challenge in
            guard let serverTrust = challenge.protectionSpace.serverTrust,
                  let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
                flutterResult(
                    FlutterError(
                        code: "ERROR CERT",
                        message: "Invalid Certificate",
                        details: nil
                    )
                )
                return (.cancelAuthenticationChallenge, nil)
            }

            // Define políticas SSL para verificação de nome de domínio
            let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
            SecTrustSetPolicies(serverTrust, policies as CFTypeRef)

            // Avalia o certificado do servidor
            var result: SecTrustResultType = .invalid
            SecTrustEvaluate(serverTrust, &result)
            let isServerTrusted = (result == .unspecified || result == .proceed)

            // Obtém o hash do certificado
            let serverCertData = SecCertificateCopyData(certificate) as Data
            var serverCertHash = serverCertData.sha256().toHexString()

            if type == "SHA1" {
                serverCertHash = serverCertData.sha1().toHexString()
            }

            // Verifica se o hash do certificado está na lista de fingerprints
            let isSecure = self.fingerprints?.contains { fingerprint in
                fingerprint.replacingOccurrences(of: " ", with: "").caseInsensitiveCompare(serverCertHash) == .orderedSame
            } ?? false

            if isServerTrusted && isSecure {
                if !resultDispatched {
                    flutterResult("CONNECTION_SECURE")
                    resultDispatched = true
                }
            } else {
                if !resultDispatched {
                    flutterResult(
                        FlutterError(
                            code: "CONNECTION_NOT_SECURE",
                            message: nil,
                            details: nil
                        )
                    )
                    resultDispatched = true
                }
            }

            return (.cancelAuthenticationChallenge, nil)
        }
    }
}