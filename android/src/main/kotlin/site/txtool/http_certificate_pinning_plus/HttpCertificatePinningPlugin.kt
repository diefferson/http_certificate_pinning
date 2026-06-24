package site.txtool.http_certificate_pinning_plus

import android.net.http.X509TrustManagerExtensions
import android.os.Handler
import android.os.Looper
import android.os.StrictMode
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.IOException
import java.net.UnknownHostException
import java.net.SocketTimeoutException
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.text.ParseException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** HttpCertificatePinningPlugin */
public class HttpCertificatePinningPlugin : FlutterPlugin, MethodCallHandler {

  companion object {
    private const val CERTIFICATE_PINNING_TARGET_LEAF = "leaf"
    private const val CERTIFICATE_PINNING_TARGET_ROOT = "root"

    @Volatile
    private var defaultTrustManager: X509TrustManager? = null

    @Volatile
    private var trustManagerExtensions: X509TrustManagerExtensions? = null
  }

  private var threadExecutorService: ExecutorService? = null
  private var handler: Handler? = null

  init {
    threadExecutorService = Executors.newSingleThreadExecutor()
    handler = Handler(Looper.getMainLooper())
  }


  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    val channel = MethodChannel(binding.binaryMessenger, "http_certificate_pinning_plus")
    channel.setMethodCallHandler(HttpCertificatePinningPlugin())
  }


  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    try {
      when (call.method) {
        "check" -> threadExecutorService?.execute {
          handleCheckEvent(call, result)
        }
        else -> result.notImplemented()
      }
    } catch (e: Exception) {
      handler?.post {
        result.error(e.toString(), "", "")
      }
    }
  }

  private fun handleCheckEvent(call: MethodCall, result: Result) {
    val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
    val serverURL: String = arguments.get("url") as String
    val allowedFingerprints: List<String> = arguments.get("fingerprints") as List<String>
    val httpHeaderArgs: Map<String, String> = arguments.get("headers") as Map<String, String>
    val timeout: Int = (arguments.get("timeout") as? Int) ?: 0
    val type: String = arguments.get("type") as String
    val certificatePinningTarget: String =
      (arguments.get("certificatePinningTarget") as? String) ?: CERTIFICATE_PINNING_TARGET_LEAF

    try {
      if (this.checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type, certificatePinningTarget)) {
        handler?.post {
          result.success("CONNECTION_SECURE")
        }
      } else {
        handler?.post {
          result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
        }
      }
    } catch (e: UnknownHostException) {
      handler?.post {
        result.error("NO_INTERNET", "No Internet Connection", e.localizedMessage)
      }
    } catch (e: SocketTimeoutException) {
      handler?.post {
        result.error("TIMEOUT", "Connection Timeout", e.localizedMessage)
      }
    } catch (e: IOException) {
      handler?.post {
        result.error("NETWORK_ERROR", "Network Error", e.localizedMessage)
      }
    } catch (e: Exception) {
      handler?.post {
        result.error("UNKNOWN_ERROR", "An Unknown Error Occurred", e.localizedMessage)
      }
    }
  }


  private fun checkConnexion(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String, certificatePinningTarget: String): Boolean {
    val fingerprint: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type, certificatePinningTarget)
    val normalizedAllowedFingerprints = allowedFingerprints.map { fp -> fp.uppercase().replace("\\s".toRegex(), "") }

    return normalizedAllowedFingerprints.contains(fingerprint)
  }


  @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class, CertificateEncodingException::class, SocketTimeoutException::class)
  private fun getFingerprint(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, type: String, certificatePinningTarget: String): String {
      val url = URL(httpsURL)
      val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection
      if (connectTimeout > 0)
          httpClient.connectTimeout = connectTimeout * 1000
      httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }

      try {
          httpClient.connect()

          val certificateChain = this.getValidatedCertificateChain(
              host = url.host,
              serverCertificates = httpClient.serverCertificates
          )
          val certificate = if (certificatePinningTarget.equals(CERTIFICATE_PINNING_TARGET_ROOT, ignoreCase = true)) {
              certificateChain.last()
          } else {
              certificateChain.first()
          }

          return this.hashString(type, certificate.encoded)
      } finally {
          httpClient.disconnect()
      }
  }

  private fun getValidatedCertificateChain(host: String, serverCertificates: Array<Certificate>): List<X509Certificate> {
      val certificateChain = serverCertificates.filterIsInstance<X509Certificate>().toTypedArray()
      if (certificateChain.isEmpty()) {
          throw CertificateException("No X509 certificates found in connection")
      }
      val trustManagerExtensions = this.getTrustManagerExtensions()
      val authType = certificateChain.first().publicKey.algorithm
      return trustManagerExtensions.checkServerTrusted(certificateChain, authType, host)
  }

  private fun getTrustManagerExtensions(): X509TrustManagerExtensions {
      var extensions = trustManagerExtensions
      if (extensions == null) {
          synchronized(HttpCertificatePinningPlugin::class.java) {
              extensions = trustManagerExtensions
              if (extensions == null) {
                  extensions = X509TrustManagerExtensions(this.getDefaultX509TrustManager())
                  trustManagerExtensions = extensions
              }
          }
      }

      return extensions ?: throw CertificateException("No X509TrustManagerExtensions available")
  }

  private fun getDefaultX509TrustManager(): X509TrustManager {
      var trustManager = defaultTrustManager
      if (trustManager == null) {
          synchronized(HttpCertificatePinningPlugin::class.java) {
              trustManager = defaultTrustManager
              if (trustManager == null) {
                  val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                  trustManagerFactory.init(null as KeyStore?)
                  trustManager = trustManagerFactory.trustManagers
                      .filterIsInstance<X509TrustManager>()
                      .firstOrNull() ?: throw CertificateException("No X509TrustManager available")
                  defaultTrustManager = trustManager
              }
          }
      }

      return trustManager ?: throw CertificateException("No X509TrustManager available")
  }

  private fun hashString(type: String, input: ByteArray) =
          MessageDigest
                  .getInstance(type)
                  .digest(input)
                  .map { String.format("%02X", it) }
                  .joinToString(separator = "")


  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}


}
