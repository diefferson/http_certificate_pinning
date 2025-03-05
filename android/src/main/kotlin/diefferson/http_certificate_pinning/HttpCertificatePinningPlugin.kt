package diefferson.http_certificate_pinning

import java.net.UnknownHostException
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
import java.net.SocketTimeoutException
import java.net.URL
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.cert.Certificate
import java.security.cert.CertificateEncodingException
import java.text.ParseException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection
import javax.security.cert.CertificateException

/** HttpCertificatePinningPlugin */
public class HttpCertificatePinningPlugin : FlutterPlugin, MethodCallHandler {

  private var threadExecutorService: ExecutorService? = null
  private var handler: Handler? = null

  init {
    threadExecutorService = Executors.newSingleThreadExecutor()
    handler = Handler(Looper.getMainLooper())
  }


  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    val channel = MethodChannel(binding.binaryMessenger, "http_certificate_pinning")
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
    val timeout: Int = arguments.get("timeout") as Int
    val type: String = arguments.get("type") as String

    try {
      if (this.checkConnexion(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type)) {
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


  private fun checkConnexion(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String): Boolean {
    val sha: String = this.getFingerprint(serverURL, timeout, httpHeaderArgs, type)
    return allowedFingerprints.map { fp -> fp.uppercase().replace("\\s".toRegex(), "") }.contains(sha)
  }

  @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class, CertificateEncodingException::class, SocketTimeoutException::class)
  private fun getFingerprint(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, type: String): String {

    val url = URL(httpsURL)
    val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection
    if (connectTimeout > 0)
      httpClient.connectTimeout = connectTimeout * 1000
    httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }

    httpClient.connect()

    val cert: Certificate = httpClient.serverCertificates[0] as Certificate
    return this.hashString(type, cert.encoded)
  }

  private fun hashString(type: String, input: ByteArray) =
          MessageDigest
                  .getInstance(type)
                  .digest(input)
                  .map { String.format("%02X", it) }
                  .joinToString(separator = "")


  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}


}
