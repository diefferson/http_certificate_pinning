package diefferson.http_certificate_pinning


import android.os.Handler
import android.os.Looper
import android.os.StrictMode
import android.util.Base64
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
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

  companion object {
    @JvmStatic
    fun registerWith(registrar: Registrar) {
      val channel = MethodChannel(registrar.messenger(), "http_certificate_pinning")
      channel.setMethodCallHandler(HttpCertificatePinningPlugin())
    }
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

  @Throws(ParseException::class)
  private fun handleCheckEvent(call: MethodCall, result: Result) {

    val arguments: HashMap<String, Any> = call.arguments as HashMap<String, Any>
    val serverURL: String = arguments.get("url") as String
    val allowedFingerprints: List<String> = arguments.get("fingerprints") as List<String>
    val httpHeaderArgs: Map<String, String> = arguments.get("headers") as Map<String, String>
    val timeout: Int = arguments.get("timeout") as Int
    val type: String = arguments.get("type") as String

    if (this.checkConnection(serverURL, allowedFingerprints, httpHeaderArgs, timeout, type)) {
      handler?.post {
        result.success("CONNECTION_SECURE")
      }
    } else {
      handler?.post {
        result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Fingerprint doesn't match")
      }
    }

  }

  @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class, CertificateEncodingException::class, SocketTimeoutException::class)
  private fun checkConnection(serverURL: String, allowedFingerprints: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, type: String): Boolean {
    val url = URL(serverURL)
    val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection
    if (connectTimeout > 0)
      httpClient.connectTimeout = connectTimeout * 1000
    httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }

    try {
      httpClient.connect()
    } catch (socket: SocketTimeoutException) {
      return false
    } catch (io: IOException) {
      return false
    }

    httpClient.serverCertificates.forEach {
      val server = hashString(url.host, type, it.publicKey.encoded)
      for (client in allowedFingerprints) {
        if (server == client) {
          return true
        }
      }
    }
    return false
  }

  private fun hashString(
    host: String,
    type: String,
    input: ByteArray
  ): String {
    val hashString = Base64.encodeToString(MessageDigest
        .getInstance(type)
        .digest(input),
      Base64.DEFAULT
    ).replace("\n", "").replace("\r", "")
    return hashString
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {}
}