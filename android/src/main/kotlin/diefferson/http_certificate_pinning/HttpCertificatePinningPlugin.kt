package diefferson.http_certificate_pinning

import java.net.UnknownHostException
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
        "checkPublicKeys" -> threadExecutorService?.execute {
          handleCheckPublicKeysEvent(call, result)
        }
        "checkLeaf" -> threadExecutorService?.execute {
          handleCheckPositionEvent(call, result, "leaf")
        }
        "checkIntermediate" -> threadExecutorService?.execute {
          handleCheckPositionEvent(call, result, "intermediate")
        }
        "checkRoot" -> threadExecutorService?.execute {
          handleCheckPositionEvent(call, result, "root")
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


  private fun handleCheckPublicKeysEvent(call: MethodCall, result: Result) {
    val arguments: HashMap<String, Any>? = call.arguments as? HashMap<String, Any>
    val serverURL: String? = arguments?.get("url") as? String
    val leafPublicKeyHashes: List<String>? = arguments?.get("leafPublicKeyHashes") as? List<String>
    val intermediatePublicKeyHashes: List<String> = (arguments?.get("intermediatePublicKeyHashes") as? List<String>) ?: listOf()
    val httpHeaderArgs: Map<String, String> = (arguments?.get("headers") as? Map<String, String>) ?: mapOf()
    val timeout: Int = (arguments?.get("timeout") as? Int) ?: 60
    val allowCache: Boolean = (arguments?.get("allowCache") as? Boolean) ?: true

    if (serverURL == null || leafPublicKeyHashes == null) {
      handler?.post {
        result.error("Params incorrect", "The provided parameters are incorrect", null)
      }
      return
    }

    this.respondToPublicKeyCheck(result) {
      this.checkPublicKeyConnexion(serverURL, leafPublicKeyHashes, intermediatePublicKeyHashes, httpHeaderArgs, timeout, allowCache)
    }
  }

  private fun handleCheckPositionEvent(call: MethodCall, result: Result, position: String) {
    val arguments: HashMap<String, Any>? = call.arguments as? HashMap<String, Any>
    val serverURL: String? = arguments?.get("url") as? String
    val publicKeyHashes: List<String>? = arguments?.get("publicKeyHashes") as? List<String>
    val httpHeaderArgs: Map<String, String> = (arguments?.get("headers") as? Map<String, String>) ?: mapOf()
    val timeout: Int = (arguments?.get("timeout") as? Int) ?: 60
    val allowCache: Boolean = (arguments?.get("allowCache") as? Boolean) ?: true

    if (serverURL == null || publicKeyHashes == null) {
      handler?.post {
        result.error("Params incorrect", "The provided parameters are incorrect", null)
      }
      return
    }

    this.respondToPublicKeyCheck(result) {
      val chain = this.getServerCertificates(serverURL, timeout, httpHeaderArgs, allowCache)
      val certificate = this.certificateAt(position, chain)
      certificate != null && publicKeyHashes.map { it.trim() }.contains(this.publicKeyHash(certificate))
    }
  }

  private fun respondToPublicKeyCheck(result: Result, check: () -> Boolean) {
    try {
      if (check()) {
        handler?.post {
          result.success("CONNECTION_SECURE")
        }
      } else {
        handler?.post {
          result.error("CONNECTION_NOT_SECURE", "Connection is not secure", "Public key hash doesn't match")
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

  private fun checkPublicKeyConnexion(serverURL: String, leafPublicKeyHashes: List<String>, intermediatePublicKeyHashes: List<String>, httpHeaderArgs: Map<String, String>, timeout: Int, allowCache: Boolean): Boolean {
    val chain = this.getServerCertificates(serverURL, timeout, httpHeaderArgs, allowCache)

    val leaf = this.certificateAt("leaf", chain)
    if (leaf != null && leafPublicKeyHashes.map { it.trim() }.contains(this.publicKeyHash(leaf))) {
      return true
    }

    val intermediate = this.certificateAt("intermediate", chain)
    return intermediate != null && intermediatePublicKeyHashes.map { it.trim() }.contains(this.publicKeyHash(intermediate))
  }

  // The chain is ordered leaf first, root last. The intermediate sits between leaf and
  // root, so it only exists in chains of 3+. Note: the root is the last certificate the
  // server sent, which some servers omit; root pinning then fails as CONNECTION_NOT_SECURE.
  private fun certificateAt(position: String, chain: List<Certificate>): Certificate? = when (position) {
    "leaf" -> chain.firstOrNull()
    "intermediate" -> if (chain.size > 2) chain[1] else null
    "root" -> if (chain.size > 1) chain.lastOrNull() else null
    else -> null
  }

  @Throws(IOException::class, SocketTimeoutException::class)
  private fun getServerCertificates(httpsURL: String, connectTimeout: Int, httpHeaderArgs: Map<String, String>, allowCache: Boolean = true): List<Certificate> {
    val url = URL(httpsURL)
    val httpClient: HttpsURLConnection = url.openConnection() as HttpsURLConnection
    try {
      httpClient.useCaches = allowCache
      if (!allowCache) {
        // useCaches only disables the response cache; keep-alive pooling could still
        // reuse a TLS connection to the same host. Closing the connection makes a
        // cache-disabled check observe a fresh handshake.
        httpClient.setRequestProperty("Connection", "close")
      }
      if (connectTimeout > 0)
        httpClient.connectTimeout = connectTimeout * 1000
      httpHeaderArgs.forEach { (key, value) -> httpClient.setRequestProperty(key, value) }

      httpClient.connect()

      return httpClient.serverCertificates.toList()
    } finally {
      httpClient.disconnect()
    }
  }

  // PublicKey.getEncoded() returns the DER SubjectPublicKeyInfo, so this hash matches
  // standard SPKI pins (openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64).
  private fun publicKeyHash(certificate: Certificate): String =
          Base64.encodeToString(
                  MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded),
                  Base64.NO_WRAP
          )


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
