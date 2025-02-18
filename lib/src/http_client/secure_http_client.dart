import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/http.dart';
import 'package:http/io_client.dart';
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';

class SecureHttpClient extends http.BaseClient {
  List<String> allowedSHAFingerprints;

  http.BaseClient _client = IOClient();

  Future<String>? secure = Future.value('');

  SecureHttpClient._internal(
      {required this.allowedSHAFingerprints, http.BaseClient? customClient}) {
    if (customClient != null) {
      _client = customClient;
    }
  }

  factory SecureHttpClient.build(List<String> allowedSHAFingerprints,
      {http.BaseClient? customClient}) {
    return SecureHttpClient._internal(
        allowedSHAFingerprints: allowedSHAFingerprints,
        customClient: customClient);
  }

  Future<Response> head(url, {Map<String, String>? headers}) =>
      _sendUnstreamed("HEAD", url, headers);

  Future<Response> get(url, {Map<String, String>? headers}) =>
      _sendUnstreamed("GET", url, headers);

  Future<Response> post(url,
          {Map<String, String>? headers, body, Encoding? encoding}) =>
      _sendUnstreamed("POST", url, headers, body, encoding);

  Future<Response> put(url,
          {Map<String, String>? headers, body, Encoding? encoding}) =>
      _sendUnstreamed("PUT", url, headers, body, encoding);

  Future<Response> patch(url,
          {Map<String, String>? headers, body, Encoding? encoding}) =>
      _sendUnstreamed("PATCH", url, headers, body, encoding);

  Future<Response> delete(url,
          {Map<String, String>? headers, body, Encoding? encoding}) =>
      _sendUnstreamed("DELETE", url, headers, body, encoding);

  Future<String> read(url, {Map<String, String>? headers}) {
    return get(url, headers: headers).then((response) {
      _checkResponseSuccess(url, response);
      return response.body;
    });
  }

  Future<Uint8List> readBytes(url, {Map<String, String>? headers}) {
    return get(url, headers: headers).then((response) {
      _checkResponseSuccess(url, response);
      return response.bodyBytes;
    });
  }

  Future<StreamedResponse> send(BaseRequest request) => _client.send(request);

  /// Sends a non-streaming [Request] and returns a non-streaming [Response].
  Future<Response> _sendUnstreamed(
      String method, url, Map<String, String>? headers,
      [body, Encoding? encoding]) async {
    // iOS bug: Alamofire is failing to return parallel requests for certificate validation
    if (Platform.isIOS && secure != null) {
      await secure;
    }

    secure = HttpCertificatePinning.check(
      serverURL: url.toString(),
      headerHttp: {},
      sha: SHA.SHA256,
      allowedSHAFingerprints: allowedSHAFingerprints,
      timeout: 50,
    );

    secure?.whenComplete(() => secure = null);
    final secureString = await secure ?? '';

    if (secureString.contains("CONNECTION_SECURE")) {
      var request = Request(method, _fromUriOrString(url));

      if (headers != null) request.headers.addAll(headers);
      if (encoding != null) request.encoding = encoding;
      if (body != null) {
        if (body is String) {
          request.body = body;
        } else if (body is List) {
          request.bodyBytes = body.cast<int>();
        } else if (body is Map) {
          request.bodyFields = body.cast<String, String>();
        } else {
          throw ArgumentError('Invalid request body "$body".');
        }
      }

      return Response.fromStream(await send(request));
    } else {
      throw CertificateNotVerifiedException();
    }
  }

  /// Throws an error if [response] is not successful.
  void _checkResponseSuccess(url, Response response) {
    if (response.statusCode < 400) return;
    var message = 'Request to $url failed with status ${response.statusCode}';
    if (response.reasonPhrase != null) {
      message = '$message: ${response.reasonPhrase}';
    }
    throw ClientException('$message.', _fromUriOrString(url));
  }

  void close() {
    _client.close();
  }
}

Uri _fromUriOrString(uri) => uri is String ? Uri.parse(uri) : uri as Uri;
