import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final Set<String> verifiedURLs = {};
  Future<String>? secure = Future.value('');
  CertificatePinningInterceptor(this._allowedSHAFingerprints);

  @override
  Future onRequest(
      RequestOptions options, RequestInterceptorHandler handler) async {
// skip verification if already verified, performance
    if (verifiedURLs.contains(options.baseUrl)) {
      return super.onRequest(options, handler);
    }
// iOS bug: Alamofire is failing to return parallel requests for certificate validation
    if (Platform.isIOS && secure != null) {
      await secure;
    }

    secure = HttpCertificatePinning.check(
        serverURL: options.baseUrl,
        headerHttp: options.headers.map((a, b) => MapEntry(a, b.toString())),
        sha: SHA.SHA256,
        allowedSHAFingerprints: _allowedSHAFingerprints,
        timeout: 50);
    secure?.whenComplete(() => secure = null);
    final secureString = await secure;

    if (secureString!.contains("CONNECTION_SECURE")) {
      // record success
      verifiedURLs.add(options.baseUrl);
      return super.onRequest(options, handler);
    } else {
      throw Exception("CONNECTION_NOT_SECURE");
    }
  }
}
