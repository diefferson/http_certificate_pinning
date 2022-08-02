import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;
  final Set<String> verifiedURLs = {};
  Future<String>? secure = Future.value('');

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    int timeout = 0,
  })  : _allowedSHAFingerprints = allowedSHAFingerprints != null
            ? allowedSHAFingerprints
            : <String>[],
        _timeout = timeout;

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
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
        timeout: _timeout,
      );

      secure?.whenComplete(() => secure = null);
      final secureString = await secure ?? '';

      if (secureString.contains('CONNECTION_SECURE')) {
        verifiedURLs.add(options.baseUrl);
        return super.onRequest(options, handler);
      } else {
        handler.reject(
          DioError(
            requestOptions: options,
            error: CertificateNotVerifiedException(),
          ),
        );
      }
    } on Exception catch (e) {
      dynamic error;

      if (e is PlatformException && e.code == 'CONNECTION_NOT_SECURE') {
        error = const CertificateNotVerifiedException();
      } else {
        error = CertificateCouldNotBeVerifiedException(e);
      }

      handler.reject(
        DioError(
          requestOptions: options,
          error: error,
        ),
      );
    }
  }
}
