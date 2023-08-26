import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;
  final bool _callFollowingErrorInterceptor;
  Future<String>? secure = Future.value('');

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    int timeout = 0,
    bool callFollowingErrorInterceptor = false,
  })  : _allowedSHAFingerprints = allowedSHAFingerprints ?? [],
        _timeout = timeout,
        _callFollowingErrorInterceptor = callFollowingErrorInterceptor;

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      // iOS bug: Alamofire is failing to return parallel requests for certificate validation
      if (Platform.isIOS && secure != null) {
        await secure;
      }

      var baseUrl = options.baseUrl;

      if (options.path.contains('http') || options.baseUrl.isEmpty) {
        baseUrl = options.path;
      }

      secure = HttpCertificatePinning.check(
        serverURL: baseUrl,
        headerHttp: {},
        sha: SHA.SHA256,
        allowedSHAFingerprints: _allowedSHAFingerprints,
        timeout: _timeout,
      );

      secure?.whenComplete(() => secure = null);
      final secureString = await secure ?? '';

      if (secureString.contains('CONNECTION_SECURE')) {
        return super.onRequest(options, handler);
      } else {
        handler.reject(
          DioException(
            requestOptions: options,
            error: CertificateNotVerifiedException(),
          ),
          _callFollowingErrorInterceptor,
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
        DioException(
          requestOptions: options,
          error: error,
        ),
        _callFollowingErrorInterceptor,
      );
    }
  }
}
