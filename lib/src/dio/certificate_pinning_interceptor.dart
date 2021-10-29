import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

import '../exceptions/exceptions.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    int timeout = 0,
  })  : _allowedSHAFingerprints = allowedSHAFingerprints == null
            ? allowedSHAFingerprints!
            : <String>[],
        _timeout = timeout;

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      final secure = await HttpCertificatePinning.check(
        serverURL: options.baseUrl,
        headerHttp: options.headers.map((a, b) => MapEntry(a, b.toString())),
        sha: SHA.SHA256,
        allowedSHAFingerprints: _allowedSHAFingerprints,
        timeout: _timeout,
      );

      if (secure.contains('CONNECTION_SECURE')) {
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
