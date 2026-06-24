import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;
  final CertificatePinningTarget _certificatePinningTarget;
  final Duration _cacheDuration;
  final bool callFollowingErrorInterceptor;
  final SHA _sha;

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    int timeout = 0,
    SHA sha = SHA.SHA256,
    CertificatePinningTarget certificatePinningTarget =
        CertificatePinningTarget.leaf,
    Duration cacheDuration = const Duration(minutes: 10),
    this.callFollowingErrorInterceptor = false,
  })  : _allowedSHAFingerprints = allowedSHAFingerprints != null
            ? allowedSHAFingerprints
            : <String>[],
        _sha = sha,
        _certificatePinningTarget = certificatePinningTarget,
        _cacheDuration = cacheDuration,
        _timeout = timeout;

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      var baseUrl = options.baseUrl;

      if (options.path.contains('http') || options.baseUrl.isEmpty) {
        baseUrl = options.path;
      }

      final secureString = await HttpCertificatePinning.check(
        serverURL: baseUrl,
        headerHttp: {},
        sha: _sha,
        allowedSHAFingerprints: _allowedSHAFingerprints,
        certificatePinningTarget: _certificatePinningTarget,
        cacheDuration: _cacheDuration,
        timeout: _timeout,
      );

      if (secureString.contains('CONNECTION_SECURE')) {
        return super.onRequest(options, handler);
      } else {
        handler.reject(
          DioException(
            requestOptions: options,
            error: CertificateNotVerifiedException(),
          ),
          callFollowingErrorInterceptor,
        );
      }
    } on Exception catch (e) {
      dynamic error;

      if (e is PlatformException && e.code == 'CONNECTION_NOT_SECURE') {
        error = const CertificateNotVerifiedException();
      } else if (e is PlatformException && e.code == 'NO_INTERNET') {
        return handler.reject(
          DioException.connectionError(
            requestOptions: options,
            reason: 'NO_INTERNET',
          ),
        );
      } else {
        error = CertificateCouldNotBeVerifiedException(e);
      }

      handler.reject(
        DioException(requestOptions: options, error: error),
        callFollowingErrorInterceptor,
      );
    }
  }
}
