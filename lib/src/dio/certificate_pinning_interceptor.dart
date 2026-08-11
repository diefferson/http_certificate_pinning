import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

class CertificatePinningInterceptor extends Interceptor {
  final List<String> _allowedSHAFingerprints;
  final int _timeout;
  final bool callFollowingErrorInterceptor;
  FutureOr<String> Function()? onTimeout;
  Future<String>? secure = Future.value('');

  CertificatePinningInterceptor({
    List<String>? allowedSHAFingerprints,
    int timeout = 60000,
    this.callFollowingErrorInterceptor = false,
    this.onTimeout,
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
      ).timeout(Duration(milliseconds: _timeout),
          onTimeout: onTimeout ??
              () {
                throw DioException.connectionTimeout(
                    timeout: Duration(milliseconds: _timeout),
                    requestOptions: options);
              });
      ;

      final secureString = await secure?.whenComplete(() => secure = null);

      if (secureString?.contains('CONNECTION_SECURE') ?? false) {
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
        DioException(
          requestOptions: options,
          error: error,
        ),
        callFollowingErrorInterceptor,
      );
    }
  }
}
