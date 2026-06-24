import 'dart:async';

import 'package:flutter/services.dart';

enum SHA { SHA1, SHA256 }

enum CertificatePinningTarget { leaf, root }

class HttpCertificatePinning {
  static const String _connectionSecure = 'CONNECTION_SECURE';
  static final Map<String, DateTime> _verifiedChecks = <String, DateTime>{};
  static final Map<String, Future<String>> _pendingChecks =
      <String, Future<String>>{};
  static int _cacheGeneration = 0;

  static const MethodChannel _channel = const MethodChannel(
    'http_certificate_pinning_plus',
  );

  static final HttpCertificatePinning _sslPinning =
      HttpCertificatePinning._internal();

  factory HttpCertificatePinning() => _sslPinning;

  HttpCertificatePinning._internal() {
    _channel.setMethodCallHandler(_platformCallHandler);
  }

  static Future<String> check({
    required String serverURL,
    required SHA sha,
    required List<String> allowedSHAFingerprints,
    CertificatePinningTarget certificatePinningTarget =
        CertificatePinningTarget.leaf,
    Duration cacheDuration = const Duration(minutes: 10),
    Map<String, String>? headerHttp,
    int? timeout,
  }) async {
    final normalizedFingerprints =
        allowedSHAFingerprints.map(_normalizeFingerprint).toList();
    final Map<String, dynamic> params = <String, dynamic>{
      "url": serverURL,
      "headers": headerHttp ?? {},
      "type": sha.toString().split(".").last,
      "certificatePinningTarget":
          certificatePinningTarget.toString().split(".").last,
      "fingerprints": normalizedFingerprints,
      "timeout": timeout,
    };

    if (cacheDuration.inMicroseconds <= 0) {
      return _invokeCheck(params);
    }

    final cacheKey = _buildCacheKey(
      serverURL: serverURL,
      sha: sha,
      certificatePinningTarget: certificatePinningTarget,
      normalizedFingerprints: normalizedFingerprints,
    );

    final now = DateTime.now();
    final expiresAt = _verifiedChecks[cacheKey];
    if (expiresAt != null) {
      if (expiresAt.isAfter(now)) {
        return _connectionSecure;
      }
      _verifiedChecks.remove(cacheKey);
    }

    final pendingCheck = _pendingChecks[cacheKey];
    if (pendingCheck != null) {
      return pendingCheck;
    }

    final cacheGeneration = _cacheGeneration;
    final checkFuture = _invokeCheck(params).then((response) {
      if (cacheGeneration == _cacheGeneration &&
          response.contains(_connectionSecure)) {
        _verifiedChecks[cacheKey] = DateTime.now().add(cacheDuration);
      }
      return response;
    });

    _pendingChecks[cacheKey] = checkFuture;

    try {
      return await checkFuture;
    } finally {
      if (_pendingChecks[cacheKey] == checkFuture) {
        _pendingChecks.remove(cacheKey);
      }
    }
  }

  static void clearCache() {
    _cacheGeneration++;
    _verifiedChecks.clear();
    _pendingChecks.clear();
  }

  static Future<String> _invokeCheck(Map<String, dynamic> params) async {
    return _invokeNativeCheck(params);
  }

  static Future<String> _invokeNativeCheck(Map<String, dynamic> params) async {
    String resp = await _channel.invokeMethod('check', params);
    return resp;
  }

  static String _buildCacheKey({
    required String serverURL,
    required SHA sha,
    required CertificatePinningTarget certificatePinningTarget,
    required List<String> normalizedFingerprints,
  }) {
    final fingerprints = List<String>.from(normalizedFingerprints)..sort();

    return <String>[
      _serverIdentity(serverURL),
      sha.toString().split(".").last,
      certificatePinningTarget.toString().split(".").last,
      fingerprints.join(";"),
    ].join("|");
  }

  static String _serverIdentity(String serverURL) {
    final uri = Uri.tryParse(serverURL);
    if (uri == null || uri.host.isEmpty) {
      return serverURL.toLowerCase();
    }

    final scheme = uri.scheme.isEmpty ? "https" : uri.scheme.toLowerCase();
    final port = uri.hasPort ? uri.port : _defaultPortForScheme(scheme);
    final portSuffix = port == null ? "" : ":$port";

    return "$scheme://${uri.host.toLowerCase()}$portSuffix";
  }

  static int? _defaultPortForScheme(String scheme) {
    if (scheme == "https") {
      return 443;
    }
    if (scheme == "http") {
      return 80;
    }
    return null;
  }

  static String _normalizeFingerprint(String fingerprint) {
    return fingerprint.replaceAll(RegExp(r"[\s:]"), "").toUpperCase();
  }

  Future _platformCallHandler(MethodCall call) async {
    print("_platformCallHandler call ${call.method} ${call.arguments}");
  }
}
