import 'dart:async';

import 'package:flutter/services.dart';

enum SHA { SHA1, SHA256 }

class HttpCertificatePinning {
  static const MethodChannel _channel =
      const MethodChannel('http_certificate_pinning');

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
    Map<String, String>? headerHttp,
    int? timeout,
  }) async {
    final Map<String, dynamic> params = <String, dynamic>{
      "url": serverURL,
      "headers": headerHttp ?? {},
      "type": sha.name,
      "fingerprints":
          allowedSHAFingerprints.map((a) => a.replaceAll(":", "")).toList(),
      "timeout": timeout
    };
    String resp = await _channel.invokeMethod('check', params);
    return resp;
  }

  /// Checks the connection to [serverURL] against public key pins: base64-encoded
  /// SHA-256 hashes of the SubjectPublicKeyInfo, as produced by
  /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`.
  ///
  /// The connection is secure when the leaf key matches one of
  /// [allowedLeafPublicKeyHashes], or, failing that, when the intermediate CA
  /// key matches one of [allowedIntermediatePublicKeyHashes]. Pinning the
  /// intermediate survives leaf certificate rotations.
  ///
  /// Pins may carry the conventional `sha256/` prefix; it is stripped before
  /// comparison.
  ///
  /// [allowCache] (default true) lets the platform HTTP stack use its normal
  /// caches. Set it to false when testing pin changes, so the probe always
  /// reaches the network; note the OS TLS session cache may still resume a
  /// recent session without re-checking pins.
  static Future<String> checkPublicKeys({
    required String serverURL,
    required List<String> allowedLeafPublicKeyHashes,
    List<String> allowedIntermediatePublicKeyHashes = const [],
    Map<String, String>? headerHttp,
    int? timeout,
    bool allowCache = true,
  }) async {
    final Map<String, dynamic> params = <String, dynamic>{
      "url": serverURL,
      "headers": headerHttp ?? {},
      "leafPublicKeyHashes":
          allowedLeafPublicKeyHashes.map(_normalizePin).toList(),
      "intermediatePublicKeyHashes":
          allowedIntermediatePublicKeyHashes.map(_normalizePin).toList(),
      "timeout": timeout,
      "allowCache": allowCache
    };
    String resp = await _channel.invokeMethod('checkPublicKeys', params);
    return resp;
  }

  /// Checks that the server's leaf (end-entity) public key matches one of
  /// [publicKeyHashes] (base64-encoded SHA-256 SubjectPublicKeyInfo hashes,
  /// see [checkPublicKeys]).
  static Future<String> checkLeaf({
    required String serverURL,
    required List<String> publicKeyHashes,
    Map<String, String>? headerHttp,
    int? timeout,
    bool allowCache = true,
  }) =>
      _checkPosition(
        method: 'checkLeaf',
        serverURL: serverURL,
        publicKeyHashes: publicKeyHashes,
        headerHttp: headerHttp,
        timeout: timeout,
        allowCache: allowCache,
      );

  /// Checks that the intermediate CA public key matches one of
  /// [publicKeyHashes]. The intermediate only exists in chains of three or
  /// more certificates; shorter chains fail the check.
  static Future<String> checkIntermediate({
    required String serverURL,
    required List<String> publicKeyHashes,
    Map<String, String>? headerHttp,
    int? timeout,
    bool allowCache = true,
  }) =>
      _checkPosition(
        method: 'checkIntermediate',
        serverURL: serverURL,
        publicKeyHashes: publicKeyHashes,
        headerHttp: headerHttp,
        timeout: timeout,
        allowCache: allowCache,
      );

  /// Checks that the root CA public key matches one of [publicKeyHashes].
  ///
  /// On iOS the root comes from the evaluated trust chain (the system trust
  /// store anchor). On Android it is the last certificate the server sent;
  /// some servers omit the root, in which case this check fails.
  static Future<String> checkRoot({
    required String serverURL,
    required List<String> publicKeyHashes,
    Map<String, String>? headerHttp,
    int? timeout,
    bool allowCache = true,
  }) =>
      _checkPosition(
        method: 'checkRoot',
        serverURL: serverURL,
        publicKeyHashes: publicKeyHashes,
        headerHttp: headerHttp,
        timeout: timeout,
        allowCache: allowCache,
      );

  static Future<String> _checkPosition({
    required String method,
    required String serverURL,
    required List<String> publicKeyHashes,
    Map<String, String>? headerHttp,
    int? timeout,
    bool allowCache = true,
  }) async {
    final Map<String, dynamic> params = <String, dynamic>{
      "url": serverURL,
      "headers": headerHttp ?? {},
      "publicKeyHashes": publicKeyHashes.map(_normalizePin).toList(),
      "timeout": timeout,
      "allowCache": allowCache
    };
    String resp = await _channel.invokeMethod(method, params);
    return resp;
  }

  static String _normalizePin(String pin) => pin
      .replaceAll(RegExp(r'\s+'), '')
      .replaceFirst('sha256/', '');

  Future _platformCallHandler(MethodCall call) async {
    print("_platformCallHandler call ${call.method} ${call.arguments}");
  }
}
