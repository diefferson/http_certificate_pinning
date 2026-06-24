import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('http_certificate_pinning_plus');

  tearDown(() {
    HttpCertificatePinning.clearCache();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('caches successful checks for the same certificate identity', () async {
    var nativeCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      nativeCalls++;
      return 'CONNECTION_SECURE';
    });

    await HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
    );
    await HttpCertificatePinning.check(
      serverURL: 'https://example.com/orders',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA BB'],
    );

    expect(nativeCalls, 1);
  });

  test('does not cache checks when cache duration is zero', () async {
    var nativeCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      nativeCalls++;
      return 'CONNECTION_SECURE';
    });

    await HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
      cacheDuration: Duration.zero,
    );
    await HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
      cacheDuration: Duration.zero,
    );

    expect(nativeCalls, 2);
  });

  test('joins concurrent checks for the same certificate identity', () async {
    var nativeCalls = 0;
    final completer = Completer<String>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) {
      nativeCalls++;
      return completer.future;
    });

    final firstCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
    );
    final secondCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/orders',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA BB'],
    );

    await Future<void>.delayed(Duration.zero);
    expect(nativeCalls, 1);

    completer.complete('CONNECTION_SECURE');

    expect(
      await Future.wait(<Future<String>>[firstCheck, secondCheck]),
      const ['CONNECTION_SECURE', 'CONNECTION_SECURE'],
    );
  });

  test('clearCache prevents pending checks from repopulating cache', () async {
    var nativeCalls = 0;
    final completer = Completer<String>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) {
      nativeCalls++;
      return completer.future;
    });

    final pendingCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
    );

    await Future<void>.delayed(Duration.zero);
    expect(nativeCalls, 1);

    HttpCertificatePinning.clearCache();
    completer.complete('CONNECTION_SECURE');
    await pendingCheck;

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      nativeCalls++;
      return 'CONNECTION_SECURE';
    });

    await HttpCertificatePinning.check(
      serverURL: 'https://example.com/orders',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA BB'],
    );

    expect(nativeCalls, 2);
  });

  test('completed stale checks do not remove newer pending checks', () async {
    var nativeCalls = 0;
    final completers = <Completer<String>>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) {
      nativeCalls++;
      final completer = Completer<String>();
      completers.add(completer);
      return completer.future;
    });

    final firstCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/login',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
    );
    await Future<void>.delayed(Duration.zero);
    expect(nativeCalls, 1);

    HttpCertificatePinning.clearCache();

    final secondCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/orders',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA BB'],
    );
    await Future<void>.delayed(Duration.zero);
    expect(nativeCalls, 2);

    completers[0].complete('CONNECTION_SECURE');
    await firstCheck;

    final thirdCheck = HttpCertificatePinning.check(
      serverURL: 'https://example.com/profile',
      sha: SHA.SHA256,
      allowedSHAFingerprints: const ['AA:BB'],
    );
    await Future<void>.delayed(Duration.zero);
    expect(nativeCalls, 2);

    completers[1].complete('CONNECTION_SECURE');

    expect(
      await Future.wait(<Future<String>>[secondCheck, thirdCheck]),
      const ['CONNECTION_SECURE', 'CONNECTION_SECURE'],
    );
  });
}
