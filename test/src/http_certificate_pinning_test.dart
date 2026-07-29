import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('HttpCertificatePinning', () {
    const MethodChannel channel = MethodChannel('http_certificate_pinning');
    final List<MethodCall> log = <MethodCall>[];

    setUp(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (MethodCall methodCall) async {
        log.add(methodCall);
        if (methodCall.method.startsWith('check')) {
          return 'SUCCESS';
        }
        return null;
      });
      log.clear();
    });

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
    });

    test('check method invokes with correct arguments', () async {
      const String testUrl = 'https://example.com';
      const SHA testSha = SHA.SHA256;
      const List<String> testFingerprints = ['AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'];
      final Map<String, String> testHeaders = {'Authorization': 'Bearer token'};
      const int testTimeout = 10000;

      await HttpCertificatePinning.check(
        serverURL: testUrl,
        sha: testSha,
        allowedSHAFingerprints: testFingerprints,
        headerHttp: testHeaders,
        timeout: testTimeout,
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'check');
      expect(log.first.arguments, <String, dynamic>{
        'url': testUrl,
        'headers': testHeaders,
        'type': 'SHA256',
        'fingerprints': ['AABBCCDDEEFF', '112233445566'],
        'timeout': testTimeout,
      });
    });

    test('check method handles null headers and timeout gracefully', () async {
      const String testUrl = 'https://example.com';
      const List<String> testFingerprints = ['AA:BB:CC:DD:EE:FF'];

      await HttpCertificatePinning.check(
        serverURL: testUrl,
        sha: SHA.SHA1,
        allowedSHAFingerprints: testFingerprints,
        headerHttp: null,
        timeout: null,
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'check');
      expect(log.first.arguments, <String, dynamic>{
        'url': testUrl,
        'headers': {},
        'type': 'SHA1',
        'fingerprints': ['AABBCCDDEEFF'],
        'timeout': null,
      });
    });

    test('check method returns expected string on success', () async {
      const String testUrl = 'https://example.com';
      const List<String> testFingerprints = ['AA:BB:CC:DD:EE:FF'];

      final String result = await HttpCertificatePinning.check(
        serverURL: testUrl,
        sha: SHA.SHA256,
        allowedSHAFingerprints: testFingerprints,
      );

      expect(result, 'SUCCESS');
    });

    test('check method handles empty fingerprints list', () async {
      const String testUrl = 'https://example.com';
      const SHA testSha = SHA.SHA256;
      const List<String> testFingerprints = [];

      await HttpCertificatePinning.check(
        serverURL: testUrl,
        sha: testSha,
        allowedSHAFingerprints: testFingerprints,
      );

      expect(log, hasLength(1));
      expect(log.first.arguments['fingerprints'], []);
    });

    test('checkPublicKeys method invokes with correct arguments', () async {
      const String testUrl = 'https://example.com';
      final Map<String, String> testHeaders = {'Authorization': 'Bearer token'};
      const int testTimeout = 10;

      await HttpCertificatePinning.checkPublicKeys(
        serverURL: testUrl,
        allowedLeafPublicKeyHashes: [
          'sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
          ' bGVhZjItcHVibGljLWtleS1oYXNoLXBsYWNlaG9sZGVyPz8= ',
        ],
        allowedIntermediatePublicKeyHashes: [
          'sha256/aW50ZXJtZWRpYXRlLWtleS1oYXNoLXBsYWNlaG9sZGVyPT0=',
        ],
        headerHttp: testHeaders,
        timeout: testTimeout,
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'checkPublicKeys');
      expect(log.first.arguments, <String, dynamic>{
        'url': testUrl,
        'headers': testHeaders,
        'leafPublicKeyHashes': [
          '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
          'bGVhZjItcHVibGljLWtleS1oYXNoLXBsYWNlaG9sZGVyPz8=',
        ],
        'intermediatePublicKeyHashes': [
          'aW50ZXJtZWRpYXRlLWtleS1oYXNoLXBsYWNlaG9sZGVyPT0=',
        ],
        'timeout': testTimeout,
        'allowCache': true,
      });
    });

    test('checkPublicKeys method handles omitted optional arguments', () async {
      await HttpCertificatePinning.checkPublicKeys(
        serverURL: 'https://example.com',
        allowedLeafPublicKeyHashes: ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
      );

      expect(log, hasLength(1));
      expect(log.first.arguments, <String, dynamic>{
        'url': 'https://example.com',
        'headers': {},
        'leafPublicKeyHashes': ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
        'intermediatePublicKeyHashes': [],
        'timeout': null,
        'allowCache': true,
      });
    });

    test('checkPublicKeys method returns expected string on success', () async {
      final String result = await HttpCertificatePinning.checkPublicKeys(
        serverURL: 'https://example.com',
        allowedLeafPublicKeyHashes: ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
      );

      expect(result, 'SUCCESS');
    });

    test('checkLeaf method invokes with correct arguments', () async {
      await HttpCertificatePinning.checkLeaf(
        serverURL: 'https://example.com',
        publicKeyHashes: ['sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
        headerHttp: {'Authorization': 'Bearer token'},
        timeout: 10,
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'checkLeaf');
      expect(log.first.arguments, <String, dynamic>{
        'url': 'https://example.com',
        'headers': {'Authorization': 'Bearer token'},
        'publicKeyHashes': ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
        'timeout': 10,
        'allowCache': true,
      });
    });

    test('checkIntermediate method invokes with correct arguments', () async {
      await HttpCertificatePinning.checkIntermediate(
        serverURL: 'https://example.com',
        publicKeyHashes: ['aW50ZXJtZWRpYXRlLWtleS1oYXNoLXBsYWNlaG9sZGVyPT0='],
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'checkIntermediate');
      expect(log.first.arguments, <String, dynamic>{
        'url': 'https://example.com',
        'headers': {},
        'publicKeyHashes': ['aW50ZXJtZWRpYXRlLWtleS1oYXNoLXBsYWNlaG9sZGVyPT0='],
        'timeout': null,
        'allowCache': true,
      });
    });

    test('checkLeaf forwards allowCache false', () async {
      await HttpCertificatePinning.checkLeaf(
        serverURL: 'https://example.com',
        publicKeyHashes: ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
        allowCache: false,
      );

      expect(log, hasLength(1));
      expect(log.first.arguments['allowCache'], false);
    });

    test('checkRoot method invokes with correct arguments', () async {
      await HttpCertificatePinning.checkRoot(
        serverURL: 'https://example.com',
        publicKeyHashes: ['cm9vdC1jYS1rZXktaGFzaC1wbGFjZWhvbGRlci1iYXNlNjQ='],
      );

      expect(log, hasLength(1));
      expect(log.first.method, 'checkRoot');
      expect(log.first.arguments, <String, dynamic>{
        'url': 'https://example.com',
        'headers': {},
        'publicKeyHashes': ['cm9vdC1jYS1rZXktaGFzaC1wbGFjZWhvbGRlci1iYXNlNjQ='],
        'timeout': null,
        'allowCache': true,
      });
    });
  });
}