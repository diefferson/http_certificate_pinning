# Http Certificate Pinning

HTTPS certificate pinning for Flutter. Two pinning strategies are supported:

- **Certificate fingerprint pinning**: pin the SHA-1/SHA-256 fingerprint of the whole certificate.
- **Public key pinning (SPKI)**: pin the SHA-256 hash of a certificate's public key, at the leaf, intermediate or root position of the chain.

This project is based on [ssl_pinning_plugin](https://github.com/macif-dev/ssl_pinning_plugin) 

Any help is appreciated! Comment, suggestions, issues, PR's!

## Getting Started

In your flutter or dart project add the dependency:

```yml
dependencies:
  ...
  http_certificate_pinning: 3.0.1
```

## Get Certificate FingerPrint

To get SHA256 certificate fingerprint run in console:

```
openssl x509 -noout -fingerprint -sha256 -inform pem -in [certificate-file.crt]
```

The Result is like:

'59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D'


## Usage example

### Using Dio

```dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';
  
  // Add CertificatePinningInterceptor in dio Client
  Dio getClient(String baseUrl, List<String> allowedSHAFingerprints) {
      var dio = Dio(BaseOptions(baseUrl: baseUrl))
        ..interceptors.add(CertificatePinningInterceptor(allowedSHAFingerprints));
      return dio;
  }

  myRepositoryMethod() {
    dio.get("myurl.com");
  }
```

### Using Http

```dart
import 'package:http_certificate_pinning/secure_http_client.dart';
  
  // Uses SecureHttpClient to make requests
  SecureHttpClient getClient(List<String> allowedSHAFingerprints) {
      final secureClient = SecureHttpClient.build(certificateSHA256Fingerprints);
      return secureClient;
  }

  myRepositoryMethod() {
    secureClient.get("myurl.com");
  }
```

### Other Client

```dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';
  
Future myCustomImplementation(String url, Map<String,String> headers, List<String> allowedSHAFingerprints) async {
  try {
    final secure = await HttpCertificatePinning.check(
      serverURL: url,
      headerHttp: headers,
      sha: SHA.SHA256,
      allowedSHAFingerprints: allowedSHAFingerprints,
      timeout : 50
    );

    return secure.contains("CONNECTION_SECURE");
  } catch(e) {
    return false;
  }
}
```

## Public Key Pinning (SPKI)

As an alternative to certificate fingerprint pinning, the plugin can also pin
the SHA-256 hash of a certificate's public key (SubjectPublicKeyInfo). Both
strategies are equally supported. Public key pins could have the advantage of
surviving certificate renewals as long as the key pair is kept, and pinning the
intermediate CA key additionally survives leaf key rotations.

Public key pinning is a particularly good alternative when a certificate
rotation strategy is in place. Certificates can be renewed on schedule (or even
frequently, as with short-lived certificates) without invalidating the pins and
without shipping an app update. The pinned keys outlive the individual
certificates, whether that's a reused leaf key pair or a stable intermediate CA
key.

> **Caution**: pinning is a powerful control that cuts both ways. A lost or
> unexpectedly rotated key turns into a self-inflicted outage until an app
> update ships. Before adopting it, make sure you own or control the pinned
> keys' lifecycle, ship backup pins, and have a rotation and recovery plan. The
> [OWASP Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html)
> covers these considerations in detail.

To get a public key pin from a certificate file (works for a leaf, intermediate
or root CA certificate alike), run in console:

```sh
openssl x509 -in [certificate-file.crt] -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

The result is like:

'47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='

The pins can also be read directly from a live server. For the intermediate pin
(second certificate of the served chain):

```sh
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com -showcerts </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/{n++} n==2' | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Careful: the second certificate is the intermediate only when the served chain
contains at least three certificates. In a two-certificate chain (leaf + root)
this command returns the root pin instead, which `checkIntermediate` will never
match, since the intermediate check requires a chain of three or more.

For the root pin (last certificate of the served chain):

```sh
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com -showcerts </dev/null 2>/dev/null | awk '/BEGIN CERTIFICATE/{n++} {c[n]=c[n] $0 "\n"} END{printf "%s", c[n]}' | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

Alternatively, the repository ships a helper script that prints the pin of every
certificate in a server's chain, labeled by position (it labels positions
correctly even for two-certificate chains, so it avoids the pitfall above):

```sh
./get_public_key_pins.sh yourdomain.com
```

The connection is accepted when the leaf key matches one of the leaf pins, or,
failing that, when the intermediate CA key matches one of the intermediate pins:

```dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

Future myCustomImplementation(String url, Map<String,String> headers) async {
  try {
    final secure = await HttpCertificatePinning.checkPublicKeys(
      serverURL: url,
      headerHttp: headers,
      allowedLeafPublicKeyHashes: ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
      allowedIntermediatePublicKeyHashes: ['aW50ZXJtZWRpYXRlLWtleS1oYXNoLXBsYWNlaG9sZGVyPT0='],
      timeout: 50,
    );

    return secure.contains("CONNECTION_SECURE");
  } catch(e) {
    return false;
  }
}
```

To pin one specific chain position instead, use `checkLeaf`, `checkIntermediate`
or `checkRoot`:

```dart
Future<bool> checkLeafPin(String url) async {
  final secure = await HttpCertificatePinning.checkLeaf(
    serverURL: url,
    publicKeyHashes: ['47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='],
  );

  return secure.contains("CONNECTION_SECURE");
}
```

Note on `checkRoot`: on iOS the root comes from the evaluated trust chain (the
system trust store anchor), while on Android it is the last certificate the
server sent. Some servers omit the root, in which case the check fails.

On failure the platform reports distinct error codes, so a pinning failure can be
told apart from a plain connectivity problem: `CONNECTION_NOT_SECURE` (pin
mismatch or untrusted chain), `NO_INTERNET`, `TIMEOUT`, `NETWORK_ERROR` and
`UNKNOWN_ERROR`.
