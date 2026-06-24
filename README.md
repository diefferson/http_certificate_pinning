# HTTP Certificate Pinning Plus

HTTPS certificate pinning for Flutter with SHA-1/SHA-256 fingerprints,
leaf or root certificate validation, Dio/http helpers, and in-memory check
caching.

This project is based on
[http_certificate_pinning](https://github.com/diefferson/http_certificate_pinning)
and [ssl_pinning_plugin](https://github.com/macif-dev/ssl_pinning_plugin).

Any help is appreciated! Comment, suggestions, issues, PR's!

## Getting Started

In your flutter or dart project add the dependency:

```yml
dependencies:
  ...
  http_certificate_pinning_plus: ^3.2.0
```

## Get Certificate FingerPrint

To get SHA256 certificate fingerprint run in console:

```
openssl x509 -noout -fingerprint -sha256 -inform pem -in [certificate-file.crt]
```

The Result is like:

'59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D:59:58:57:5A:5B:5C:5D'

By default the plugin validates the leaf certificate for the requested host.
To validate the root certificate fingerprint instead, pass
`certificatePinningTarget: CertificatePinningTarget.root`.
The same optional parameter is available on `CertificatePinningInterceptor`
and `SecureHttpClient.build`.

Successful certificate checks are cached in memory for 10 minutes by default.
The cache key is based on the host, port, SHA type, pinning target, and
fingerprints. Pass `cacheDuration: Duration.zero` to disable caching, or call
`HttpCertificatePinning.clearCache()` to clear the in-memory cache manually.


## Usage example

### Using Dio

```dart
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';
  
  // Add CertificatePinningInterceptor in dio Client
  Dio getClient(String baseUrl, List<String> allowedSHAFingerprints){
      var dio =  Dio(BaseOptions(baseUrl: baseUrl))
        ..interceptors.add(CertificatePinningInterceptor(
          allowedSHAFingerprints: allowedSHAFingerprints,
          cacheDuration: const Duration(minutes: 10),
        ));
      return dio;
  }

  myRepositoryMethod(){ 
    dio.get("myurl.com");
  }    
```

### Using Http

```dart
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';
  
  // Uses SecureHttpClient to make requests
  SecureHttpClient getClient(List<String> allowedSHAFingerprints){
      final secureClient = SecureHttpClient.build(
        certificateSHA256Fingerprints,
        cacheDuration: const Duration(minutes: 10),
      );
      return secureClient;
  }

  myRepositoryMethod(){ 
    secureClient.get("myurl.com");
  }    

```

### Other Client

```dart
import 'package:http_certificate_pinning_plus/http_certificate_pinning_plus.dart';
  
Future myCustomImplementation(String url, Map<String,String> headers, List<String> allowedSHAFingerprints) async {
  try{
    final secure = await HttpCertificatePinning.check(
      serverURL: url,
      headerHttp: headers,
      sha: SHA.SHA256,
      allowedSHAFingerprints:allowedSHAFingerprints,
      certificatePinningTarget: CertificatePinningTarget.root,
      cacheDuration: const Duration(minutes: 10),
      timeout : 50
    );

    if(secure.contains("CONNECTION_SECURE")){
      return true;
    }else{
      return false;
    }
  }catch(e){
    return false;
  }
}

```
