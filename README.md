# Http Certificate Pinning

Https Certificate pinning for Flutter

This project ins based on [ssl_pinning_plugin](https://github.com/macif-dev/ssl_pinning_plugin) 

Any help is appreciated! Comment, suggestions, issues, PR's!

## Getting Started

In your flutter or dart project add the dependency:

```yml
dependencies:
  ...
  http_certificate_pinning: 2.1.3
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
  Dio getClient(String baseUrl, List<String> allowedSHAFingerprints){
      var dio =  Dio(BaseOptions(baseUrl: baseUrl))
        ..interceptors.add(CertificatePinningInterceptor(allowedSHAFingerprints));
      return dio;
  }

  myRepositoryMethod(){ 
    dio.get("myurl.com");
  }    
```

### Using Http

```dart
import 'package:http_certificate_pinning/secure_http_client.dart';
  
  // Uses SecureHttpClient to make requests
  SecureHttpClient getClient(List<String> allowedSHAFingerprints){
      final secureClient = SecureHttpClient.build(certificateSHA256Fingerprints);
      return secureClient;
  }

  myRepositoryMethod(){ 
    secureClient.get("myurl.com");
  }    

```

### Other Client

```dart
import 'package:http_certificate_pinning/http_certificate_pinning.dart';
  
Future myCustomImplementation(String url, Map<String,String> headers, List<String> allowedSHAFingerprints) async {
  try{
    final secure = await HttpCertificatePinning.check(
      serverURL: url,
      headerHttp: headers,
      sha: SHA.SHA256,
      allowedSHAFingerprints:allowedSHAFingerprints,
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
