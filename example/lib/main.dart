import 'package:flutter/material.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

void main() => runApp(const MyApp());

/// Which plugin method the form exercises.
enum PinCheckType { certificate, publicKeys, leaf, intermediate, root }

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  _MyAppState createState() => _MyAppState();
}

class _PiningSslData {
  String serverURL = '';
  Map<String, String> headerHttp = {};
  String allowedFingerprintOrHashes = '';
  String intermediatePublicKeyHashes = '';
  int timeout = 0;
  SHA? sha;
}

class _MyAppState extends State<MyApp> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final _PiningSslData _data = _PiningSslData();
  final _messengerKey = GlobalKey<ScaffoldMessengerState>();
  PinCheckType _checkType = PinCheckType.certificate;
  bool _allowCache = true;

  final _urlController = TextEditingController(text: 'https://google.com');
  final _certFingerprintController = TextEditingController(
      text:
          "51 E9 01 5F FE FB 79 70 D8 DF 74 BB 46 94 63 72 B1 E3 2B 31 6A 46 F0 C5 36 E7 C1 D4 DD C5 B2 70");
  final _publicKeyPinsController = TextEditingController();
  final _intermediatePinsController = TextEditingController();

  @override
  initState() {
    super.initState();
  }

  @override
  void dispose() {
    _urlController.dispose();
    _certFingerprintController.dispose();
    _publicKeyPinsController.dispose();
    _intermediatePinsController.dispose();
    super.dispose();
  }

  List<String> _splitPins(String value) => value
      .split(',')
      .map((pin) => pin.trim())
      .where((pin) => pin.isNotEmpty)
      .toList();

  // Platform messages are asynchronous, so we initialize in an async method.
  check(_PiningSslData data) async {
    final pins = _splitPins(data.allowedFingerprintOrHashes);

    try {
      // Platform messages may fail, so we use a try/catch PlatformException.
      String checkMsg;
      switch (_checkType) {
        case PinCheckType.certificate:
          checkMsg = await HttpCertificatePinning.check(
            serverURL: data.serverURL,
            headerHttp: data.headerHttp,
            sha: data.sha ?? SHA.SHA256,
            allowedSHAFingerprints: pins,
            timeout: data.timeout,
          );
        case PinCheckType.publicKeys:
          checkMsg = await HttpCertificatePinning.checkPublicKeys(
            serverURL: data.serverURL,
            headerHttp: data.headerHttp,
            allowedLeafPublicKeyHashes: pins,
            allowedIntermediatePublicKeyHashes:
                _splitPins(data.intermediatePublicKeyHashes),
            timeout: data.timeout,
            allowCache: _allowCache,
          );
        case PinCheckType.leaf:
          checkMsg = await HttpCertificatePinning.checkLeaf(
            serverURL: data.serverURL,
            headerHttp: data.headerHttp,
            publicKeyHashes: pins,
            timeout: data.timeout,
            allowCache: _allowCache,
          );
        case PinCheckType.intermediate:
          checkMsg = await HttpCertificatePinning.checkIntermediate(
            serverURL: data.serverURL,
            headerHttp: data.headerHttp,
            publicKeyHashes: pins,
            timeout: data.timeout,
            allowCache: _allowCache,
          );
        case PinCheckType.root:
          checkMsg = await HttpCertificatePinning.checkRoot(
            serverURL: data.serverURL,
            headerHttp: data.headerHttp,
            publicKeyHashes: pins,
            timeout: data.timeout,
            allowCache: _allowCache,
          );
      }

      // If the widget was removed from the tree while the asynchronous platform
      // message was in flight, we want to discard the reply rather than calling
      // setState to update our non-existent appearance.
      if (!mounted) return;

      _messengerKey.currentState?.showSnackBar(
        SnackBar(
          content: Text(checkMsg),
          duration: const Duration(seconds: 1),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      _messengerKey.currentState?.showSnackBar(
        SnackBar(
          content: Text(e.toString()),
          duration: const Duration(seconds: 1),
          backgroundColor: Colors.red,
        ),
      );
    }
  }

  void submit() {
    // First validate form.
    if (_formKey.currentState?.validate() == true) {
      _formKey.currentState?.save(); // Save our form now.

      check(_data);
    }
  }

  bool get _isPublicKeyCheck => _checkType != PinCheckType.certificate;

  String get _pinsLabel {
    switch (_checkType) {
      case PinCheckType.certificate:
        return 'Fingerprint';
      case PinCheckType.publicKeys:
        return 'Leaf public key hashes (base64, comma separated)';
      case PinCheckType.leaf:
        return 'Leaf public key hashes (base64, comma separated)';
      case PinCheckType.intermediate:
        return 'Intermediate public key hashes (base64, comma separated)';
      case PinCheckType.root:
        return 'Root public key hashes (base64, comma separated)';
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      scaffoldMessengerKey: _messengerKey,
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Ssl Pinning Plugin'),
        ),
        body: Builder(
          builder: (BuildContext context) {
            return Container(
              padding: const EdgeInsets.all(20.0),
              child: Form(
                key: _formKey,
                child: ListView(
                  children: <Widget>[
                    TextFormField(
                      keyboardType: TextInputType.url,
                      controller: _urlController,
                      decoration: const InputDecoration(
                        hintText: 'https://yourdomain.com',
                        labelText: 'URL',
                      ),
                      validator: (value) {
                        if (value?.isEmpty == true) {
                          return 'Please enter some url';
                        }
                        return null;
                      },
                      onSaved: (value) {
                        _data.serverURL = value ?? '';
                      },
                    ),
                    DropdownButton<PinCheckType>(
                      items: const [
                        DropdownMenuItem(
                          value: PinCheckType.certificate,
                          child: Text('Certificate fingerprint (check)'),
                        ),
                        DropdownMenuItem(
                          value: PinCheckType.publicKeys,
                          child: Text('Public keys (checkPublicKeys)'),
                        ),
                        DropdownMenuItem(
                          value: PinCheckType.leaf,
                          child: Text('Leaf public key (checkLeaf)'),
                        ),
                        DropdownMenuItem(
                          value: PinCheckType.intermediate,
                          child:
                              Text('Intermediate public key (checkIntermediate)'),
                        ),
                        DropdownMenuItem(
                          value: PinCheckType.root,
                          child: Text('Root public key (checkRoot)'),
                        ),
                      ],
                      value: _checkType,
                      isExpanded: true,
                      onChanged: (PinCheckType? val) {
                        setState(() {
                          _checkType = val ?? PinCheckType.certificate;
                        });
                      },
                    ),
                    if (!_isPublicKeyCheck)
                      DropdownButton(
                        items: [
                          DropdownMenuItem(
                            value: SHA.SHA1,
                            child: Text(SHA.SHA1.toString()),
                          ),
                          DropdownMenuItem(
                            value: SHA.SHA256,
                            child: Text(SHA.SHA256.toString()),
                          )
                        ],
                        value: _data.sha,
                        isExpanded: true,
                        onChanged: (SHA? val) {
                          setState(() {
                            _data.sha = val;
                          });
                        },
                      ),
                    TextFormField(
                      controller: _isPublicKeyCheck
                          ? _publicKeyPinsController
                          : _certFingerprintController,
                      keyboardType: TextInputType.text,
                      decoration: InputDecoration(
                        hintText: _isPublicKeyCheck
                            ? '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
                            : 'OO OO OO OO OO OO OO OO OO OO',
                        labelText: _pinsLabel,
                      ),
                      validator: (value) {
                        if (value?.isEmpty == true) {
                          return 'Please enter some fingerprint or hash';
                        }
                        return null;
                      },
                      onSaved: (value) {
                        _data.allowedFingerprintOrHashes = value ?? '';
                      },
                    ),
                    if (_checkType == PinCheckType.publicKeys)
                      TextFormField(
                        controller: _intermediatePinsController,
                        keyboardType: TextInputType.text,
                        decoration: const InputDecoration(
                          hintText:
                              '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
                          labelText:
                              'Intermediate public key hashes (optional, comma separated)',
                        ),
                        onSaved: (value) {
                          _data.intermediatePublicKeyHashes = value ?? '';
                        },
                      ),
                    if (_isPublicKeyCheck)
                      SwitchListTile(
                        contentPadding: EdgeInsets.zero,
                        title: const Text('Allow cache'),
                        subtitle: const Text(
                            'Disable while testing pin changes so the probe always hits the network'),
                        value: _allowCache,
                        onChanged: (value) {
                          setState(() {
                            _allowCache = value;
                          });
                        },
                      ),
                    TextFormField(
                      keyboardType: TextInputType.number,
                      initialValue: '60',
                      decoration: const InputDecoration(
                        hintText: '60',
                        labelText: 'Timeout',
                      ),
                      validator: (value) {
                        if (value?.isEmpty == true) {
                          return 'Please enter some timeout';
                        }
                        return null;
                      },
                      onSaved: (value) {
                        _data.timeout = int.tryParse(value ?? '') ?? 0;
                      },
                    ),
                    Container(
                      margin: const EdgeInsets.only(top: 20.0),
                      child: FilledButton(
                        onPressed: () => submit(),
                        style: FilledButton.styleFrom(
                          minimumSize: const Size.fromHeight(48),
                        ),
                        child: const Text('Check'),
                      ),
                    )
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }
}
