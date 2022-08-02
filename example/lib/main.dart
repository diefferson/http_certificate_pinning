import 'package:flutter/material.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

void main() => runApp(const MyApp());

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  _MyAppState createState() => _MyAppState();
}

class _PiningSslData {
  String serverURL = '';
  Map<String, String> headerHttp = {};
  String allowedSHAFingerprint = '';
  int timeout = 0;
  SHA? sha;
}

class _MyAppState extends State<MyApp> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final _PiningSslData _data = _PiningSslData();
  final _messengerKey = GlobalKey<ScaffoldMessengerState>();

  @override
  initState() {
    super.initState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  check(
    String url,
    String fingerprint,
    SHA sha,
    Map<String, String> headerHttp,
    int timeout,
  ) async {
    List<String> allowedShA1FingerprintList = [];
    allowedShA1FingerprintList.add(fingerprint);

    try {
      // Platform messages may fail, so we use a try/catch PlatformException.
      String checkMsg = await HttpCertificatePinning.check(
          serverURL: url,
          headerHttp: headerHttp,
          sha: sha,
          allowedSHAFingerprints: allowedShA1FingerprintList,
          timeout: timeout);

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

      check(
        _data.serverURL,
        _data.allowedSHAFingerprint,
        _data.sha ?? SHA.SHA256,
        _data.headerHttp,
        _data.timeout,
      );
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
                    DropdownButton(
                      items: [
                        DropdownMenuItem(
                          child: Text(SHA.SHA1.toString()),
                          value: SHA.SHA1,
                        ),
                        DropdownMenuItem(
                          child: Text(SHA.SHA256.toString()),
                          value: SHA.SHA256,
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
                      keyboardType: TextInputType.text,
                      decoration: const InputDecoration(
                        hintText: 'OO OO OO OO OO OO OO OO OO OO',
                        labelText: 'Fingerprint',
                      ),
                      validator: (value) {
                        if (value?.isEmpty == null) {
                          return 'Please enter some fingerprint';
                        }
                        return null;
                      },
                      onSaved: (value) {
                        _data.allowedSHAFingerprint = value ?? '';
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
                      child: ElevatedButton(
                        onPressed: () => submit(),
                        child: const Text(
                          'Check',
                          style: TextStyle(
                            color: Colors.white,
                          ),
                        ),
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
