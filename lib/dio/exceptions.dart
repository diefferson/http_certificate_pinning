class CertificateNotVerifiedException implements Exception {
  const CertificateNotVerifiedException();

  @override
  String toString() {
    return 'CertificateNotVerifiedException: Connection is not secure';
  }
}

class CertificateCouldNotBeVerifiedException implements Exception {
  final Exception? innerException;

  const CertificateCouldNotBeVerifiedException([this.innerException]);

  @override
  String toString() {
    return 'CertificateCouldNotBeVerifiedException: Unable to verify certificates';
  }
}
