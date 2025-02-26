#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint http_certificate_pinning.podspec' to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'http_certificate_pinning'
  s.version          = '1.0.3'
  s.summary          = 'Https Certificate pinning for Flutter'
  s.description      = <<-DESC
Https Certificate pinning for Flutter
                       DESC
  s.homepage         = 'https://github.com/diefferson/https_certificate_pinning'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Diefferson Santos' => 'diefferson.sts@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.dependency 'CryptoSwift'
  s.dependency 'Alamofire', '~> 5.9.0'
  s.platform = :ios, '8.0'

  # Flutter.framework does not contain a i386 slice. Only x86_64 simulators are supported.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'VALID_ARCHS[sdk=iphonesimulator*]' => 'x86_64' }
  s.swift_version = '5.0'
end
