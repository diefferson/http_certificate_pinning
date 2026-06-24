#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint http_certificate_pinning_plus.podspec' to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'http_certificate_pinning_plus'
  s.version          = '3.1.0'
  s.summary          = 'HTTPS certificate pinning for Flutter'
  s.description      = <<-DESC
HTTPS certificate pinning for Flutter with leaf or root certificate fingerprint validation and in-memory check caching.
                       DESC
  s.homepage         = 'https://txtool.site'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'txtool' => 'https://txtool.site' }
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
