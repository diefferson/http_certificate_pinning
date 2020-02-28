#import "HttpCertificatePinningPlugin.h"
#if __has_include(<http_certificate_pinning/http_certificate_pinning-Swift.h>)
#import <http_certificate_pinning/http_certificate_pinning-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "http_certificate_pinning-Swift.h"
#endif

@implementation HttpCertificatePinningPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftHttpCertificatePinningPlugin registerWithRegistrar:registrar];
}
@end
