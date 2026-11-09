import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

int pinChecks = 0;

@pragma('vm:never-inline')
@pragma('vm:entry-point')
bool verifyPeerCertificatePin(X509Certificate certificate, {required bool checkingPin}) {
  pinChecks++;
  final fingerprint = certificate.sha1.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return checkingPin && fingerprint == '0000000000000000000000000000000000000000';
}

@pragma('vm:never-inline')
@pragma('vm:entry-point')
bool verifyAppFeature(String value, {required bool checkingPin}) {
  return checkingPin && value == '0000000000000000000000000000000000000000';
}

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  final mode = args[2];
  final context = SecurityContext(withTrustedRoots: false);
  if (mode == 'post') {
    final ca = await rootBundle.load('assets/origin-ca.pem');
    context.setTrustedCertificatesBytes(ca.buffer.asUint8List());
  }
  int callbacks = 0;
  final client = HttpClient(context: context)
    ..connectionTimeout = const Duration(seconds: 7)
    ..findProxy = ((uri) => 'DIRECT')
    ..badCertificateCallback = ((cert, host, port) { callbacks++; return false; });
  final result = <String, dynamic>{'token': args[0], 'mode': mode, 'status': 'failed'};
  try {
    final request = await client.getUrl(Uri.parse(args[1]));
    final response = await request.close().timeout(const Duration(seconds: 10));
    if (mode == 'post' && !verifyPeerCertificatePin(response.certificate!, checkingPin: true)) {
      throw const HandshakeException('fixture post-handshake certificate pin mismatch');
    }
    result['http_status'] = response.statusCode;
    result['body'] = await utf8.decoder.bind(response).join();
    result['status'] = 'response';
  } catch (error) {
    result['error'] = error.toString();
    result['error_type'] = error.runtimeType.toString();
  } finally { client.close(force: true); }
  result['callback_calls'] = callbacks;
  result['pin_checks'] = pinChecks;
  result['unrelated'] = 6 * 7;
  result['feature_negative_control'] = verifyAppFeature('reject', checkingPin: true);
  await const MethodChannel('repack.fixture.native').invokeMethod('result', jsonEncode(result));
}
