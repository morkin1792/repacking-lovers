import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();
  final token = args[0];
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 6);
  final result = <String, dynamic>{'token': token, 'url': args[1], 'status': 'failed'};
  try {
    final request = await client.getUrl(Uri.parse(args[1]));
    final response = await request.close().timeout(const Duration(seconds: 8));
    result['http_status'] = response.statusCode;
    result['body'] = await utf8.decoder.bind(response).join();
    result['status'] = 'response';
  } catch (error) {
    result['error'] = error.toString();
    result['error_type'] = error.runtimeType.toString();
  } finally {
    client.close(force: true);
  }
  result['unrelated'] = 6 * 7;
  await const MethodChannel('repack.fixture.native').invokeMethod('result', jsonEncode(result));
}
