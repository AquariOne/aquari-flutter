import 'dart:convert';
import 'package:aquari_one/aquari_one.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  for (final String value in <String>[
    '-1',
    '+1',
    '0x10',
    '1.5',
    '',
    'not-a-date',
  ]) {
    test('invalid Retry-After $value does not become a zero delay', () async {
      final AquariClient client = _client(value);
      try {
        await client.passport.get('access-token');
        fail('Expected rate limit');
      } on AquariRateLimitException catch (error) {
        expect(error.retryAfter, isNull);
      }
    });
  }
  test('HTTP-date delay is preserved on structured errors', () async {
    final DateTime date = DateTime.now().toUtc().add(
      const Duration(minutes: 1),
    );
    const List<String> weekdays = <String>[
      'Mon',
      'Tue',
      'Wed',
      'Thu',
      'Fri',
      'Sat',
      'Sun',
    ];
    const List<String> months = <String>[
      'Jan',
      'Feb',
      'Mar',
      'Apr',
      'May',
      'Jun',
      'Jul',
      'Aug',
      'Sep',
      'Oct',
      'Nov',
      'Dec',
    ];
    String pad(int value) => value.toString().padLeft(2, '0');
    final String header =
        '${weekdays[date.weekday - 1]}, ${pad(date.day)} ${months[date.month - 1]} ${date.year} ${pad(date.hour)}:${pad(date.minute)}:${pad(date.second)} GMT';
    try {
      await _client(header).passport.get('access-token');
      fail('Expected rate limit');
    } on AquariRateLimitException catch (error) {
      expect(error.retryAfter, isNotNull);
      expect(error.retryAfter!.inSeconds, greaterThan(30));
      expect(error.retryAfter!.inSeconds, lessThanOrEqualTo(60));
    }
  });
  test(
    'oversized delays are positive and exceed the local retry budget',
    () async {
      try {
        await _client('9223372036854775807').passport.get('access-token');
        fail('Expected rate limit');
      } on AquariRateLimitException catch (error) {
        expect(error.retryAfter!.inSeconds, 9007199254);
      }
    },
  );
}

AquariClient _client(String retryAfter) => AquariClient(
  AquariClientOptions(
    issuer: 'https://example.invalid/',
    clientId: 'public',
    redirectUri: 'com.example.app:/callback',
    scopes: const <String>['openid'],
    maxRetries: 0,
    httpExecutor: HttpClientAquariExecutor(
      MockClient(
        (http.Request request) async => http.Response(
          jsonEncode(<String, Object?>{
            'error': <String, Object?>{
              'code': 'RateLimitExceeded',
              'message': 'Wait',
            },
          }),
          429,
          headers: <String, String>{
            'content-type': 'application/json',
            'retry-after': retryAfter,
          },
        ),
      ),
    ),
  ),
);
