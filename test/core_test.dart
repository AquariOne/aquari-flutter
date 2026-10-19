import 'dart:convert';

import 'package:aquari_one/aquari_one.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:jose/jose.dart';

const Map<String, Object?> _privateJwk = {
  "kty": "RSA",
  "kid": "aquari-test-rs256",
  "use": "sig",
  "alg": "RS256",
  "n":
      "k7KUO71PF7SUNa5hNZkMglQ0jTeh0tlq0mazJ3tC8jMvYdHYh-Tnc7m-UXjikpjzfNDiwC6ZZlEs2WiaUWfqpcS44Dkq-YbdGr-AmCQkWtEwehjhWT3xk-wdDNYvZYEz68vSFF2c1r4facdbZ8qi610PBTFIQANCwFbDN1HcTHOfyDNuLDI9kxSmVrYIZs2DF_gaxkROT5x8bJU4nbwE0a4g_sRNtnC8tQB2e5JkfwvwjCMVi1K-qAVU7HZZXbYC8faDHJ4c4VWtDffwjGOdrxPabHIPVQxRshJjsLzNOwNTSSXBDMvjA9Cu64fWnQ48ldXO9ZSpRUB8p78ZjXdahQ",
  "e": "AQAB",
  "d":
      "C_BP9iI_zfE9V7eASRZVggVveAjKrmH_tgEyMxtOFojXqCcPwzBYGy0k-q30VphBelHiOlmp8bDXGL3RV4o4V-z2ar2EQUZLAhn_uYyWWbb2HbB8KrwMloHr-Tko_KH8ge9oTFgi0OLuZB0GwPWKxM6xY6CPsAjzcNuyjPqzfYRtrzm78bWZ-zrFBKIoSY3Ip3zLAIiZiGUpNhiPuY3cB3DdmkfTNK2RZaJUJQKwJccfA4dYQTJ1-I0n062wwMXuvzRagQGXJl8nAyozGb8jZT7s57o3MpQ8O-b3azEc9D2x03FmpqvRV3cIZlPz8XkHB2HaXibikLk4lrKH5SimgQ",
  "p":
      "yGTs7b4wc0bI4FYPtxP7KAltQS12WJdaHgacI7kzFnNXvFEY1x6GE8tCxkHR-oGWAdAsZrEZ-GOqKNsn6zq2ZyGEEIr-eATIjRr2dQ1j_RVcT6gisoRvBBeT74acDYMiBnhYbYhtj8KEzTwUYe4DIbwd2Cd7GGkMmKkGXwvxK8U",
  "q":
      "vK5T2vHPc2sdcTi41HE9GEh8eVF_HWsyOSCphhBDwBVGkJk1MHMzaLQ14e9vtERKqvnNR3vhr27aAZL17UfcecNMQs6CFf3O5nnSR9DAmudb9aEl4SNG7orNi7cW6GP7MuguI-O9HQuW77TMSaFL4lCgkBc6IE6GagDXlFH-n8E",
  "dp":
      "jDJft-xpRRzuiFRtZi4qdlYyA3lk5JHu0Dbbofp9jWVgqjUqZcXLE6oOq1l9J_7lDZuwlJ-uhaJkd3Trtpw65GgEVvaHFTxzepS0fCvEGlmJXYlJzQ7uBDTioJ7SKnnlohUr-GWMERmLg3JW6DR2KHHNh14Htoo3783A0Vovfek",
  "dq":
      "CVSxru0wbivI6_V7Jn5nIBFNno5KNAE-HZcg6xFY2GH0-GerOrcnvrDSzVaS9p499xCdd0CIG63muBc1dEOOgrMGzXL6-e1wUvOJU6XeMIrqgE402lptQpS4r4Uha-Kt5ImY5ot3qb0N_NK7G5UPdKS6HAYaCMj5Wrqp7prTdcE",
  "qi":
      "kKlFc01sQC-54Ox4GL_MzGssja0MUIihYwn7ZYnVoUvmKNdCAABhc76TwCS55J5mLulUPKCpBMUYB06DpEc84YldS7XZWT0ij0LAwBpiDDgJe1s2Uxa4Y201Jb7HRQ-Xb7Zpgsdr5EcO-odGBBOHAo7j2DrZ7m0Sa2U5vzEUH4k",
};
const Map<String, Object?> _publicJwk = {
  "kty": "RSA",
  "kid": "aquari-test-rs256",
  "use": "sig",
  "alg": "RS256",
  "n":
      "k7KUO71PF7SUNa5hNZkMglQ0jTeh0tlq0mazJ3tC8jMvYdHYh-Tnc7m-UXjikpjzfNDiwC6ZZlEs2WiaUWfqpcS44Dkq-YbdGr-AmCQkWtEwehjhWT3xk-wdDNYvZYEz68vSFF2c1r4facdbZ8qi610PBTFIQANCwFbDN1HcTHOfyDNuLDI9kxSmVrYIZs2DF_gaxkROT5x8bJU4nbwE0a4g_sRNtnC8tQB2e5JkfwvwjCMVi1K-qAVU7HZZXbYC8faDHJ4c4VWtDffwjGOdrxPabHIPVQxRshJjsLzNOwNTSSXBDMvjA9Cu64fWnQ48ldXO9ZSpRUB8p78ZjXdahQ",
  "e": "AQAB",
};

void main() {
  test('configuration rejects insecure remote issuer', () {
    expect(
      () => AquariClient(
        const AquariClientOptions(
          issuer: 'http://example.com',
          clientId: 'client',
          redirectUri: 'one.aquari.test:/callback',
          scopes: <String>[AquariScopes.openId],
        ),
      ),
      throwsA(isA<AquariConfigurationException>()),
    );
  });

  test('authorization transaction has S256 PKCE and round-trips', () async {
    final MockClient httpClient = MockClient((http.Request request) async {
      expect(request.url.path, '/.well-known/openid-configuration');
      return http.Response(
        jsonEncode(_discovery()),
        200,
        headers: <String, String>{'content-type': 'application/json'},
      );
    });

    final AquariClient client = _client(httpClient);
    final AquariBeginAuthorizationResult begin = await client.auth.begin();

    expect(
      begin.transaction.codeVerifier,
      matches(RegExp(r'^[A-Za-z0-9_-]{64}$')),
    );
    expect(begin.transaction.state, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
    expect(begin.transaction.nonce, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
    expect(begin.url.queryParameters['code_challenge_method'], 'S256');
    expect(begin.url.queryParameters['code_challenge'], isNotEmpty);

    final String encoded = serializeAquariAuthorizationTransaction(
      begin.transaction,
    );
    final AquariAuthorizationTransaction decoded =
        deserializeAquariAuthorizationTransaction(encoded);
    expect(decoded.state, begin.transaction.state);
    expect(decoded.codeVerifier, begin.transaction.codeVerifier);
  });

  test(
    'real signed RS256 id token completes authorization and UserInfo',
    () async {
      late AquariAuthorizationTransaction transaction;
      late String idToken;

      final MockClient httpClient = MockClient((http.Request request) async {
        if (request.url.path == '/.well-known/openid-configuration') {
          return _jsonResponse(_discovery());
        }
        if (request.url.path == '/connect/token') {
          return _jsonResponse(<String, Object?>{
            'token_type': 'Bearer',
            'access_token': 'access-secret',
            'id_token': idToken,
            'refresh_token': 'refresh-secret',
            'expires_in': 3600,
            'scope': 'openid profile email offline_access passport.read',
          });
        }
        if (request.url.path == '/.well-known/jwks') {
          return _jsonResponse(<String, Object?>{
            'keys': <Object?>[_publicJwk],
          });
        }
        if (request.url.path == '/connect/userinfo') {
          return _jsonResponse(<String, Object?>{
            'sub': 'subject-1',
            'preferred_username': '@test.aquari.one',
            'name': 'Test User',
            'email': 'test@example.com',
            'email_verified': true,
          });
        }
        fail('Unexpected request: ${request.method} ${request.url}');
      });

      final AquariClient client = _client(httpClient);
      final AquariBeginAuthorizationResult begin = await client.auth.begin();
      transaction = begin.transaction;
      idToken = _signedIdToken(transaction);

      final AquariAuthorizationResult result = await client.auth.complete(
        Uri.parse(
          'one.aquari.test:/callback?code=abc&state=${transaction.state}'
          '&iss=${Uri.encodeQueryComponent(transaction.issuer)}',
        ),
        transaction,
      );

      expect(result.tokens.subject, 'subject-1');
      expect(result.identity.subject, 'subject-1');

      final AquariIdentity userInfo = await client.auth.userInfo(result.tokens);
      expect(userInfo.subject, 'subject-1');
      expect(userInfo.emailVerified, isTrue);
    },
  );

  test('state mismatch fails before token exchange', () async {
    final MockClient httpClient = MockClient((http.Request request) async {
      return _jsonResponse(_discovery());
    });
    final AquariClient client = _client(httpClient);
    final AquariBeginAuthorizationResult begin = await client.auth.begin();

    await expectLater(
      client.auth.complete(
        Uri.parse(
          'one.aquari.test:/callback?code=abc&state=wrong'
          '&iss=${Uri.encodeQueryComponent(begin.transaction.issuer)}',
        ),
        begin.transaction,
      ),
      throwsA(
        isA<AquariOAuthException>().having(
          (AquariOAuthException error) => error.oauthCode,
          'oauthCode',
          'state_mismatch',
        ),
      ),
    );
  });

  test('Passport, signals, public Passport, and trust parse', () async {
    final MockClient httpClient = MockClient((http.Request request) async {
      if (request.url.path == '/api/v1/passport') {
        return _jsonResponse(<String, Object?>{
          'passport': <String, Object?>{
            'id': 'p1',
            'passportNumber': 'AQ-00000001',
            'subjectId': 'subject-1',
            'profile': <String, Object?>{
              'displayName': 'Test',
              'handle': '@test.aquari.one',
              'avatarUrl': null,
              'publicUrl': 'https://aquari.one/test',
              'verified': true,
              'visibility': 'public',
            },
            'signals': <String, Object?>{'total': 0},
          },
        });
      }
      if (request.url.path == '/api/v1/passport/signals') {
        return _jsonResponse(<String, Object?>{
          'items': <Object?>[],
          'page': <String, Object?>{'nextCursor': null, 'hasMore': false},
        });
      }
      if (request.url.path == '/api/v1/passport/trust/evaluation') {
        return _jsonResponse(<String, Object?>{
          'evaluationId': 'eval-1',
          'subjectId': 'subject-1',
          'consumerApplicationId': 'app-1',
          'evaluatedAt': '2026-09-27T00:00:00Z',
          'outcomes': <Object?>[],
        });
      }
      if (request.url.path.startsWith('/api/v1/public/passports/')) {
        return _jsonResponse(<String, Object?>{
          'displayName': 'Test',
          'handle': '@test.aquari.one',
          'avatarUrl': null,
          'publicUrl': 'https://aquari.one/test',
          'verified': true,
          'signals': <Object?>[],
        });
      }
      fail('Unexpected request: ${request.method} ${request.url}');
    });

    final AquariClient client = _client(httpClient);
    final AquariPassport passport = await client.passport.get('access');
    final AquariPassportSignalPage signals = await client.passport.signals.list(
      'access',
    );
    final AquariTrustEvaluation trust = await client.trust.evaluate('access');
    final AquariPublicPassport publicPassport = await client.passport.getPublic(
      passport.profile.handle,
    );

    expect(passport.subjectId, 'subject-1');
    expect(signals.items, isEmpty);
    expect(trust.subjectId, 'subject-1');
    expect(publicPassport.handle, '@test.aquari.one');
  });

  test('timeout is mapped to AquariTimeoutException', () async {
    final MockClient httpClient = MockClient((http.Request request) async {
      await Future<void>.delayed(const Duration(milliseconds: 50));
      return _jsonResponse(_discovery());
    });

    final AquariClient client = AquariClient(
      AquariClientOptions(
        issuer: 'https://issuer.example/',
        clientId: 'client',
        redirectUri: 'one.aquari.test:/callback',
        scopes: const <String>[AquariScopes.openId],
        timeout: const Duration(milliseconds: 5),
        maxRetries: 0,
        httpExecutor: HttpClientAquariExecutor(httpClient),
      ),
    );

    await expectLater(
      client.auth.discover(),
      throwsA(isA<AquariTimeoutException>()),
    );
  });
}

AquariClient _client(http.Client httpClient) {
  return AquariClient(
    AquariClientOptions(
      issuer: 'https://issuer.example/',
      clientId: 'client',
      redirectUri: 'one.aquari.test:/callback',
      scopes: const <String>[
        AquariScopes.openId,
        AquariScopes.profile,
        AquariScopes.email,
        AquariScopes.offlineAccess,
        AquariScopes.passportRead,
      ],
      httpExecutor: HttpClientAquariExecutor(httpClient),
    ),
  );
}

Map<String, Object?> _discovery() => <String, Object?>{
  'issuer': 'https://issuer.example/',
  'authorization_endpoint': 'https://issuer.example/connect/authorize',
  'token_endpoint': 'https://issuer.example/connect/token',
  'userinfo_endpoint': 'https://issuer.example/connect/userinfo',
  'jwks_uri': 'https://issuer.example/.well-known/jwks',
  'grant_types_supported': <String>['authorization_code', 'refresh_token'],
  'response_types_supported': <String>['code'],
  'code_challenge_methods_supported': <String>['S256'],
  'id_token_signing_alg_values_supported': <String>['RS256'],
  'token_endpoint_auth_methods_supported': <String>['none'],
  'authorization_response_iss_parameter_supported': true,
};

http.Response _jsonResponse(Object body) {
  return http.Response(
    jsonEncode(body),
    200,
    headers: <String, String>{'content-type': 'application/json'},
  );
}

String _signedIdToken(AquariAuthorizationTransaction transaction) {
  final int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  final JsonWebSignatureBuilder builder = JsonWebSignatureBuilder()
    ..jsonContent = <String, Object?>{
      'iss': transaction.issuer,
      'sub': 'subject-1',
      'aud': transaction.clientId,
      'exp': now + 3600,
      'iat': now,
      'nonce': transaction.nonce,
      'preferred_username': '@test.aquari.one',
      'email': 'test@example.com',
      'email_verified': true,
    }
    ..setProtectedHeader('typ', 'JWT')
    ..setProtectedHeader('kid', 'aquari-test-rs256')
    ..addRecipient(JsonWebKey.fromJson(_privateJwk), algorithm: 'RS256');

  return builder.build().toCompactSerialization();
}
