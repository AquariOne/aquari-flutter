import 'package:aquari_one/aquari_one.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  test(
    'Flutter client persists transaction before launching browser',
    () async {
      final _MemoryTransactionStore transactions = _MemoryTransactionStore();
      final _MemoryTokenStore tokens = _MemoryTokenStore();
      final _Launcher launcher = _Launcher();

      final MockClient httpClient = MockClient((http.Request request) async {
        return http.Response(
          '''
        {
          "issuer":"https://issuer.example/",
          "authorization_endpoint":"https://issuer.example/connect/authorize",
          "token_endpoint":"https://issuer.example/connect/token",
          "userinfo_endpoint":"https://issuer.example/connect/userinfo",
          "jwks_uri":"https://issuer.example/.well-known/jwks",
          "grant_types_supported":["authorization_code","refresh_token"],
          "response_types_supported":["code"],
          "code_challenge_methods_supported":["S256"],
          "id_token_signing_alg_values_supported":["RS256"],
          "token_endpoint_auth_methods_supported":["none"]
        }
        ''',
          200,
          headers: <String, String>{'content-type': 'application/json'},
        );
      });

      final AquariClient core = AquariClient(
        AquariClientOptions(
          issuer: 'https://issuer.example/',
          clientId: 'client',
          redirectUri: 'one.aquari.flutter:/oauth2redirect',
          scopes: const <String>[AquariScopes.openId],
          httpExecutor: HttpClientAquariExecutor(httpClient),
        ),
      );

      final AquariFlutterClient client = AquariFlutterClient(
        client: core,
        tokenStore: tokens,
        transactionStore: transactions,
        authorizationLauncher: launcher,
      );

      await client.beginAuthorization();

      expect(transactions.value, isNotNull);
      expect(launcher.lastUrl, isNotNull);
      expect(launcher.lastUrl!.scheme, 'https');
      expect(
        launcher.lastUrl!.queryParameters['code_challenge_method'],
        'S256',
      );
    },
  );
}

final class _MemoryTokenStore implements AquariTokenStore {
  AquariTokenSet? value;

  @override
  Future<void> clearTokens() async {
    value = null;
  }

  @override
  Future<AquariTokenSet?> readTokens() async => value;

  @override
  Future<void> writeTokens(AquariTokenSet tokens) async {
    value = tokens;
  }
}

final class _MemoryTransactionStore
    implements AquariAuthorizationTransactionStore {
  AquariAuthorizationTransaction? value;

  @override
  Future<void> clearTransaction() async {
    value = null;
  }

  @override
  Future<AquariAuthorizationTransaction?> readTransaction() async => value;

  @override
  Future<void> writeTransaction(
    AquariAuthorizationTransaction transaction,
  ) async {
    value = transaction;
  }
}

final class _Launcher implements AquariAuthorizationLauncher {
  Uri? lastUrl;

  @override
  Future<void> launch(Uri url) async {
    lastUrl = url;
  }
}
