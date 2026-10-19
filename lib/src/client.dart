import 'auth.dart';
import 'config.dart';
import 'http.dart';
import 'passport.dart';
import 'transport.dart';
import 'trust.dart';

/// Provides the main Aquari runtime entry point for authentication, Passport, and trust operations.
final class AquariClient {
  /// Creates the main Aquari client from validated OAuth and HTTP configuration.
  AquariClient(AquariClientOptions options)
    : _resolved = resolveAquariOptions(options),
      _executor = options.httpExecutor {
    _transport = AquariHttpTransport(options: _resolved);
    auth = AquariAuthClient(_resolved, _transport);
    passport = AquariPassportClient(_transport);
    trust = AquariTrustClient(_transport);
  }

  late final AquariHttpTransport _transport;
  final ResolvedAquariClientOptions _resolved;
  final AquariHttpExecutor? _executor;

  late final AquariAuthClient auth;
  late final AquariPassportClient passport;
  late final AquariTrustClient trust;

  /// Gets the normalized Aquari issuer URL.
  Uri get issuer => _resolved.issuer;

  /// Gets the configured OAuth client identifier.
  String get clientId => _resolved.clientId;

  /// Gets the registered OAuth redirect URI.
  Uri get redirectUri => _resolved.redirectUri;

  /// Gets the OAuth scopes requested by this client.
  List<String> get scopes => _resolved.scopes;

  /// Releases HTTP resources owned by this SDK object.
  void close() {
    final AquariHttpExecutor executor = _resolved.httpExecutor;
    if (_executor == null && executor is HttpClientAquariExecutor) {
      executor.close();
    }
  }
}
