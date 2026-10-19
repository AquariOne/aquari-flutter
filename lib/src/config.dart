import 'errors.dart';
import 'http.dart';

const Duration aquariDefaultRequestTimeout = Duration(seconds: 15);
const int aquariDefaultMaxRetries = 2;
const Duration aquariDefaultMaxRetryDelay = Duration(seconds: 5);

/// Configures an Aquari OAuth client and its HTTP behavior. Do not put a confidential client secret
/// in distributable client code.
final class AquariClientOptions {
  const AquariClientOptions({
    required this.issuer,
    required this.clientId,
    required this.redirectUri,
    required this.scopes,
    this.timeout = aquariDefaultRequestTimeout,
    this.maxRetries = aquariDefaultMaxRetries,
    this.maxRetryDelay = aquariDefaultMaxRetryDelay,
    this.httpExecutor,
  });

  final String issuer;
  final String clientId;
  final String redirectUri;
  final List<String> scopes;
  final Duration timeout;
  final int maxRetries;
  final Duration maxRetryDelay;
  final AquariHttpExecutor? httpExecutor;
}

/// Contains validated Flutter SDK configuration used by the Aquari transport and clients.
final class ResolvedAquariClientOptions {
  const ResolvedAquariClientOptions({
    required this.issuer,
    required this.clientId,
    required this.redirectUri,
    required this.scopes,
    required this.timeout,
    required this.maxRetries,
    required this.maxRetryDelay,
    required this.httpExecutor,
  });

  final Uri issuer;
  final String clientId;
  final Uri redirectUri;
  final List<String> scopes;
  final Duration timeout;
  final int maxRetries;
  final Duration maxRetryDelay;
  final AquariHttpExecutor httpExecutor;
}

/// Validates Flutter client options, applies defaults, and returns the normalized configuration
/// used by the SDK.
ResolvedAquariClientOptions resolveAquariOptions(AquariClientOptions options) {
  if (options.timeout <= Duration.zero) {
    throw AquariConfigurationException('timeout must be positive.');
  }
  if (options.maxRetries < 0) {
    throw AquariConfigurationException('maxRetries must be non-negative.');
  }
  if (options.maxRetryDelay < Duration.zero) {
    throw AquariConfigurationException('maxRetryDelay must be non-negative.');
  }

  return ResolvedAquariClientOptions(
    issuer: normalizeAquariBaseUrl(options.issuer),
    clientId: validateAquariTokenLikeValue(options.clientId, 'clientId'),
    redirectUri: validateAquariRedirectUri(options.redirectUri),
    scopes: validateAquariScopes(options.scopes),
    timeout: options.timeout,
    maxRetries: options.maxRetries,
    maxRetryDelay: options.maxRetryDelay,
    httpExecutor: options.httpExecutor ?? HttpClientAquariExecutor(),
  );
}

/// Validates and normalizes an Aquari base URL while preserving its origin and path identity.
Uri normalizeAquariBaseUrl(String value) {
  final Uri uri;
  try {
    uri = Uri.parse(value);
  } on FormatException catch (error) {
    throw AquariConfigurationException(
      'Aquari base URL must be a valid absolute URL.',
      error,
    );
  }

  if (!uri.hasScheme || (uri.scheme != 'https' && uri.scheme != 'http')) {
    throw AquariConfigurationException(
      'Aquari base URL must use HTTPS or HTTP.',
    );
  }
  if (uri.host.isEmpty) {
    throw AquariConfigurationException('Aquari base URL must include a host.');
  }
  if (uri.scheme == 'http' && !isAquariLocalDevelopmentHost(uri.host)) {
    throw AquariConfigurationException(
      'Insecure HTTP Aquari URLs are allowed only for local development.',
    );
  }
  if (uri.userInfo.isNotEmpty) {
    throw AquariConfigurationException(
      'Aquari base URL must not contain credentials.',
    );
  }
  if (uri.hasQuery || uri.hasFragment) {
    throw AquariConfigurationException(
      'Aquari base URL must not contain a query string or fragment.',
    );
  }

  final String path = uri.path.isEmpty
      ? '/'
      : uri.path.endsWith('/')
      ? uri.path
      : '${uri.path}/';

  return uri.replace(path: path, query: null, fragment: null);
}

/// Validates that a redirect URI is absolute, contains no credentials or fragment, and preserves
/// the registered value exactly.
Uri validateAquariRedirectUri(String value) {
  if (value.isEmpty || value != value.trim()) {
    throw AquariConfigurationException(
      'Aquari redirectUri must be a non-empty absolute URI.',
    );
  }

  final Uri uri;
  try {
    uri = Uri.parse(value);
  } on FormatException catch (error) {
    throw AquariConfigurationException(
      'Aquari redirectUri must be a valid absolute URI.',
      error,
    );
  }

  if (!uri.hasScheme) {
    throw AquariConfigurationException(
      'Aquari redirectUri must be a valid absolute URI.',
    );
  }
  if (uri.userInfo.isNotEmpty) {
    throw AquariConfigurationException(
      'Aquari redirectUri must not contain credentials.',
    );
  }
  if (uri.hasFragment) {
    throw AquariConfigurationException(
      'Aquari redirectUri must not contain a fragment.',
    );
  }
  return uri;
}

/// Validates explicit OAuth scopes, rejects duplicates or whitespace, and requires the openid
/// scope.
List<String> validateAquariScopes(List<String> values) {
  if (values.isEmpty) {
    throw AquariConfigurationException(
      'Aquari scopes must contain at least one explicit scope.',
    );
  }

  final Set<String> seen = <String>{};
  for (final String scope in values) {
    if (scope.isEmpty ||
        scope != scope.trim() ||
        RegExp(r'\s').hasMatch(scope)) {
      throw AquariConfigurationException(
        'Aquari scope values must be non-empty and must not contain whitespace.',
      );
    }
    if (!seen.add(scope)) {
      throw AquariConfigurationException(
        'Aquari scope values must not contain duplicates.',
      );
    }
  }

  if (!seen.contains(AquariScopes.openId)) {
    throw AquariConfigurationException(
      "Aquari authentication requires the explicit 'openid' scope.",
    );
  }

  return List<String>.unmodifiable(seen);
}

/// Validates a token-like configuration value and rejects empty values or surrounding whitespace.
String validateAquariTokenLikeValue(String value, String label) {
  if (value.isEmpty || value != value.trim() || RegExp(r'\s').hasMatch(value)) {
    throw AquariConfigurationException(
      'Aquari $label must be a non-empty value without whitespace.',
    );
  }
  return value;
}

/// Returns whether the host is a loopback host that Aquari permits for local insecure HTTP
/// development.
bool isAquariLocalDevelopmentHost(String host) {
  final String normalized = host.toLowerCase();
  return normalized == 'localhost' ||
      normalized == '127.0.0.1' ||
      normalized == '::1' ||
      normalized == '[::1]';
}

/// Provides standard OAuth scope values used by Aquari client applications.
abstract final class AquariScopes {
  static const String openId = 'openid';
  static const String profile = 'profile';
  static const String email = 'email';
  static const String offlineAccess = 'offline_access';
  static const String passportRead = 'passport.read';
}
