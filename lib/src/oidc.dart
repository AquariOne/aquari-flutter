import 'config.dart';
import 'errors.dart';
import 'transport.dart';

/// Contains validated OpenID Connect discovery metadata for the configured Aquari issuer.
final class AquariOidcDiscovery {
  const AquariOidcDiscovery({
    required this.issuer,
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    required this.userInfoEndpoint,
    required this.jwksUri,
    required this.grantTypesSupported,
    required this.responseTypesSupported,
    required this.codeChallengeMethodsSupported,
    required this.idTokenSigningAlgorithmsSupported,
    required this.tokenEndpointAuthMethodsSupported,
    required this.authorizationResponseIssuerParameterSupported,
  });

  final Uri issuer;
  final Uri authorizationEndpoint;
  final Uri tokenEndpoint;
  final Uri userInfoEndpoint;
  final Uri jwksUri;
  final List<String> grantTypesSupported;
  final List<String> responseTypesSupported;
  final List<String> codeChallengeMethodsSupported;
  final List<String> idTokenSigningAlgorithmsSupported;
  final List<String> tokenEndpointAuthMethodsSupported;
  final bool authorizationResponseIssuerParameterSupported;
}

/// Loads and validates Aquari OpenID Connect discovery metadata for the configured issuer.
Future<AquariOidcDiscovery> discoverAquariOidc(
  AquariHttpTransport transport,
  Uri configuredIssuer,
) async {
  final Object? raw = await transport.requestJson(
    '/.well-known/openid-configuration',
  );
  final Map<String, Object?> root = _requireMap(
    raw,
    'Aquari OIDC discovery returned an invalid document.',
  );

  final String issuerValue = _requiredString(root, 'issuer');
  final Uri issuer = Uri.parse(issuerValue);
  if (issuer != configuredIssuer) {
    throw AquariConfigurationException(
      'Aquari OIDC discovery issuer does not exactly match the configured issuer.',
    );
  }

  final List<String> grants = _requiredStringList(
    root,
    'grant_types_supported',
  );
  final List<String> responses = _requiredStringList(
    root,
    'response_types_supported',
  );
  final List<String> pkce = _requiredStringList(
    root,
    'code_challenge_methods_supported',
  );
  final List<String> algorithms = _requiredStringList(
    root,
    'id_token_signing_alg_values_supported',
  );

  _requireAdvertised(
    grants,
    'authorization_code',
    'Aquari OIDC discovery does not advertise the authorization-code grant.',
  );
  _requireAdvertised(
    grants,
    'refresh_token',
    'Aquari OIDC discovery does not advertise the refresh-token grant.',
  );
  _requireAdvertised(
    responses,
    'code',
    'Aquari OIDC discovery does not advertise the code response type.',
  );
  _requireAdvertised(
    pkce,
    'S256',
    'Aquari OIDC discovery does not advertise S256 PKCE.',
  );
  _requireAdvertised(
    algorithms,
    'RS256',
    'Aquari OIDC discovery does not advertise RS256 ID-token signing.',
  );

  return AquariOidcDiscovery(
    issuer: issuer,
    authorizationEndpoint: _requiredEndpoint(root, 'authorization_endpoint'),
    tokenEndpoint: _requiredEndpoint(root, 'token_endpoint'),
    userInfoEndpoint: _requiredEndpoint(root, 'userinfo_endpoint'),
    jwksUri: _requiredEndpoint(root, 'jwks_uri'),
    grantTypesSupported: grants,
    responseTypesSupported: responses,
    codeChallengeMethodsSupported: pkce,
    idTokenSigningAlgorithmsSupported: algorithms,
    tokenEndpointAuthMethodsSupported: _optionalStringList(
      root,
      'token_endpoint_auth_methods_supported',
    ),
    authorizationResponseIssuerParameterSupported:
        root['authorization_response_iss_parameter_supported'] == true,
  );
}

Map<String, Object?> _requireMap(Object? value, String message) {
  if (value is Map<String, Object?>) {
    return value;
  }
  if (value is Map<Object?, Object?>) {
    return value.cast<String, Object?>();
  }
  throw AquariConfigurationException(message);
}

String _requiredString(Map<String, Object?> root, String name) {
  final Object? value = root[name];
  if (value is! String || value.isEmpty || value != value.trim()) {
    throw AquariConfigurationException(
      "Aquari OIDC discovery field '$name' must be a non-empty normalized string.",
    );
  }
  return value;
}

List<String> _requiredStringList(Map<String, Object?> root, String name) {
  final Object? value = root[name];
  if (value is! List<Object?> || value.isEmpty) {
    throw AquariConfigurationException(
      "Aquari OIDC discovery field '$name' must be a non-empty string array.",
    );
  }

  final List<String> result = <String>[];
  for (final Object? item in value) {
    if (item is! String || item.isEmpty || item != item.trim()) {
      throw AquariConfigurationException(
        "Aquari OIDC discovery field '$name' must be a non-empty string array.",
      );
    }
    result.add(item);
  }
  return List<String>.unmodifiable(result);
}

List<String> _optionalStringList(Map<String, Object?> root, String name) {
  final Object? value = root[name];
  if (value is! List<Object?>) {
    return const <String>[];
  }
  return List<String>.unmodifiable(
    value.whereType<String>().where(
      (String item) => item.isNotEmpty && item == item.trim(),
    ),
  );
}

Uri _requiredEndpoint(Map<String, Object?> root, String name) {
  final String value = _requiredString(root, name);
  final Uri uri = Uri.parse(value);

  if (!uri.hasScheme || uri.host.isEmpty) {
    throw AquariConfigurationException(
      "Aquari OIDC discovery field '$name' must be an absolute URL.",
    );
  }
  if (uri.scheme != 'https' &&
      !(uri.scheme == 'http' && isAquariLocalDevelopmentHost(uri.host))) {
    throw AquariConfigurationException(
      "Aquari OIDC discovery field '$name' must use HTTPS outside local development.",
    );
  }
  if (uri.userInfo.isNotEmpty || uri.hasFragment) {
    throw AquariConfigurationException(
      "Aquari OIDC discovery field '$name' contains unsupported URL components.",
    );
  }
  return uri;
}

void _requireAdvertised(List<String> values, String required, String message) {
  if (!values.contains(required)) {
    throw AquariConfigurationException(message);
  }
}
