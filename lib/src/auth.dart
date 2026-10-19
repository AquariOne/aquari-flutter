import 'dart:convert';

import 'package:jose/jose.dart';

import 'config.dart';
import 'errors.dart';
import 'oidc.dart';
import 'pkce.dart';
import 'transport.dart';

const Duration _authorizationTransactionMaxAge = Duration(minutes: 15);
const Duration _authorizationTransactionClockSkew = Duration(minutes: 1);
const Duration _idTokenClockTolerance = Duration(minutes: 1);

const String _canonicalHandleClaim =
    'https://aquari.one/claims/canonical_handle';
const String _verifiedHandleClaim = 'https://aquari.one/claims/verified_handle';

final RegExp _statePattern = RegExp(r'^[A-Za-z0-9_-]{43}$');
final RegExp _verifierPattern = RegExp(r'^[A-Za-z0-9_-]{64}$');

/// Lists the supported prompt values for an Aquari authorization request.
enum AquariAuthorizationPrompt {
  consent('consent'),
  login('login'),
  none('none'),
  selectAccount('select_account');

  const AquariAuthorizationPrompt(this.wireValue);
  final String wireValue;
}

/// Stores the authorization transaction that binds an OAuth callback to the request that started
/// it. Preserve this value until authorization completes. Treat the PKCE verifier, state, and nonce
/// as sensitive.
final class AquariAuthorizationTransaction {
  const AquariAuthorizationTransaction({
    required this.version,
    required this.issuer,
    required this.clientId,
    required this.redirectUri,
    required this.scopes,
    required this.codeVerifier,
    required this.state,
    required this.nonce,
    required this.createdAt,
  });

  final int version;
  final String issuer;
  final String clientId;
  final String redirectUri;
  final List<String> scopes;
  final String codeVerifier;
  final String state;
  final String nonce;
  final int createdAt;

  /// Serializes this Aquari value to the JSON shape used for protected local persistence.
  Map<String, Object?> toJson() => <String, Object?>{
    'version': version,
    'issuer': issuer,
    'clientId': clientId,
    'redirectUri': redirectUri,
    'scopes': scopes,
    'codeVerifier': codeVerifier,
    'state': state,
    'nonce': nonce,
    'createdAt': createdAt,
  };

  /// Restores this Aquari value from its persisted JSON representation and rejects malformed state.
  static AquariAuthorizationTransaction fromJson(Map<String, Object?> json) {
    try {
      final Object? scopesValue = json['scopes'];
      if (scopesValue is! List<Object?>) {
        throw const FormatException('scopes');
      }
      return AquariAuthorizationTransaction(
        version: json['version'] as int,
        issuer: json['issuer'] as String,
        clientId: json['clientId'] as String,
        redirectUri: json['redirectUri'] as String,
        scopes: List<String>.unmodifiable(scopesValue.cast<String>()),
        codeVerifier: json['codeVerifier'] as String,
        state: json['state'] as String,
        nonce: json['nonce'] as String,
        createdAt: json['createdAt'] as int,
      );
    } on Object catch (error) {
      throw AquariOAuthException(
        'invalid_transaction',
        'Aquari authorization transaction is invalid.',
        cause: error,
      );
    }
  }

  /// Returns a diagnostic representation that does not expose protected token or authorization secret
  /// values.
  @override
  String toString() =>
      'AquariAuthorizationTransaction(version=$version, issuer=$issuer, '
      'clientId=$clientId, redirectUri=$redirectUri, scopes=$scopes, '
      'secrets=[REDACTED], createdAt=$createdAt)';
}

/// Contains the authorization URL and transaction created when an Aquari authorization request
/// starts.
final class AquariBeginAuthorizationResult {
  const AquariBeginAuthorizationResult({
    required this.url,
    required this.transaction,
  });

  final Uri url;
  final AquariAuthorizationTransaction transaction;
}

/// Represents the subject-bound identity returned by Aquari UserInfo.
final class AquariIdentity {
  const AquariIdentity({
    required this.subject,
    this.handle,
    this.canonicalHandle,
    this.verifiedHandle,
    this.name,
    this.pictureUrl,
    this.email,
    this.emailVerified,
  });

  final String subject;
  final String? handle;
  final String? canonicalHandle;
  final String? verifiedHandle;
  final String? name;
  final String? pictureUrl;
  final String? email;
  final bool? emailVerified;

  /// Returns a diagnostic representation that does not expose protected token or authorization secret
  /// values.
  @override
  String toString() =>
      'AquariIdentity(subject=$subject, handle=$handle, '
      'canonicalHandle=$canonicalHandle, verifiedHandle=$verifiedHandle, '
      'name=$name, pictureUrl=$pictureUrl, email=$email, '
      'emailVerified=$emailVerified)';
}

/// Contains the OAuth tokens, subject, scopes, and expiration metadata for an Aquari session. Do
/// not log or expose token values.
final class AquariTokenSet {
  const AquariTokenSet({
    required this.subject,
    required this.tokenType,
    required this.accessToken,
    required this.idToken,
    required this.refreshToken,
    required this.expiresIn,
    required this.expiresAt,
    required this.scopes,
  });

  final String subject;
  final String tokenType;
  final String accessToken;
  final String idToken;
  final String? refreshToken;
  final int expiresIn;
  final int expiresAt;
  final List<String> scopes;

  /// Serializes this Aquari value to the JSON shape used for protected local persistence.
  Map<String, Object?> toJson() => <String, Object?>{
    'subject': subject,
    'tokenType': tokenType,
    'accessToken': accessToken,
    'idToken': idToken,
    'refreshToken': refreshToken,
    'expiresIn': expiresIn,
    'expiresAt': expiresAt,
    'scopes': scopes,
  };

  /// Restores this Aquari value from its persisted JSON representation and rejects malformed state.
  static AquariTokenSet fromJson(Map<String, Object?> json) {
    try {
      final Object? scopesValue = json['scopes'];
      if (scopesValue is! List<Object?>) {
        throw const FormatException('scopes');
      }
      return AquariTokenSet(
        subject: json['subject'] as String,
        tokenType: json['tokenType'] as String,
        accessToken: json['accessToken'] as String,
        idToken: json['idToken'] as String,
        refreshToken: json['refreshToken'] as String?,
        expiresIn: json['expiresIn'] as int,
        expiresAt: json['expiresAt'] as int,
        scopes: List<String>.unmodifiable(scopesValue.cast<String>()),
      );
    } on Object catch (error) {
      throw AquariOAuthException(
        'invalid_token_set',
        'Aquari token set is invalid.',
        cause: error,
      );
    }
  }

  /// Returns a diagnostic representation that does not expose protected token or authorization secret
  /// values.
  @override
  String toString() =>
      'AquariTokenSet(subject=$subject, tokenType=$tokenType, '
      'tokens=[REDACTED], expiresIn=$expiresIn, expiresAt=$expiresAt, '
      'scopes=$scopes)';
}

/// Contains the validated token set and subject-bound Aquari identity produced by authorization.
final class AquariAuthorizationResult {
  const AquariAuthorizationResult({
    required this.tokens,
    required this.identity,
  });

  final AquariTokenSet tokens;
  final AquariIdentity identity;
}

/// Serializes the Aquari state to a protected-storage representation.
String serializeAquariAuthorizationTransaction(
  AquariAuthorizationTransaction transaction,
) => jsonEncode(transaction.toJson());

/// Restores Aquari state from protected storage and rejects malformed data.
AquariAuthorizationTransaction deserializeAquariAuthorizationTransaction(
  String value,
) {
  try {
    final Object? decoded = jsonDecode(value);
    if (decoded is! Map<Object?, Object?>) {
      throw const FormatException('transaction');
    }
    return AquariAuthorizationTransaction.fromJson(
      decoded.cast<String, Object?>(),
    );
  } on AquariOAuthException {
    rethrow;
  } on Object catch (error) {
    throw AquariOAuthException(
      'invalid_transaction',
      'Aquari authorization transaction is invalid.',
      cause: error,
    );
  }
}

/// Serializes the Aquari state to a protected-storage representation.
String serializeAquariTokenSet(AquariTokenSet tokens) =>
    jsonEncode(tokens.toJson());

/// Restores Aquari state from protected storage and rejects malformed data.
AquariTokenSet deserializeAquariTokenSet(String value) {
  try {
    final Object? decoded = jsonDecode(value);
    if (decoded is! Map<Object?, Object?>) {
      throw const FormatException('tokens');
    }
    return AquariTokenSet.fromJson(decoded.cast<String, Object?>());
  } on AquariOAuthException {
    rethrow;
  } on Object catch (error) {
    throw AquariOAuthException(
      'invalid_token_set',
      'Aquari token set is invalid.',
      cause: error,
    );
  }
}

/// Provides OIDC discovery, Authorization Code with S256 PKCE, refresh-token rotation, and UserInfo
/// operations.
final class AquariAuthClient {
  /// Creates the authentication client from normalized OAuth configuration and an Aquari HTTP
  /// transport. Most applications obtain this client from AquariClient authentication accessors.
  AquariAuthClient(this._options, this._transport);

  final ResolvedAquariClientOptions _options;
  final AquariHttpTransport _transport;
  AquariOidcDiscovery? _cachedDiscovery;

  /// Loads and validates Aquari OpenID Connect discovery metadata. The client reuses cached metadata
  /// unless the caller requests a refresh.
  Future<AquariOidcDiscovery> discover({bool forceRefresh = false}) async {
    if (!forceRefresh && _cachedDiscovery != null) {
      return _cachedDiscovery!;
    }
    final AquariOidcDiscovery discovery = await discoverAquariOidc(
      _transport,
      _options.issuer,
    );
    _cachedDiscovery = discovery;
    return discovery;
  }

  /// Starts an Authorization Code request. The SDK creates S256 PKCE, state, nonce, and a
  /// serializable authorization transaction, then returns the system-browser URL. Preserve the
  /// transaction until authorization completes.
  Future<AquariBeginAuthorizationResult> begin({
    AquariAuthorizationPrompt? prompt,
  }) async {
    final AquariOidcDiscovery discovery = await discover();
    final AquariPkcePair pkce = createAquariPkcePair();
    final AquariAuthorizationTransaction transaction =
        AquariAuthorizationTransaction(
          version: 1,
          issuer: _options.issuer.toString(),
          clientId: _options.clientId,
          redirectUri: _options.redirectUri.toString(),
          scopes: _options.scopes,
          codeVerifier: pkce.codeVerifier,
          state: createAquariSecureRandomValue(),
          nonce: createAquariSecureRandomValue(),
          createdAt: DateTime.now().millisecondsSinceEpoch,
        );

    final Map<String, String> parameters = <String, String>{
      'client_id': transaction.clientId,
      'redirect_uri': transaction.redirectUri,
      'response_type': 'code',
      'scope': transaction.scopes.join(' '),
      'state': transaction.state,
      'nonce': transaction.nonce,
      'code_challenge': pkce.codeChallenge,
      'code_challenge_method': 'S256',
      if (prompt != null) 'prompt': prompt.wireValue,
    };

    return AquariBeginAuthorizationResult(
      url: discovery.authorizationEndpoint.replace(
        queryParameters: <String, String>{
          ...discovery.authorizationEndpoint.queryParameters,
          ...parameters,
        },
      ),
      transaction: transaction,
    );
  }

  /// Validates the authorization callback against the original transaction, exchanges the
  /// authorization code, validates the ID token and nonce, and returns subject-bound session state.
  Future<AquariAuthorizationResult> complete(
    Uri callback,
    AquariAuthorizationTransaction transaction,
  ) async {
    _validateTransaction(transaction);
    _validateCallbackBase(callback, Uri.parse(transaction.redirectUri));

    final Map<String, List<String>> parameters = callback.queryParametersAll;
    final String state = _singleCallbackValue(
      parameters,
      'state',
      required: true,
    )!;
    if (state != transaction.state) {
      throw AquariOAuthException(
        'state_mismatch',
        'Aquari authorization callback state does not match the initiating transaction.',
      );
    }

    final String? callbackIssuer = _singleCallbackValue(
      parameters,
      'iss',
      required: false,
    );
    if (callbackIssuer != null && callbackIssuer != transaction.issuer) {
      throw AquariOAuthException(
        'issuer_mismatch',
        'Aquari authorization callback issuer does not match the initiating transaction.',
      );
    }

    final String? oauthError = _singleCallbackValue(
      parameters,
      'error',
      required: false,
    );
    final String? code = _singleCallbackValue(
      parameters,
      'code',
      required: false,
    );

    if (oauthError != null && code != null) {
      throw AquariOAuthException(
        'invalid_callback',
        'Aquari authorization callback cannot contain both a code and an OAuth error.',
      );
    }
    if (oauthError != null) {
      final String? description = _singleCallbackValue(
        parameters,
        'error_description',
        required: false,
      );
      final String? errorUri = _singleCallbackValue(
        parameters,
        'error_uri',
        required: false,
      );
      throw AquariOAuthException(
        oauthError,
        description ?? "Aquari returned OAuth error '$oauthError'.",
        errorDescription: description,
        errorUri: errorUri,
      );
    }
    if (code == null) {
      throw AquariOAuthException(
        'invalid_callback',
        'Aquari authorization callback does not contain an authorization code.',
      );
    }

    final AquariOidcDiscovery discovery = await discover();
    if (discovery.authorizationResponseIssuerParameterSupported &&
        callbackIssuer == null) {
      throw AquariOAuthException(
        'missing_issuer',
        'Aquari authorization callback is missing the advertised issuer parameter.',
      );
    }

    final String body = _encodeForm(<String, String>{
      'grant_type': 'authorization_code',
      'client_id': transaction.clientId,
      'redirect_uri': transaction.redirectUri,
      'code': code,
      'code_verifier': transaction.codeVerifier,
    });

    final Object? raw = await _transport.requestAbsoluteJson(
      discovery.tokenEndpoint,
      method: 'POST',
      headers: const <String, String>{'accept': 'application/json'},
      body: body,
      contentType: 'application/x-www-form-urlencoded',
      retryMode: AquariRetryMode.never,
    );

    final Map<String, Object?> response = _requireJsonMap(
      raw,
      'invalid_token_response',
      'Aquari returned an invalid token response.',
    );

    final _UnboundTokenSet unbound = _parseAuthorizationTokenResponse(
      response,
      transaction.scopes,
    );
    final AquariIdentity identity = await _validateIdToken(
      unbound.idToken,
      discovery,
      transaction.clientId,
      transaction.nonce,
    );

    return AquariAuthorizationResult(
      tokens: AquariTokenSet(
        subject: identity.subject,
        tokenType: unbound.tokenType,
        accessToken: unbound.accessToken,
        idToken: unbound.idToken,
        refreshToken: unbound.refreshToken,
        expiresIn: unbound.expiresIn,
        expiresAt: unbound.expiresAt,
        scopes: unbound.scopes,
      ),
      identity: identity,
    );
  }

  /// Exchanges the current refresh token for a replacement token set. Treat the returned token set as
  /// the new session state because Aquari rotates refresh tokens.
  Future<AquariTokenSet> refresh(AquariTokenSet tokens) async {
    _validateTokenSet(tokens);
    final String refreshToken =
        tokens.refreshToken ??
        (throw AquariOAuthException(
          'missing_refresh_token',
          'Aquari cannot refresh this token set because it does not contain a refresh token.',
        ));

    final AquariOidcDiscovery discovery = await discover();
    final Object? raw = await _transport.requestAbsoluteJson(
      discovery.tokenEndpoint,
      method: 'POST',
      headers: const <String, String>{'accept': 'application/json'},
      body: _encodeForm(<String, String>{
        'grant_type': 'refresh_token',
        'client_id': _options.clientId,
        'refresh_token': refreshToken,
      }),
      contentType: 'application/x-www-form-urlencoded',
      retryMode: AquariRetryMode.never,
    );

    final Map<String, Object?> response = _requireJsonMap(
      raw,
      'invalid_token_response',
      'Aquari returned an invalid refresh response.',
    );
    final AquariTokenSet refreshed = _parseRefreshTokenResponse(
      response,
      tokens,
    );

    if (refreshed.idToken != tokens.idToken) {
      final AquariIdentity identity = await _validateIdToken(
        refreshed.idToken,
        discovery,
        _options.clientId,
        null,
      );
      if (identity.subject != tokens.subject) {
        throw _invalidIdToken(
          'Aquari refreshed ID token subject does not match the existing token set.',
        );
      }
    }

    return refreshed;
  }

  /// Reads Aquari UserInfo with the current access token and returns the subject-bound identity.
  Future<AquariIdentity> userInfo(AquariTokenSet tokens) async {
    _validateTokenSet(tokens);
    final AquariOidcDiscovery discovery = await discover();
    final Object? raw = await _transport.requestAbsoluteJson(
      discovery.userInfoEndpoint,
      headers: <String, String>{
        'accept': 'application/json',
        'authorization': 'Bearer ${tokens.accessToken}',
      },
      retryMode: AquariRetryMode.never,
    );

    final Map<String, Object?> response = _requireJsonMap(
      raw,
      'invalid_userinfo_response',
      'Aquari returned an invalid UserInfo response.',
    );
    final AquariIdentity identity = _parseIdentity(
      response,
      label: 'UserInfo',
      errorCode: 'invalid_userinfo_response',
    );
    if (identity.subject != tokens.subject) {
      throw AquariOAuthException(
        'userinfo_subject_mismatch',
        'Aquari UserInfo subject does not match the authenticated token set.',
      );
    }
    return identity;
  }

  void _validateTransaction(AquariAuthorizationTransaction transaction) {
    final int now = DateTime.now().millisecondsSinceEpoch;
    final bool structurallyValid =
        transaction.version == 1 &&
        transaction.issuer == _options.issuer.toString() &&
        transaction.clientId == _options.clientId &&
        transaction.redirectUri == _options.redirectUri.toString() &&
        _listEquals(transaction.scopes, _options.scopes) &&
        _verifierPattern.hasMatch(transaction.codeVerifier) &&
        _statePattern.hasMatch(transaction.state) &&
        _statePattern.hasMatch(transaction.nonce);

    if (!structurallyValid) {
      throw AquariOAuthException(
        'invalid_transaction',
        'Aquari authorization transaction is invalid or does not match this client configuration.',
      );
    }

    if (transaction.createdAt >
            now + _authorizationTransactionClockSkew.inMilliseconds ||
        now - transaction.createdAt >
            _authorizationTransactionMaxAge.inMilliseconds) {
      throw AquariOAuthException(
        'expired_transaction',
        'Aquari authorization transaction is expired or has an invalid timestamp.',
      );
    }
  }

  Future<AquariIdentity> _validateIdToken(
    String idToken,
    AquariOidcDiscovery discovery,
    String clientId,
    String? expectedNonce,
  ) async {
    final List<String> parts = idToken.split('.');
    if (parts.length != 3) {
      throw _invalidIdToken();
    }

    final Map<String, Object?> header = _decodeJwtPart(parts[0]);
    if (header['alg'] != 'RS256') {
      throw _invalidIdToken();
    }

    final String? kid = header['kid'] is String
        ? header['kid']! as String
        : null;
    final Object? jwksRaw = await _transport.requestAbsoluteJson(
      discovery.jwksUri,
      retryMode: AquariRetryMode.never,
    );
    final Map<String, Object?> jwks = _requireJsonMap(
      jwksRaw,
      'invalid_id_token',
      'Aquari returned an invalid JWKS document.',
    );

    final Object? keysRaw = jwks['keys'];
    if (keysRaw is! List<Object?>) {
      throw _invalidIdToken('Aquari returned an invalid JWKS document.');
    }

    final List<Map<String, Object?>> candidates = keysRaw
        .whereType<Map<Object?, Object?>>()
        .map((Map<Object?, Object?> item) => item.cast<String, Object?>())
        .where((Map<String, Object?> key) {
          if (key['kty'] != 'RSA') {
            return false;
          }
          if (kid != null && key['kid'] != kid) {
            return false;
          }
          if (key['alg'] != null && key['alg'] != 'RS256') {
            return false;
          }
          if (key['use'] != null && key['use'] != 'sig') {
            return false;
          }
          return true;
        })
        .toList(growable: false);

    if (candidates.length != 1) {
      throw _invalidIdToken();
    }

    final JsonWebKeyStore keyStore = JsonWebKeyStore()
      ..addKey(JsonWebKey.fromJson(candidates.single));

    try {
      final JsonWebToken jwt = JsonWebToken.unverified(idToken);
      final bool verified = await jwt.verify(
        keyStore,
        allowedArguments: const <String>['RS256'],
      );
      if (!verified) {
        throw _invalidIdToken();
      }
    } on AquariOAuthException {
      rethrow;
    } on Object catch (error) {
      throw _invalidIdToken(
        'Aquari returned an ID token that failed cryptographic or claims validation.',
        error,
      );
    }

    final Map<String, Object?> claims = _decodeJwtPart(parts[1]);
    if (claims['iss'] != discovery.issuer.toString()) {
      throw _invalidIdToken();
    }

    final List<String> audience = _readAudience(claims['aud']);
    if (!audience.contains(clientId)) {
      throw _invalidIdToken();
    }

    final int exp = _requiredIntegerClaim(claims, 'exp');
    final int iat = _requiredIntegerClaim(claims, 'iat');
    final int now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final int tolerance = _idTokenClockTolerance.inSeconds;

    if (exp < now - tolerance) {
      throw _invalidIdToken();
    }
    if (iat > now + tolerance) {
      throw _invalidIdToken(
        'Aquari ID token has an issued-at time too far in the future.',
      );
    }

    final String subject = _requiredStringClaim(claims, 'sub');
    if (expectedNonce != null && claims['nonce'] != expectedNonce) {
      throw _invalidIdToken(
        'Aquari ID token nonce does not match the authorization transaction.',
      );
    }
    if (audience.length > 1 && claims['azp'] != clientId) {
      throw _invalidIdToken(
        'Aquari ID token with multiple audiences must identify this client as the authorized party.',
      );
    }

    return _parseIdentity(claims, label: 'ID token', knownSubject: subject);
  }
}

final class _UnboundTokenSet {
  const _UnboundTokenSet({
    required this.tokenType,
    required this.accessToken,
    required this.idToken,
    required this.refreshToken,
    required this.expiresIn,
    required this.expiresAt,
    required this.scopes,
  });

  final String tokenType;
  final String accessToken;
  final String idToken;
  final String? refreshToken;
  final int expiresIn;
  final int expiresAt;
  final List<String> scopes;
}

_UnboundTokenSet _parseAuthorizationTokenResponse(
  Map<String, Object?> value,
  List<String> requestedScopes,
) {
  final String tokenType = _requireBearer(value);
  final String access = _requiredTokenString(value, 'access_token');
  final String id = _requiredTokenString(value, 'id_token');
  final String? refresh = _optionalTokenString(value, 'refresh_token');
  final int expiresIn = _requiredPositiveInt(value, 'expires_in');
  final List<String> scopes = _parseScope(
    _optionalScopeString(value),
    requestedScopes,
  );
  return _UnboundTokenSet(
    tokenType: tokenType,
    accessToken: access,
    idToken: id,
    refreshToken: refresh,
    expiresIn: expiresIn,
    expiresAt: DateTime.now().millisecondsSinceEpoch + (expiresIn * 1000),
    scopes: scopes,
  );
}

AquariTokenSet _parseRefreshTokenResponse(
  Map<String, Object?> value,
  AquariTokenSet current,
) {
  final int expiresIn = _requiredPositiveInt(value, 'expires_in');
  return AquariTokenSet(
    subject: current.subject,
    tokenType: _requireBearer(value),
    accessToken: _requiredTokenString(value, 'access_token'),
    idToken: _optionalTokenString(value, 'id_token') ?? current.idToken,
    refreshToken:
        _optionalTokenString(value, 'refresh_token') ?? current.refreshToken,
    expiresIn: expiresIn,
    expiresAt: DateTime.now().millisecondsSinceEpoch + (expiresIn * 1000),
    scopes: _parseScope(_optionalScopeString(value), current.scopes),
  );
}

void _validateTokenSet(AquariTokenSet tokens) {
  if (tokens.subject.isEmpty ||
      tokens.tokenType != 'Bearer' ||
      tokens.accessToken.isEmpty ||
      tokens.idToken.isEmpty ||
      tokens.expiresIn <= 0 ||
      tokens.expiresAt <= 0 ||
      tokens.scopes.isEmpty) {
    throw AquariOAuthException(
      'invalid_token_set',
      'Aquari token set is invalid.',
    );
  }
}

String _requireBearer(Map<String, Object?> value) {
  final String raw = _requiredTokenString(value, 'token_type');
  if (raw.toLowerCase() != 'bearer') {
    throw AquariOAuthException(
      'invalid_token_response',
      'Aquari token response did not use the Bearer token type.',
    );
  }
  return 'Bearer';
}

String _requiredTokenString(Map<String, Object?> value, String name) {
  return _optionalTokenString(value, name) ??
      (throw AquariOAuthException(
        'invalid_token_response',
        'Aquari returned an invalid token response.',
      ));
}

String? _optionalTokenString(Map<String, Object?> value, String name) {
  final Object? raw = value[name];
  if (raw == null) {
    return null;
  }
  if (raw is! String || raw.isEmpty) {
    throw AquariOAuthException(
      'invalid_token_response',
      'Aquari returned an invalid token response.',
    );
  }
  return raw;
}

int _requiredPositiveInt(Map<String, Object?> value, String name) {
  final Object? raw = value[name];
  if (raw is! int || raw <= 0) {
    throw AquariOAuthException(
      'invalid_token_response',
      'Aquari returned an invalid token response.',
    );
  }
  return raw;
}

String? _optionalScopeString(Map<String, Object?> value) {
  final Object? raw = value['scope'];
  if (raw == null) {
    return null;
  }
  if (raw is! String) {
    throw AquariOAuthException(
      'invalid_token_response',
      'Aquari returned an invalid scope value.',
    );
  }
  return raw;
}

List<String> _parseScope(String? value, List<String> fallback) {
  if (value == null) {
    return fallback;
  }
  final List<String> scopes = value
      .split(' ')
      .where((String scope) => scope.isNotEmpty)
      .toList(growable: false);

  if (scopes.isEmpty ||
      scopes.any(
        (String scope) =>
            scope != scope.trim() || RegExp(r'\s').hasMatch(scope),
      ) ||
      scopes.toSet().length != scopes.length) {
    throw AquariOAuthException(
      'invalid_token_response',
      'Aquari returned an invalid scope value.',
    );
  }
  return List<String>.unmodifiable(scopes);
}

AquariIdentity _parseIdentity(
  Map<String, Object?> value, {
  required String label,
  String? knownSubject,
  String errorCode = 'invalid_id_token',
}) {
  return AquariIdentity(
    subject:
        knownSubject ??
        _strictString(
          value,
          'sub',
          required: true,
          label: label,
          errorCode: errorCode,
        )!,
    handle: _strictString(
      value,
      'preferred_username',
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    canonicalHandle: _strictString(
      value,
      _canonicalHandleClaim,
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    verifiedHandle: _strictString(
      value,
      _verifiedHandleClaim,
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    name: _strictString(
      value,
      'name',
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    pictureUrl: _strictString(
      value,
      'picture',
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    email: _strictString(
      value,
      'email',
      required: false,
      label: label,
      errorCode: errorCode,
    ),
    emailVerified: _strictBool(
      value,
      'email_verified',
      label: label,
      errorCode: errorCode,
    ),
  );
}

String? _strictString(
  Map<String, Object?> value,
  String name, {
  required bool required,
  required String label,
  required String errorCode,
}) {
  final Object? raw = value[name];
  if (raw == null) {
    if (required) {
      throw AquariOAuthException(
        errorCode,
        "Aquari $label is missing '$name'.",
      );
    }
    return null;
  }
  if (raw is! String || (required && raw.isEmpty)) {
    throw AquariOAuthException(
      errorCode,
      "Aquari $label claim '$name' is malformed.",
    );
  }
  return raw;
}

bool? _strictBool(
  Map<String, Object?> value,
  String name, {
  required String label,
  required String errorCode,
}) {
  final Object? raw = value[name];
  if (raw == null) {
    return null;
  }
  if (raw is! bool) {
    throw AquariOAuthException(
      errorCode,
      "Aquari $label claim '$name' is malformed.",
    );
  }
  return raw;
}

Map<String, Object?> _decodeJwtPart(String value) {
  try {
    final String normalized = base64Url.normalize(value);
    final Object? decoded = jsonDecode(
      utf8.decode(base64Url.decode(normalized)),
    );
    if (decoded is! Map<Object?, Object?>) {
      throw const FormatException('JWT object');
    }
    return decoded.cast<String, Object?>();
  } on Object catch (error) {
    throw _invalidIdToken(
      'Aquari returned an ID token that failed cryptographic or claims validation.',
      error,
    );
  }
}

List<String> _readAudience(Object? raw) {
  if (raw is String && raw.isNotEmpty) {
    return <String>[raw];
  }
  if (raw is List<Object?> && raw.every((Object? item) => item is String)) {
    return List<String>.unmodifiable(raw.cast<String>());
  }
  throw _invalidIdToken('Aquari ID token audience claim is malformed.');
}

int _requiredIntegerClaim(Map<String, Object?> claims, String name) {
  final Object? raw = claims[name];
  if (raw is! int) {
    throw _invalidIdToken("Aquari ID token is missing a valid '$name' claim.");
  }
  return raw;
}

String _requiredStringClaim(Map<String, Object?> claims, String name) {
  final Object? raw = claims[name];
  if (raw is! String || raw.isEmpty) {
    throw _invalidIdToken("Aquari ID token is missing a valid '$name' claim.");
  }
  return raw;
}

AquariOAuthException _invalidIdToken([
  String message =
      'Aquari returned an ID token that failed cryptographic or claims validation.',
  Object? cause,
]) {
  return AquariOAuthException('invalid_id_token', message, cause: cause);
}

Map<String, Object?> _requireJsonMap(
  Object? raw,
  String errorCode,
  String message,
) {
  if (raw is Map<String, Object?>) {
    return raw;
  }
  if (raw is Map<Object?, Object?>) {
    return raw.cast<String, Object?>();
  }
  throw AquariOAuthException(errorCode, message);
}

void _validateCallbackBase(Uri callback, Uri redirect) {
  final bool sameBase =
      callback.scheme == redirect.scheme &&
      callback.userInfo == redirect.userInfo &&
      callback.host == redirect.host &&
      callback.port == redirect.port &&
      callback.path == redirect.path &&
      !callback.hasFragment;

  if (!sameBase || !_containsFixedQuery(callback, redirect)) {
    throw AquariOAuthException(
      'invalid_callback',
      'Aquari authorization callback URL does not match the configured redirect URI.',
    );
  }
}

bool _containsFixedQuery(Uri callback, Uri redirect) {
  final Map<String, List<String>> actual = callback.queryParametersAll;
  final Map<String, List<String>> expected = redirect.queryParametersAll;

  for (final MapEntry<String, List<String>> entry in expected.entries) {
    final List<String> remaining = List<String>.from(
      actual[entry.key] ?? const <String>[],
    );
    for (final String expectedValue in entry.value) {
      final int index = remaining.indexOf(expectedValue);
      if (index < 0) {
        return false;
      }
      remaining.removeAt(index);
    }
  }
  return true;
}

String? _singleCallbackValue(
  Map<String, List<String>> parameters,
  String name, {
  required bool required,
}) {
  final List<String> values = parameters[name] ?? const <String>[];
  if (values.length > 1) {
    throw AquariOAuthException(
      'invalid_callback',
      "Aquari authorization callback contains multiple '$name' parameters.",
    );
  }
  final String? value = values.isEmpty ? null : values.first;
  if (value == null || value.isEmpty) {
    if (required) {
      throw AquariOAuthException(
        'invalid_callback',
        "Aquari authorization callback is missing '$name'.",
      );
    }
    return null;
  }
  return value;
}

String _encodeForm(Map<String, String> values) {
  return values.entries
      .map(
        (MapEntry<String, String> entry) =>
            '${Uri.encodeQueryComponent(entry.key)}='
            '${Uri.encodeQueryComponent(entry.value)}',
      )
      .join('&');
}

bool _listEquals(List<String> a, List<String> b) {
  if (a.length != b.length) {
    return false;
  }
  for (int index = 0; index < a.length; index += 1) {
    if (a[index] != b[index]) {
      return false;
    }
  }
  return true;
}
