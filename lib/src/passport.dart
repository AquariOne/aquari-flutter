import 'transport.dart';

/// Identifies the Aquari signal family represented by a Passport signal.
enum AquariPassportSignalFamily {
  badge,
  stamp,
  credential,
  entitlement,
  role,
  membership,
  unknown,
}

/// Contains the profile fields exposed by a connected Aquari Passport.
final class AquariPassportProfile {
  const AquariPassportProfile({
    required this.displayName,
    required this.handle,
    required this.avatarUrl,
    required this.publicUrl,
    required this.verified,
    required this.visibility,
  });

  final String displayName;
  final String handle;
  final String? avatarUrl;
  final String publicUrl;
  final bool verified;
  final String visibility;
}

/// Contains the total number of signals reported for a connected Passport.
final class AquariPassportSignalSummary {
  const AquariPassportSignalSummary(this.total);
  final int total;
}

/// Represents the connected Passport returned for the authenticated Aquari subject.
final class AquariPassport {
  const AquariPassport({
    required this.id,
    required this.passportNumber,
    required this.subjectId,
    required this.profile,
    required this.signals,
  });

  final String id;
  final String passportNumber;
  final String subjectId;
  final AquariPassportProfile profile;
  final AquariPassportSignalSummary signals;
}

/// Identifies the issuer that produced a Passport signal.
final class AquariPassportSignalIssuer {
  const AquariPassportSignalIssuer({
    required this.type,
    required this.id,
    required this.name,
    required this.logoUrl,
  });

  final String type;
  final String id;
  final String name;
  final String? logoUrl;
}

/// Identifies the resource scope attached to a Passport signal.
final class AquariPassportSignalScope {
  const AquariPassportSignalScope({required this.type, required this.id});

  final String type;
  final String id;
}

/// Represents one portable signal on an Aquari Passport.
final class AquariPassportSignal {
  const AquariPassportSignal({
    required this.id,
    required this.subjectId,
    required this.family,
    required this.sourceType,
    required this.definitionId,
    required this.presentationType,
    required this.name,
    required this.description,
    required this.imageUrl,
    required this.issuer,
    required this.issuedAt,
    required this.expiresAt,
    required this.visibility,
    required this.verified,
    required this.occurredAt,
    required this.scope,
  });

  final String id;
  final String subjectId;
  final AquariPassportSignalFamily family;
  final String sourceType;
  final String? definitionId;
  final String presentationType;
  final String name;
  final String description;
  final String? imageUrl;
  final AquariPassportSignalIssuer issuer;
  final DateTime issuedAt;
  final DateTime? expiresAt;
  final String visibility;
  final bool verified;
  final DateTime? occurredAt;
  final AquariPassportSignalScope? scope;
}

/// Contains one page of Passport signals and cursor pagination state.
final class AquariPassportSignalPage {
  const AquariPassportSignalPage({
    required this.items,
    required this.nextCursor,
    required this.hasMore,
  });

  final List<AquariPassportSignal> items;
  final String? nextCursor;
  final bool hasMore;
}

/// Represents one signal that is visible on a public Aquari Passport.
final class AquariPublicPassportSignal {
  const AquariPublicPassportSignal({
    required this.id,
    required this.type,
    required this.name,
    required this.description,
    required this.imageUrl,
    required this.issuer,
    required this.issuerLogoUrl,
    required this.issuedAt,
    required this.expiresAt,
    required this.verified,
    required this.occurredAt,
    required this.scope,
  });

  final String id;
  final String type;
  final String name;
  final String description;
  final String? imageUrl;
  final String issuer;
  final String? issuerLogoUrl;
  final DateTime issuedAt;
  final DateTime? expiresAt;
  final bool verified;
  final DateTime? occurredAt;
  final AquariPassportSignalScope? scope;
}

/// Represents public Passport data that can be read by handle without an authenticated session.
final class AquariPublicPassport {
  const AquariPublicPassport({
    required this.displayName,
    required this.handle,
    required this.avatarUrl,
    required this.publicUrl,
    required this.verified,
    required this.signals,
  });

  final String displayName;
  final String handle;
  final String? avatarUrl;
  final String publicUrl;
  final bool verified;
  final List<AquariPublicPassportSignal> signals;
}

/// Configures Passport signal filtering and cursor pagination.
final class AquariPassportSignalQuery {
  const AquariPassportSignalQuery({
    this.type,
    this.issuerId,
    this.definitionId,
    this.limit,
    this.cursor,
  });

  final String? type;
  final String? issuerId;
  final String? definitionId;
  final int? limit;
  final String? cursor;

  /// Creates a copy of these Passport signal filters with the requested cursor change.
  AquariPassportSignalQuery copyWith({String? cursor}) {
    return AquariPassportSignalQuery(
      type: type,
      issuerId: issuerId,
      definitionId: definitionId,
      limit: limit,
      cursor: cursor,
    );
  }
}

/// Lists and reads signals on the authenticated subject's Passport.
final class AquariPassportSignalsClient {
  /// Creates a Passport signal client that uses the supplied Aquari HTTP transport.
  AquariPassportSignalsClient(this._transport);
  final AquariHttpTransport _transport;

  /// Reads one page of Passport signals using the supplied filters and cursor.
  Future<AquariPassportSignalPage> list(
    String accessToken, {
    AquariPassportSignalQuery query = const AquariPassportSignalQuery(),
  }) async {
    final Map<String, String> params = <String, String>{};
    if (query.type != null) {
      params['type'] = _validateFilter(query.type!, 'type');
    }
    if (query.issuerId != null) {
      params['issuer_id'] = _validateFilter(query.issuerId!, 'issuerId');
    }
    if (query.definitionId != null) {
      params['definition_id'] = _validateFilter(
        query.definitionId!,
        'definitionId',
      );
    }
    if (query.limit != null) {
      if (query.limit! < 1 || query.limit! > 100) {
        throw ArgumentError(
          'Aquari Passport signal limit must be from 1 through 100.',
        );
      }
      params['limit'] = query.limit!.toString();
    }
    if (query.cursor != null) {
      params['cursor'] = _validateFilter(query.cursor!, 'cursor');
    }

    final String suffix = params.isEmpty
        ? ''
        : '?${Uri(queryParameters: params).query}';

    final Map<String, Object?> root = _map(
      await _transport.requestJson(
        '/api/v1/passport/signals$suffix',
        headers: _bearer(accessToken),
      ),
      'Passport signal page',
    );
    final List<Object?> items = _list(root, 'items', 'Passport signal page');
    final Map<String, Object?> page = _map(
      root['page'],
      'Passport page metadata',
    );

    return AquariPassportSignalPage(
      items: List<AquariPassportSignal>.unmodifiable(items.map(_parseSignal)),
      nextCursor: _optionalString(page, 'nextCursor'),
      hasMore: _requiredBool(page, 'hasMore'),
    );
  }

  /// Streams Passport signals across cursor pages until Aquari reports that no additional page is
  /// available.
  Stream<AquariPassportSignal> iterate(
    String accessToken, {
    AquariPassportSignalQuery query = const AquariPassportSignalQuery(),
  }) async* {
    String? cursor = query.cursor;
    while (true) {
      final AquariPassportSignalPage page = await list(
        accessToken,
        query: query.copyWith(cursor: cursor),
      );
      yield* Stream<AquariPassportSignal>.fromIterable(page.items);
      if (!page.hasMore || page.nextCursor == null) {
        return;
      }
      cursor = page.nextCursor;
    }
  }
}

/// Reads connected and public Passport data.
final class AquariPassportClient {
  /// Creates a Passport client and its signal subclient with the supplied Aquari HTTP transport.
  AquariPassportClient(this._transport)
    : signals = AquariPassportSignalsClient(_transport);

  final AquariHttpTransport _transport;
  final AquariPassportSignalsClient signals;

  /// Reads the connected Passport for the authenticated subject represented by the supplied access
  /// token.
  Future<AquariPassport> get(String accessToken) async {
    final Map<String, Object?> root = _map(
      await _transport.requestJson(
        '/api/v1/passport',
        headers: _bearer(accessToken),
      ),
      'Passport response',
    );
    return _parsePassport(root['passport']);
  }

  /// Reads public Passport data for the supplied Aquari handle without using a bearer access token.
  Future<AquariPublicPassport> getPublic(String handle) async {
    final String value = _validateFilter(handle, 'handle');
    return _parsePublicPassport(
      await _transport.requestJson(
        '/api/v1/public/passports/${Uri.encodeComponent(value)}',
      ),
    );
  }
}

AquariPassport _parsePassport(Object? value) {
  final Map<String, Object?> record = _map(value, 'Passport object');
  final Map<String, Object?> profile = _map(
    record['profile'],
    'Passport profile',
  );
  final Map<String, Object?> signals = _map(
    record['signals'],
    'Passport signals',
  );

  return AquariPassport(
    id: _requiredString(record, 'id'),
    passportNumber: _requiredString(record, 'passportNumber'),
    subjectId: _requiredString(record, 'subjectId'),
    profile: AquariPassportProfile(
      displayName: _requiredString(profile, 'displayName', allowEmpty: true),
      handle: _requiredString(profile, 'handle'),
      avatarUrl: _optionalString(profile, 'avatarUrl'),
      publicUrl: _requiredString(profile, 'publicUrl'),
      verified: _requiredBool(profile, 'verified'),
      visibility: _requiredString(profile, 'visibility'),
    ),
    signals: AquariPassportSignalSummary(_requiredInt(signals, 'total')),
  );
}

AquariPassportSignal _parseSignal(Object? value) {
  final Map<String, Object?> record = _map(value, 'Passport signal');
  final Map<String, Object?> issuer = _map(
    record['issuer'],
    'Passport signal issuer',
  );
  final Map<String, Object?>? scope = record['scope'] == null
      ? null
      : _map(record['scope'], 'Passport signal scope');
  final String sourceType = _requiredString(record, 'sourceType');
  final String presentationType = _requiredString(record, 'type');

  return AquariPassportSignal(
    id: _requiredString(record, 'id'),
    subjectId: _requiredString(record, 'subjectId'),
    family: _signalFamily(sourceType, presentationType),
    sourceType: sourceType,
    definitionId: _optionalString(record, 'definitionId'),
    presentationType: presentationType,
    name: _requiredString(record, 'name'),
    description: _requiredString(record, 'description', allowEmpty: true),
    imageUrl: _optionalString(record, 'imageUrl'),
    issuer: AquariPassportSignalIssuer(
      type: _requiredString(issuer, 'type'),
      id: _requiredString(issuer, 'id'),
      name: _requiredString(issuer, 'name'),
      logoUrl: _optionalString(issuer, 'logoUrl'),
    ),
    issuedAt: _requiredDate(record, 'issuedAt'),
    expiresAt: _optionalDate(record, 'expiresAt'),
    visibility: _requiredString(record, 'visibility'),
    verified: _requiredBool(record, 'verified'),
    occurredAt: _optionalDate(record, 'occurredAt'),
    scope: scope == null
        ? null
        : AquariPassportSignalScope(
            type: _requiredString(scope, 'type'),
            id: _requiredString(scope, 'id'),
          ),
  );
}

AquariPublicPassport _parsePublicPassport(Object? value) {
  final Map<String, Object?> record = _map(value, 'public Passport response');
  final List<Object?> signals = _list(record, 'signals', 'public Passport');
  return AquariPublicPassport(
    displayName: _requiredString(record, 'displayName', allowEmpty: true),
    handle: _requiredString(record, 'handle'),
    avatarUrl: _optionalString(record, 'avatarUrl'),
    publicUrl: _requiredString(record, 'publicUrl'),
    verified: _requiredBool(record, 'verified'),
    signals: List<AquariPublicPassportSignal>.unmodifiable(
      signals.map((Object? item) {
        final Map<String, Object?> signal = _map(
          item,
          'public Passport signal',
        );
        final Map<String, Object?>? scope = signal['scope'] == null
            ? null
            : _map(signal['scope'], 'public Passport signal scope');
        return AquariPublicPassportSignal(
          id: _requiredString(signal, 'id'),
          type: _requiredString(signal, 'type'),
          name: _requiredString(signal, 'name'),
          description: _requiredString(signal, 'description', allowEmpty: true),
          imageUrl: _optionalString(signal, 'imageUrl'),
          issuer: _requiredString(signal, 'issuer'),
          issuerLogoUrl: _optionalString(signal, 'issuerLogoUrl'),
          issuedAt: _requiredDate(signal, 'issuedAt'),
          expiresAt: _optionalDate(signal, 'expiresAt'),
          verified: _requiredBool(signal, 'verified'),
          occurredAt: _optionalDate(signal, 'occurredAt'),
          scope: scope == null
              ? null
              : AquariPassportSignalScope(
                  type: _requiredString(scope, 'type'),
                  id: _requiredString(scope, 'id'),
                ),
        );
      }),
    ),
  );
}

AquariPassportSignalFamily _signalFamily(
  String sourceType,
  String presentationType,
) {
  if (sourceType == 'badge' && presentationType == 'badge') {
    return AquariPassportSignalFamily.badge;
  }
  if (sourceType == 'passport_stamp' && presentationType == 'stamp') {
    return AquariPassportSignalFamily.stamp;
  }
  if (sourceType == 'credential' && presentationType == 'credential') {
    return AquariPassportSignalFamily.credential;
  }
  if (sourceType == 'user_entitlement' && presentationType == 'credential') {
    return AquariPassportSignalFamily.entitlement;
  }
  if (sourceType == 'app_membership' && presentationType == 'role') {
    return AquariPassportSignalFamily.role;
  }
  if (sourceType == 'organization_membership' &&
      presentationType == 'membership') {
    return AquariPassportSignalFamily.membership;
  }
  return AquariPassportSignalFamily.unknown;
}

Map<String, String> _bearer(String token) {
  if (token.isEmpty || token != token.trim()) {
    throw ArgumentError(
      'Aquari accessToken must be a non-empty value without surrounding whitespace.',
    );
  }
  return <String, String>{'authorization': 'Bearer $token'};
}

String _validateFilter(String value, String label) {
  if (value.isEmpty || value != value.trim()) {
    throw ArgumentError('Aquari $label must be non-empty and normalized.');
  }
  return value;
}

Map<String, Object?> _map(Object? value, String label) {
  if (value is Map<String, Object?>) {
    return value;
  }
  if (value is Map<Object?, Object?>) {
    return value.cast<String, Object?>();
  }
  throw FormatException('Aquari $label is malformed.');
}

List<Object?> _list(Map<String, Object?> record, String name, String label) {
  final Object? value = record[name];
  if (value is! List<Object?>) {
    throw FormatException('Aquari $label field $name is malformed.');
  }
  return value.cast<Object?>();
}

String _requiredString(
  Map<String, Object?> record,
  String name, {
  bool allowEmpty = false,
}) {
  final Object? value = record[name];
  if (value is! String || (!allowEmpty && value.isEmpty)) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value;
}

String? _optionalString(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value == null) {
    return null;
  }
  if (value is! String) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value;
}

bool _requiredBool(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value is! bool) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value;
}

int _requiredInt(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value is! int) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value;
}

DateTime _requiredDate(Map<String, Object?> record, String name) {
  final String raw = _requiredString(record, name);
  final DateTime? value = DateTime.tryParse(raw);
  if (value == null) {
    throw FormatException('Aquari field $name is not an ISO timestamp.');
  }
  return value;
}

DateTime? _optionalDate(Map<String, Object?> record, String name) {
  final String? raw = _optionalString(record, name);
  if (raw == null) {
    return null;
  }
  final DateTime? value = DateTime.tryParse(raw);
  if (value == null) {
    throw FormatException('Aquari field $name is not an ISO timestamp.');
  }
  return value;
}
