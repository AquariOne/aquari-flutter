import 'transport.dart';

/// Contains the trust outcomes Aquari calculated for one subject and consumer application.
final class AquariTrustEvaluation {
  const AquariTrustEvaluation({
    required this.evaluationId,
    required this.subjectId,
    required this.consumerApplicationId,
    required this.evaluatedAt,
    required this.outcomes,
  });

  final String evaluationId;
  final String subjectId;
  final String consumerApplicationId;
  final DateTime evaluatedAt;
  final List<AquariTrustOutcome> outcomes;
}

/// Represents one trust outcome and the signals that support it.
final class AquariTrustOutcome {
  const AquariTrustOutcome({
    required this.type,
    required this.value,
    required this.supports,
  });

  final String type;
  final String value;
  final List<AquariTrustSupport> supports;
}

/// Explains which trusted mapping and signal support a trust outcome.
final class AquariTrustSupport {
  const AquariTrustSupport({
    required this.mappingId,
    required this.mappingVersion,
    required this.trustedIssuerId,
    required this.signal,
  });

  final String mappingId;
  final int mappingVersion;
  final String trustedIssuerId;
  final AquariTrustSignal signal;
}

/// Describes the Passport signal that supported a trust outcome.
final class AquariTrustSignal {
  const AquariTrustSignal({
    required this.id,
    required this.signalFamily,
    required this.definitionId,
    required this.authority,
    required this.scope,
    required this.issuedAt,
    required this.expiresAt,
  });

  final String id;
  final String signalFamily;
  final String? definitionId;
  final AquariTrustAuthority authority;
  final AquariTrustScope? scope;
  final DateTime issuedAt;
  final DateTime? expiresAt;
}

/// Identifies the authority attached to a trusted signal.
final class AquariTrustAuthority {
  const AquariTrustAuthority({required this.type, required this.id});
  final String type;
  final String id;
}

/// Identifies the resource scope attached to a trusted signal.
final class AquariTrustScope {
  const AquariTrustScope({required this.type, required this.id});
  final String type;
  final String id;
}

/// Evaluates the current application's configured trust mappings for an authenticated Aquari
/// subject.
final class AquariTrustClient {
  /// Creates a trust client that uses the supplied Aquari HTTP transport.
  AquariTrustClient(this._transport);
  final AquariHttpTransport _transport;

  /// Requests Aquari trust evaluation for the authenticated subject represented by the supplied
  /// access token.
  Future<AquariTrustEvaluation> evaluate(String accessToken) async {
    if (accessToken.isEmpty || accessToken != accessToken.trim()) {
      throw ArgumentError(
        'Aquari accessToken must be a non-empty value without surrounding whitespace.',
      );
    }

    final Object? raw = await _transport.requestJson(
      '/api/v1/passport/trust/evaluation',
      headers: <String, String>{'authorization': 'Bearer $accessToken'},
    );
    final Map<String, Object?> root = _map(raw, 'trust evaluation');

    return AquariTrustEvaluation(
      evaluationId: _string(root, 'evaluationId'),
      subjectId: _string(root, 'subjectId'),
      consumerApplicationId: _string(root, 'consumerApplicationId'),
      evaluatedAt: _date(root, 'evaluatedAt'),
      outcomes: List<AquariTrustOutcome>.unmodifiable(
        _list(root, 'outcomes').map((Object? item) {
          final Map<String, Object?> outcome = _map(item, 'trust outcome');
          return AquariTrustOutcome(
            type: _string(outcome, 'type'),
            value: _string(outcome, 'value'),
            supports: List<AquariTrustSupport>.unmodifiable(
              _list(outcome, 'supports').map((Object? supportValue) {
                final Map<String, Object?> support = _map(
                  supportValue,
                  'trust support',
                );
                return AquariTrustSupport(
                  mappingId: _string(support, 'mappingId'),
                  mappingVersion: _integer(support, 'mappingVersion'),
                  trustedIssuerId: _string(support, 'trustedIssuerId'),
                  signal: _parseSignal(_map(support['signal'], 'trust signal')),
                );
              }),
            ),
          );
        }),
      ),
    );
  }
}

AquariTrustSignal _parseSignal(Map<String, Object?> record) {
  final Map<String, Object?> authority = _map(
    record['authority'],
    'trust authority',
  );
  final Map<String, Object?>? scope = record['scope'] == null
      ? null
      : _map(record['scope'], 'trust scope');

  return AquariTrustSignal(
    id: _string(record, 'id'),
    signalFamily: _string(record, 'signalFamily'),
    definitionId: _optionalString(record, 'definitionId'),
    authority: AquariTrustAuthority(
      type: _string(authority, 'type'),
      id: _string(authority, 'id'),
    ),
    scope: scope == null
        ? null
        : AquariTrustScope(
            type: _string(scope, 'type'),
            id: _string(scope, 'id'),
          ),
    issuedAt: _date(record, 'issuedAt'),
    expiresAt: _optionalDate(record, 'expiresAt'),
  );
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

List<Object?> _list(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value is! List<Object?>) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value.cast<Object?>();
}

String _string(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value is! String || value.isEmpty) {
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

int _integer(Map<String, Object?> record, String name) {
  final Object? value = record[name];
  if (value is! int) {
    throw FormatException('Aquari field $name is malformed.');
  }
  return value;
}

DateTime _date(Map<String, Object?> record, String name) {
  final DateTime? value = DateTime.tryParse(_string(record, name));
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
