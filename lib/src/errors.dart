/// Reports an Aquari exception.
class AquariException implements Exception {
  AquariException(this.message, [this.cause]);

  final String message;
  final Object? cause;

  /// Returns a diagnostic representation that does not expose protected token or authorization secret
  /// values.
  @override
  String toString() => '$runtimeType: $message';
}

/// Reports an Aquari configuration exception.
final class AquariConfigurationException extends AquariException {
  AquariConfigurationException(super.message, [super.cause]);
}

/// Reports an Aquari transport exception.
class AquariTransportException extends AquariException {
  AquariTransportException(
    String message, {
    Object? cause,
    this.cancelled = false,
  }) : super(message, cause);

  final bool cancelled;
}

/// Reports an Aquari timeout exception.
final class AquariTimeoutException extends AquariTransportException {
  AquariTimeoutException(this.timeout, [Object? cause])
    : super(
        'Aquari request timed out after ${timeout.inMilliseconds}ms.',
        cause: cause,
      );

  final Duration timeout;
}

/// Reports an Aquari api exception.
class AquariApiException extends AquariException {
  AquariApiException({
    required this.status,
    required this.code,
    required this.details,
    required this.requestId,
    required String message,
  }) : super(message);

  final int status;
  final String? code;
  final Map<String, List<String>> details;
  final String? requestId;
}

/// Reports an Aquari validation exception.
final class AquariValidationException extends AquariApiException {
  AquariValidationException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
  });
}

/// Reports an Aquari authentication exception.
final class AquariAuthenticationException extends AquariApiException {
  AquariAuthenticationException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
  });
}

/// Reports an Aquari authorization exception.
final class AquariAuthorizationException extends AquariApiException {
  AquariAuthorizationException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
  });
}

/// Reports an Aquari not found exception.
final class AquariNotFoundException extends AquariApiException {
  AquariNotFoundException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
  });
}

/// Reports an Aquari conflict exception.
final class AquariConflictException extends AquariApiException {
  AquariConflictException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
  });
}

/// Reports an Aquari rate limit exception.
final class AquariRateLimitException extends AquariApiException {
  AquariRateLimitException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
    required this.retryAfter,
  });

  final Duration? retryAfter;
}

/// Reports an Aquari quota exception.
final class AquariQuotaException extends AquariApiException {
  AquariQuotaException({
    required super.status,
    required super.code,
    required super.details,
    required super.requestId,
    required super.message,
    this.resource,
    this.scopeType,
    this.scopeId,
    this.current,
    this.requested,
    this.limit,
    this.allowance,
    this.grace,
    this.periodFrom,
    this.periodTo,
    this.enforcement,
  });

  final String? resource;
  final String? scopeType;
  final String? scopeId;
  final int? current;
  final int? requested;
  final int? limit;
  final int? allowance;
  final int? grace;
  final String? periodFrom;
  final String? periodTo;
  final String? enforcement;
}

/// Reports an Aquari oauth exception.
final class AquariOAuthException extends AquariException {
  AquariOAuthException(
    this.oauthCode,
    String message, {
    this.errorDescription,
    this.errorUri,
    Object? cause,
  }) : super(message, cause);

  final String oauthCode;
  final String? errorDescription;
  final String? errorUri;
}
