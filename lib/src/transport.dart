import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'cancellation.dart';
import 'config.dart';
import 'errors.dart';
import 'http.dart';

enum AquariRetryMode { auto, never, idempotent }

final class AquariHttpTransport {
  AquariHttpTransport({required ResolvedAquariClientOptions options})
    : _baseUrl = options.issuer,
      _timeout = options.timeout,
      _maxRetries = options.maxRetries,
      _maxRetryDelay = options.maxRetryDelay,
      _executor = options.httpExecutor;

  final Uri _baseUrl;
  final Duration _timeout;
  final int _maxRetries;
  final Duration _maxRetryDelay;
  final AquariHttpExecutor _executor;
  final Random _random = Random.secure();

  Future<Object?> requestJson(
    String path, {
    String method = 'GET',
    Map<String, String> headers = const <String, String>{},
    String? body,
    String? contentType,
    AquariRetryMode retryMode = AquariRetryMode.auto,
    AquariCancellationToken? cancellationToken,
  }) {
    return requestAbsoluteJson(
      _baseUrl.resolve(path),
      method: method,
      headers: headers,
      body: body,
      contentType: contentType,
      retryMode: retryMode,
      cancellationToken: cancellationToken,
    );
  }

  Future<Object?> requestAbsoluteJson(
    Uri url, {
    String method = 'GET',
    Map<String, String> headers = const <String, String>{},
    String? body,
    String? contentType,
    AquariRetryMode retryMode = AquariRetryMode.auto,
    AquariCancellationToken? cancellationToken,
  }) async {
    final bool retryable = _isRetryableRequest(method, retryMode);
    int attempt = 0;

    while (true) {
      cancellationToken?.throwIfCancelled();
      final Completer<void> abort = Completer<void>();
      bool timedOut = false;
      bool cancelled = false;

      Future<void>? cancellationWatcher;
      if (cancellationToken != null) {
        cancellationWatcher = cancellationToken.whenCancelled.then((_) {
          cancelled = true;
          if (!abort.isCompleted) {
            abort.complete();
          }
        });
      }

      try {
        final Future<AquariRawResponse> operation = _executor.execute(
          AquariRawRequest(
            method: method,
            url: url,
            headers: headers,
            body: body,
            contentType: contentType,
          ),
          abortTrigger: abort.future,
        );

        final AquariRawResponse response = await operation.timeout(
          _timeout,
          onTimeout: () {
            timedOut = true;
            if (!abort.isCompleted) {
              abort.complete();
            }
            throw AquariTimeoutException(_timeout);
          },
        );

        if (response.status >= 200 && response.status <= 299) {
          return response.body.trim().isEmpty
              ? null
              : _parseJson(response.body);
        }

        if (retryable &&
            attempt < _maxRetries &&
            _isRetryableStatus(response.status)) {
          final Duration delay =
              _parseRetryAfter(response.headers) ?? _jitteredBackoff(attempt);
          if (delay <= _maxRetryDelay) {
            await Future<void>.delayed(delay);
            attempt += 1;
            continue;
          }
        }

        throw _classifyApiError(response);
      } on AquariTimeoutException {
        if (retryable && attempt < _maxRetries) {
          final Duration delay = _jitteredBackoff(attempt);
          if (delay <= _maxRetryDelay) {
            await Future<void>.delayed(delay);
            attempt += 1;
            continue;
          }
        }
        rethrow;
      } on http.RequestAbortedException catch (error) {
        if (timedOut) {
          throw AquariTimeoutException(_timeout, error);
        }
        if (cancelled || (cancellationToken?.isCancelled ?? false)) {
          throw AquariTransportException(
            'Aquari request was cancelled.',
            cause: error,
            cancelled: true,
          );
        }
        throw AquariTransportException(
          'Aquari request was aborted.',
          cause: error,
        );
      } on AquariApiException {
        rethrow;
      } on AquariException {
        rethrow;
      } on Object catch (error) {
        if (retryable && attempt < _maxRetries) {
          final Duration delay = _jitteredBackoff(attempt);
          if (delay <= _maxRetryDelay) {
            await Future<void>.delayed(delay);
            attempt += 1;
            continue;
          }
        }
        throw AquariTransportException(
          'Aquari request failed before a valid API response was received.',
          cause: error,
        );
      } finally {
        if (cancellationWatcher != null) {
          unawaited(cancellationWatcher);
        }
      }
    }
  }

  Object? _parseJson(String body) {
    try {
      return jsonDecode(body);
    } on FormatException catch (error) {
      throw AquariTransportException(
        'Aquari returned malformed JSON.',
        cause: error,
      );
    }
  }

  AquariApiException _classifyApiError(AquariRawResponse response) {
    Map<String, Object?>? root;
    try {
      final Object? parsed = _parseJson(response.body);
      if (parsed is Map<String, Object?>) {
        root = parsed;
      } else if (parsed is Map<Object?, Object?>) {
        root = parsed.cast<String, Object?>();
      }
    } on AquariException {
      root = null;
    }

    final String? code = _string(root, 'code') ?? _string(root, 'error');
    final String message =
        _string(root, 'message') ??
        _string(root, 'detail') ??
        'Aquari API request failed with HTTP ${response.status}.';
    final String? requestId =
        _string(root, 'requestId') ?? _header(response.headers, 'x-request-id');
    final Map<String, List<String>> details = _details(root?['details']);

    if (response.status == 429) {
      return AquariRateLimitException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
        retryAfter: _parseRetryAfter(response.headers),
      );
    }

    if (response.status == 403 && code == 'QuotaExceeded') {
      final Map<String, Object?>? quota = _asMap(root?['quota']) ?? root;
      return AquariQuotaException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
        resource: _string(quota, 'resource'),
        scopeType: _string(quota, 'scopeType'),
        scopeId: _string(quota, 'scopeId'),
        current: _integer(quota, 'current'),
        requested: _integer(quota, 'requested'),
        limit: _integer(quota, 'limit'),
        allowance: _integer(quota, 'allowance'),
        grace: _integer(quota, 'grace'),
        periodFrom: _string(quota, 'periodFrom'),
        periodTo: _string(quota, 'periodTo'),
        enforcement: _string(quota, 'enforcement'),
      );
    }

    return switch (response.status) {
      400 || 422 => AquariValidationException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
      401 => AquariAuthenticationException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
      403 => AquariAuthorizationException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
      404 => AquariNotFoundException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
      409 => AquariConflictException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
      _ => AquariApiException(
        status: response.status,
        code: code,
        details: details,
        requestId: requestId,
        message: message,
      ),
    };
  }

  bool _isRetryableRequest(String method, AquariRetryMode mode) {
    return switch (mode) {
      AquariRetryMode.never => false,
      AquariRetryMode.idempotent => true,
      AquariRetryMode.auto => const <String>{
        'GET',
        'HEAD',
        'OPTIONS',
      }.contains(method.toUpperCase()),
    };
  }

  bool _isRetryableStatus(int status) =>
      const <int>{429, 502, 503, 504}.contains(status);

  Duration _jitteredBackoff(int attempt) {
    final int exponent = min(attempt, 8);
    final int baseMs = 250 * (1 << exponent);
    final double factor = 0.5 + (_random.nextDouble() * 0.5);
    return Duration(milliseconds: (baseMs * factor).round());
  }

  Duration? _parseRetryAfter(Map<String, String> headers) {
    final String? value = _header(headers, 'retry-after');
    if (value == null) {
      return null;
    }

    final String normalized = value.trim();
    if (RegExp(r'^\d+$').hasMatch(normalized)) {
      // Keep Duration's microseconds safe on both native and JavaScript runtimes.
      const int maximumSeconds = 9007199254;
      final int? seconds = int.tryParse(normalized);
      return Duration(
        seconds: seconds == null || seconds > maximumSeconds
            ? maximumSeconds
            : seconds,
      );
    }
    final DateTime? date = _httpDate(normalized);
    if (date == null) {
      return null;
    }
    final Duration delta = date.toUtc().difference(DateTime.now().toUtc());
    return delta.isNegative ? Duration.zero : delta;
  }
}

String? _header(Map<String, String> headers, String name) {
  for (final MapEntry<String, String> entry in headers.entries) {
    if (entry.key.toLowerCase() == name.toLowerCase()) {
      return entry.value;
    }
  }
  return null;
}

Map<String, Object?>? _asMap(Object? value) {
  if (value is Map<String, Object?>) {
    return value;
  }
  if (value is Map<Object?, Object?>) {
    return value.cast<String, Object?>();
  }
  return null;
}

String? _string(Map<String, Object?>? map, String name) {
  final Object? value = map?[name];
  return value is String ? value : null;
}

int? _integer(Map<String, Object?>? map, String name) {
  final Object? value = map?[name];
  return value is int ? value : null;
}

Map<String, List<String>> _details(Object? value) {
  final Map<String, Object?>? map = _asMap(value);
  if (map == null) {
    return const <String, List<String>>{};
  }

  return Map<String, List<String>>.unmodifiable(
    map.map((String key, Object? item) {
      if (item is List<Object?>) {
        return MapEntry<String, List<String>>(
          key,
          List<String>.unmodifiable(item.whereType<String>()),
        );
      }
      if (item is String) {
        return MapEntry<String, List<String>>(key, <String>[item]);
      }
      return MapEntry<String, List<String>>(key, const <String>[]);
    }),
  );
}

// HTTP-date is not ISO 8601. Accept all three recipient formats from RFC 9110.
DateTime? _httpDate(String value) {
  final RegExp modern = RegExp(
    r'^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), (\d{2}) ([A-Za-z]{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2}) GMT$',
    caseSensitive: false,
  );
  final RegExp obsolete = RegExp(
    r'^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\d{2})-([A-Za-z]{3})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) GMT$',
    caseSensitive: false,
  );
  final RegExp ascii = RegExp(
    r'^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Za-z]{3}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})$',
    caseSensitive: false,
  );
  RegExpMatch? match = modern.firstMatch(value);
  bool shortYear = false;
  bool asciiFormat = false;
  if (match == null) {
    match = obsolete.firstMatch(value);
    shortYear = match != null;
  }
  if (match == null) {
    match = ascii.firstMatch(value);
    asciiFormat = match != null;
  }
  if (match == null) return null;
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
  final RegExpMatch parsed = match;
  final int month =
      months.indexWhere(
        (String monthName) =>
            monthName.toLowerCase() ==
            parsed.group(asciiFormat ? 1 : 2)!.toLowerCase(),
      ) +
      1;
  final int day = int.parse(match.group(asciiFormat ? 2 : 1)!);
  int year = int.parse(match.group(asciiFormat ? 6 : 3)!);
  if (shortYear) {
    final int currentYear = DateTime.now().toUtc().year;
    year += (currentYear ~/ 100) * 100;
    if (year > currentYear + 50) {
      year -= 100;
    }
  }
  final int hour = int.parse(match.group(asciiFormat ? 3 : 4)!);
  final int minute = int.parse(match.group(asciiFormat ? 4 : 5)!);
  final int second = int.parse(match.group(asciiFormat ? 5 : 6)!);
  if (month == 0 || day < 1 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  final DateTime result = DateTime.utc(year, month, day, hour, minute, second);
  const List<String> weekdays = <String>[
    'Mon',
    'Tue',
    'Wed',
    'Thu',
    'Fri',
    'Sat',
    'Sun',
  ];
  return result.year == year &&
          result.month == month &&
          result.day == day &&
          weekdays[result.weekday - 1].toLowerCase() ==
              value.substring(0, 3).toLowerCase()
      ? result
      : null;
}
