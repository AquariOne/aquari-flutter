import 'package:http/http.dart' as http;

/// Represents one low-level HTTP request before the Aquari transport sends it.
final class AquariRawRequest {
  const AquariRawRequest({
    required this.method,
    required this.url,
    this.headers = const <String, String>{},
    this.body,
    this.contentType,
  });

  final String method;
  final Uri url;
  final Map<String, String> headers;
  final String? body;
  final String? contentType;
}

/// Represents one low-level HTTP response returned to the Aquari transport.
final class AquariRawResponse {
  const AquariRawResponse({
    required this.status,
    required this.headers,
    required this.body,
  });

  final int status;
  final Map<String, String> headers;
  final String body;
}

/// Defines the low-level HTTP execution boundary used by the Flutter Aquari transport.
abstract interface class AquariHttpExecutor {
  /// Executes one low-level HTTP request for the Aquari transport and returns the raw response.
  Future<AquariRawResponse> execute(
    AquariRawRequest request, {
    Future<void>? abortTrigger,
  });
}

/// Executes Aquari HTTP requests with package:http and supports request cancellation.
final class HttpClientAquariExecutor implements AquariHttpExecutor {
  /// Creates the low-level Flutter HTTP executor. If no package:http client is supplied, the executor
  /// owns and closes the client it creates.
  HttpClientAquariExecutor([http.Client? client])
    : _client = client ?? http.Client(),
      _ownsClient = client == null;

  final http.Client _client;
  final bool _ownsClient;

  /// Executes one low-level HTTP request for the Aquari transport and returns the raw response.
  @override
  Future<AquariRawResponse> execute(
    AquariRawRequest request, {
    Future<void>? abortTrigger,
  }) async {
    final http.AbortableRequest raw = http.AbortableRequest(
      request.method,
      request.url,
      abortTrigger: abortTrigger,
    );
    raw.headers.addAll(request.headers);
    if (request.contentType != null) {
      raw.headers['content-type'] = request.contentType!;
    }
    if (request.body != null) {
      raw.body = request.body!;
    }

    final http.StreamedResponse streamed = await _client.send(raw);
    final String body = await streamed.stream.bytesToString();

    return AquariRawResponse(
      status: streamed.statusCode,
      headers: Map<String, String>.unmodifiable(streamed.headers),
      body: body,
    );
  }

  /// Releases HTTP resources owned by this SDK object.
  void close() {
    if (_ownsClient) {
      _client.close();
    }
  }
}
