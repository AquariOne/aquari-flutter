import 'dart:async';

/// Provides cooperative cancellation for Aquari Flutter operations that accept a cancellation
/// token.
final class AquariCancellationToken {
  final Completer<void> _completer = Completer<void>();

  bool get isCancelled => _completer.isCompleted;

  Future<void> get whenCancelled => _completer.future;

  /// Signals cancellation to operations that are observing this token.
  void cancel() {
    if (!_completer.isCompleted) {
      _completer.complete();
    }
  }

  /// Throws the SDK cancellation error when cancellation has been requested.
  void throwIfCancelled() {
    if (isCancelled) {
      throw StateError('Aquari operation was cancelled.');
    }
  }
}
