import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'auth.dart';
import 'flutter_client.dart';

/// Stores the Aquari token set with flutter_secure_storage.
final class FlutterSecureAquariTokenStore implements AquariTokenStore {
  /// Creates a flutter_secure_storage token store with the configured storage key.
  FlutterSecureAquariTokenStore({
    FlutterSecureStorage? storage,
    this.storageKey = 'aquari_one.tokens.v1',
  }) : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;
  final String storageKey;

  /// Reads the current Aquari token set from protected storage. Returns null when no token set is
  /// stored.
  @override
  Future<AquariTokenSet?> readTokens() async {
    final String? value = await _storage.read(key: storageKey);
    return value == null ? null : deserializeAquariTokenSet(value);
  }

  /// Replaces the current Aquari token set in protected storage.
  @override
  Future<void> writeTokens(AquariTokenSet tokens) {
    return _storage.write(
      key: storageKey,
      value: serializeAquariTokenSet(tokens),
    );
  }

  /// Removes the Aquari token set from protected storage.
  @override
  Future<void> clearTokens() => _storage.delete(key: storageKey);
}

/// Stores the pending Aquari authorization transaction with flutter_secure_storage.
final class FlutterSecureAquariTransactionStore
    implements AquariAuthorizationTransactionStore {
  /// Creates a flutter_secure_storage transaction store with the configured storage key.
  FlutterSecureAquariTransactionStore({
    FlutterSecureStorage? storage,
    this.storageKey = 'aquari_one.authorization_transaction.v1',
  }) : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;
  final String storageKey;

  /// Reads the pending Aquari authorization transaction from protected storage.
  @override
  Future<AquariAuthorizationTransaction?> readTransaction() async {
    final String? value = await _storage.read(key: storageKey);
    return value == null
        ? null
        : deserializeAquariAuthorizationTransaction(value);
  }

  /// Stores the pending Aquari authorization transaction before browser handoff.
  @override
  Future<void> writeTransaction(AquariAuthorizationTransaction transaction) {
    return _storage.write(
      key: storageKey,
      value: serializeAquariAuthorizationTransaction(transaction),
    );
  }

  /// Removes the pending Aquari authorization transaction from protected storage.
  @override
  Future<void> clearTransaction() => _storage.delete(key: storageKey);
}
