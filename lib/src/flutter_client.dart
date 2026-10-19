import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:url_launcher/url_launcher.dart';

import 'auth.dart';
import 'client.dart';
import 'errors.dart';

/// Defines protected storage for the current Aquari token set on a device.
abstract interface class AquariTokenStore {
  /// Reads the current Aquari token set from protected storage. Returns null when no token set is
  /// stored.
  Future<AquariTokenSet?> readTokens();

  /// Replaces the current Aquari token set in protected storage.
  Future<void> writeTokens(AquariTokenSet tokens);

  /// Removes the Aquari token set from protected storage.
  Future<void> clearTokens();
}

/// Defines protected storage for the pending Aquari authorization transaction.
abstract interface class AquariAuthorizationTransactionStore {
  /// Reads the pending Aquari authorization transaction from protected storage.
  Future<AquariAuthorizationTransaction?> readTransaction();

  /// Stores the pending Aquari authorization transaction before browser handoff.
  Future<void> writeTransaction(AquariAuthorizationTransaction transaction);

  /// Removes the pending Aquari authorization transaction from protected storage.
  Future<void> clearTransaction();
}

/// Defines the external browser handoff used to start Aquari authorization.
abstract interface class AquariAuthorizationLauncher {
  /// Opens the supplied Aquari authorization URL in the platform system browser.
  Future<void> launch(Uri url);
}

/// Opens an Aquari authorization URL in the platform system browser.
final class ExternalAquariAuthorizationLauncher
    implements AquariAuthorizationLauncher {
  /// Creates the default Flutter authorization launcher that opens the platform system browser.
  const ExternalAquariAuthorizationLauncher();

  /// Opens the supplied Aquari authorization URL in the platform system browser.
  @override
  Future<void> launch(Uri url) async {
    final bool launched = await launchUrl(
      url,
      mode: LaunchMode.externalApplication,
    );
    if (!launched) {
      throw AquariTransportException(
        'Aquari could not launch the system browser.',
      );
    }
  }
}

/// Defines the deep-link source used to receive the Aquari authorization callback.
abstract interface class AquariCallbackSource {
  /// Returns the deep link that launched the Flutter application, if one is available.
  Future<Uri?> getInitialLink();

  /// Streams deep-link callback URIs received while the Flutter application is running.
  Stream<Uri> get linkStream;
}

/// Reads initial and streamed deep links through the Flutter app_links package.
final class AppLinksAquariCallbackSource implements AquariCallbackSource {
  /// Creates a callback source backed by app_links. Supply an AppLinks instance to reuse
  /// application-owned link state.
  AppLinksAquariCallbackSource([AppLinks? appLinks])
    : _appLinks = appLinks ?? AppLinks();

  final AppLinks _appLinks;

  /// Returns the deep link that launched the Flutter application, if one is available.
  @override
  Future<Uri?> getInitialLink() => _appLinks.getInitialLink();

  @override
  Stream<Uri> get linkStream => _appLinks.uriLinkStream;
}

/// Contains the current Aquari token set and subject-bound identity in Flutter.
final class AquariFlutterSession {
  /// Creates a Flutter session from a subject-bound token set and identity.
  const AquariFlutterSession({required this.tokens, required this.identity});

  final AquariTokenSet tokens;
  final AquariIdentity identity;
}

/// Coordinates system-browser authorization, protected session storage, refresh, and sign-out in
/// Flutter.
final class AquariFlutterClient {
  /// Creates a Flutter client from the core Aquari client, protected token and transaction stores,
  /// and a system-browser launcher.
  factory AquariFlutterClient({
    required AquariClient client,
    required AquariTokenStore tokenStore,
    required AquariAuthorizationTransactionStore transactionStore,
    AquariAuthorizationLauncher authorizationLauncher =
        const ExternalAquariAuthorizationLauncher(),
  }) {
    return AquariFlutterClient._(
      client,
      tokenStore,
      transactionStore,
      authorizationLauncher,
    );
  }

  AquariFlutterClient._(
    this._client,
    this._tokenStore,
    this._transactionStore,
    this._authorizationLauncher,
  );

  final AquariClient _client;
  final AquariTokenStore _tokenStore;
  final AquariAuthorizationTransactionStore _transactionStore;
  final AquariAuthorizationLauncher _authorizationLauncher;

  /// Creates and stores a pending Authorization Code transaction, then opens the Aquari authorization
  /// URL in the system browser.
  Future<void> beginAuthorization({AquariAuthorizationPrompt? prompt}) async {
    final AquariBeginAuthorizationResult result = await _client.auth.begin(
      prompt: prompt,
    );
    await _transactionStore.writeTransaction(result.transaction);
    await _authorizationLauncher.launch(result.url);
  }

  /// Completes the stored authorization transaction. The SDK validates callback state and issuer
  /// data, exchanges the code, validates the returned identity, stores the new token set, and clears
  /// pending transaction state.
  Future<AquariFlutterSession> completeAuthorization(Uri callback) async {
    final AquariAuthorizationTransaction transaction =
        await _transactionStore.readTransaction() ??
        (throw AquariOAuthException(
          'missing_transaction',
          'Aquari cannot complete authorization because the initiating transaction is unavailable.',
        ));

    try {
      final AquariAuthorizationResult result = await _client.auth.complete(
        callback,
        transaction,
      );
      await _tokenStore.writeTokens(result.tokens);
      return AquariFlutterSession(
        tokens: result.tokens,
        identity: result.identity,
      );
    } finally {
      await _transactionStore.clearTransaction();
    }
  }

  /// Restores session state from protected storage and resolves Aquari UserInfo for the stored token
  /// set. This operation does not refresh an expired token automatically; call refreshSession when a
  /// refresh is required.
  Future<AquariFlutterSession?> restoreSession() async {
    final AquariTokenSet? tokens = await _tokenStore.readTokens();
    if (tokens == null) {
      return null;
    }
    final AquariIdentity identity = await _client.auth.userInfo(tokens);
    return AquariFlutterSession(tokens: tokens, identity: identity);
  }

  /// Refreshes the stored Aquari session, replaces the token set, resolves UserInfo, and preserves
  /// subject continuity.
  Future<AquariFlutterSession> refreshSession() async {
    final AquariTokenSet current =
        await _tokenStore.readTokens() ??
        (throw AquariOAuthException(
          'missing_session',
          'Aquari cannot refresh because no stored session exists.',
        ));

    final AquariTokenSet refreshed = await _client.auth.refresh(current);
    await _tokenStore.writeTokens(refreshed);
    final AquariIdentity identity = await _client.auth.userInfo(refreshed);
    return AquariFlutterSession(tokens: refreshed, identity: identity);
  }

  /// Clears local Aquari session and pending authorization state. This operation does not grant or
  /// revoke application permissions.
  Future<void> signOut() async {
    await _transactionStore.clearTransaction();
    await _tokenStore.clearTokens();
  }
}
