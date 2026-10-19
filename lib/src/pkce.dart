import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';

final class AquariPkcePair {
  const AquariPkcePair({
    required this.codeVerifier,
    required this.codeChallenge,
  });

  final String codeVerifier;
  final String codeChallenge;
}

final Random _secureRandom = Random.secure();

AquariPkcePair createAquariPkcePair() {
  final String verifier = createAquariSecureRandomValue(byteLength: 48);
  final List<int> digest = sha256.convert(ascii.encode(verifier)).bytes;
  return AquariPkcePair(
    codeVerifier: verifier,
    codeChallenge: base64UrlEncode(digest).replaceAll('=', ''),
  );
}

String createAquariSecureRandomValue({int byteLength = 32}) {
  final List<int> bytes = List<int>.generate(
    byteLength,
    (_) => _secureRandom.nextInt(256),
    growable: false,
  );
  return base64UrlEncode(bytes).replaceAll('=', '');
}
