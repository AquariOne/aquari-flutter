# Aquari One Flutter SDK

`aquari_one` is the official Aquari One public-client SDK for Flutter.

## Capabilities

- system-browser Authorization Code with S256 PKCE;
- OpenID Connect discovery and RS256 ID-token validation;
- UserInfo and refresh-token rotation;
- connected Passport, Passport signals, public Passport, and trust reads;
- app/deep-link callback handling;
- protected token and pending-authorization storage integration.

## Security boundary

Flutter applications are public OAuth clients. Do not put a confidential client secret, machine API key, privileged issuer credential, or developer-control-plane credential in a distributable application.

Use the operating-system browser for authorization and protected platform storage for session state.

Aquari authenticates the person and exposes portable Passport and trust data. The consuming application decides its own local roles and permissions.

## Documentation

See `https://docs.aquari.one/sdks/flutter` for the integration guide and API reference.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

Source repository (GitLab, authoritative): https://gitlab.com/nousen-group/aquari/aquari-flutter
GitHub read-only mirror: https://github.com/AquariOne/aquari-flutter

The public SDK source is exported from Aquari One’s private monorepo. Contributions and release decisions are managed on GitLab; do not push directly to the GitHub mirror.
