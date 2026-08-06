# HFS passkey plugin

This plugin adds WebAuthn passkey sign-in for existing HFS accounts.

- A user must already be signed in to enroll a passkey.
- The login button supports both a typed username and discoverable passkeys.
- Credentials and counters are stored in the plugin database, not in exported HFS account data.
- HFS VFS permissions, private-link behavior, and account administration remain unchanged.
- Set `rpId` and `origins` to the public HTTPS domain when HFS is behind a reverse proxy. Do not use an internal host or an HTTP origin.

The plugin intentionally does not create accounts, allow anonymous enrollment, or turn a passkey into a file-sharing token.
