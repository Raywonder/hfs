# Raywonder HFS integrations

This directory contains two deliberately separate integrations:

It also contains the `passkey` authentication plugin, which adds WebAuthn
passkey login for existing HFS accounts without changing file permissions or
turning passkeys into share-link tokens.

## `authelia-sso`

This is an Authelia/forward-auth bridge, not a replacement for Authelia. Put
Authelia or the existing Divine Creations auth proxy in front of HFS. Configure
the proxy to pass `Remote-User`, `Remote-Groups`, `Remote-Name`, and
`Remote-Email`, then set `trustedProxyNetworks` to only the proxy's address or
network. Never trust those headers from a public client.

The plugin provisions HFS accounts with the `authelia-` prefix, maps groups,
and establishes an HFS session using HFS's supported session login routine.
Admin status is granted only for the explicitly configured admin groups.
Set `loginUrl` to the existing server route, such as the Divine Creations
`/api/auth/authelia/login` helper, when protected paths should redirect to SSO.
The admin path is protected by default, so an unconfigured HFS instance will
redirect to the auth portal before HFS can show its “Admin-panel only for
localhost” fallback. Configure `trustedProxyNetworks` to the exact address of
the reverse proxy (for the current Headscale layout, normally the server's
proxy address), not the whole Tailnet.

## `rclone-smb`

This plugin starts and stops an rclone mount using an argument array (never a
shell command). Configure an rclone remote separately, including SMB
credentials in the protected rclone config file. Then point `remoteName`,
`remotePath`, and `mountPath` at it, start the mount, and add `mountPath` to an
HFS VFS root. The plugin is read-only by default and its admin REST controls
require an HFS admin account.

The plugin does not store SMB passwords, create arbitrary remote commands, or
automatically expose a mounted path. The HFS VFS permission model remains the
final file access control.
