# Raywonder HFS fleet integration

## Repository and release lanes

- Gitea target: `raywonder/hfs.git` through the configured
  `git-gitea-raywonder` SSH host.
- GitHub mirror: `https://github.com/Raywonder/hfs.git`.
- Upstream: `https://github.com/rejetto/hfs.git`.
- Stable fork branch: `main` (currently HFS 3.2.2 plus local plugins).
- Candidate branch: `integration/upstream-3.3-rc6-20260904`.
- Rollback branch: `backup/pre-upstream-3.3-20260904`.

Do not deploy the candidate branch until build, API tests, and platform smoke
tests pass on Windows, macOS, and Linux.

## Client contract

OpenClaw, AccessClaw, and Indigenous clients discover node capabilities through
the `fleet-bridge` plugin, then use HFS native endpoints for files. HFS remains
the authorization decision point. Authelia supplies browser SSO at the reverse
proxy; LDAP-backed identities are mapped into HFS only through the approved HFS
authentication plugins.

Suggested client scopes are `files.read`, `files.write`, `links.create`,
`media.read`, and `fleet.admin`. A client surface receives only the scopes its
user and device need. TVs, radios, remotes, and embedded menus should normally
receive read-only media capabilities.

## Plugin synchronization invariant

Only plugin program files are eligible for mirroring. The sync manifest records
plugin name, source repository, immutable revision, relative file names,
checksums, and platform constraints. A receiving HFS stages and validates a
bundle before installation. Missing plugins are installed disabled; existing
plugins are replaced only when the manifest revision is newer and the local
code is unmodified.

Never mirror or overwrite `config.yaml`, accounts, VFS entries, secrets,
plugin configuration, plugin storage, link databases, or user content. If a
checksum differs without a known revision, report drift and stop.

## Relay invariant

Public relay nodes expose only explicit VFS mappings and HFS-authenticated share
links. They must not become general-purpose HTTP or filesystem proxies. Peer
origins are allowlisted by stable Headscale identity, TLS is required on public
edges, and every relay request remains subject to the source node's HFS access
decision. Relay credentials are stored in the node secret store, never inside
the plugin bundle or repository.
