# Fleet bridge

This HFS plugin publishes a small authenticated capability document for
OpenClaw agents, AccessClaw desktop/iOS, and Indigenous device surfaces.

It intentionally does not create a second file-transfer implementation.
Clients use HFS's native authenticated listing, upload, download, WebDAV, and
share-link APIs, retaining HFS VFS and account authorization at every request.

The plugin never synchronizes `config.yaml`, accounts, VFS entries, secrets,
plugin configuration, plugin storage, or share-link state. Fleet tooling may
mirror plugin code only after comparing a signed manifest and checksums.

The REST method is `fleetCapabilities`, called through HFS custom REST. Leave
`requireLogin` enabled on public instances.
