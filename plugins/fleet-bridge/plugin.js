// Fleet integration bridge for OpenClaw, AccessClaw, and Indigenous clients.
// GPL-3.0-or-later; designed for HFS 3 plugin API.

exports.version = 1
exports.apiRequired = 8
exports.description = 'Authenticated capability discovery for the Raywonder HFS fleet'
exports.repo = 'raywonder/hfs'

exports.config = {
    fleetId: { type: 'string', defaultValue: 'raywonder-hfs', label: 'Fleet identifier' },
    nodeId: { type: 'string', defaultValue: '', label: 'Stable node identifier' },
    publicBaseUrl: { type: 'string', defaultValue: '', label: 'Public HFS URL' },
    requireLogin: { type: 'boolean', defaultValue: true, label: 'Require an HFS login' },
    exposeTransfers: { type: 'boolean', defaultValue: true, label: 'Advertise native file transfers' },
    exposeLinks: { type: 'boolean', defaultValue: true, label: 'Advertise link sharing' },
    exposeMedia: { type: 'boolean', defaultValue: true, label: 'Advertise media features' },
    exposeAgentApi: { type: 'boolean', defaultValue: true, label: 'Advertise agent integration' },
}

exports.init = api => {
    const cfg = key => api.getConfig(key)

    function capabilities(ctx) {
        if (cfg('requireLogin') && !ctx?.state?.account)
            throw 401
        return {
            schema: 1,
            fleet: String(cfg('fleetId') || ''),
            node: String(cfg('nodeId') || ''),
            baseUrl: String(cfg('publicBaseUrl') || ''),
            authenticated: Boolean(ctx?.state?.account),
            principal: ctx?.state?.account?.username || null,
            features: {
                files: Boolean(cfg('exposeTransfers')),
                links: Boolean(cfg('exposeLinks')),
                media: Boolean(cfg('exposeMedia')),
                agents: Boolean(cfg('exposeAgentApi')),
                pluginCodeSync: true,
                configSync: false,
            },
            invariants: {
                preserveAccounts: true,
                preserveVfs: true,
                preservePluginConfig: true,
                preservePluginStorage: true,
            },
        }
    }

    return {
        customRest: {
            fleetCapabilities(_params, ctx) {
                return capabilities(ctx)
            },
        },
        customApi: {
            fleetCapabilities(ctx) {
                return capabilities(ctx)
            },
        },
    }
}
