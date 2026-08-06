"use strict"

exports.version = 1.0
exports.description = "Bridge trusted Authelia/forward-auth identity headers to HFS sessions."
exports.apiRequired = 12.3
exports.repo = "Raywonder/hfs"

const PLUGIN_ID = "authelia-sso"

exports.config = {
    enabled: { type: "boolean", defaultValue: true, label: "Enable SSO bridge" },
    protectedPaths: {
        type: "string",
        defaultValue: "/~/admin/",
        label: "Protected path prefixes",
        helperText: "Comma-separated HFS URL prefixes. Leave empty to only link an already-authenticated SSO user.",
    },
    loginUrl: {
        type: "string",
        defaultValue: "",
        label: "Authelia login URL",
        helperText: "Use the existing server route, for example https://openlink.example/api/auth/authelia/login. If empty, AUTH_LOGIN_URL/AUTH_PORTAL_URL or the standard auth portal is used. The current URL is added as rd.",
    },
    trustedProxyNetworks: {
        type: "string",
        defaultValue: "127.0.0.1,::1,100.64.0.2",
        label: "Trusted proxy networks",
        helperText: "Only requests from these proxy addresses may supply Remote-User/Remote-Groups headers.",
    },
    autoProvision: { type: "boolean", defaultValue: true, label: "Create HFS accounts for SSO users" },
    adminGroups: {
        type: "string",
        defaultValue: "admins,admin,wheel,sudo",
        label: "Authelia admin groups",
        helperText: "Matching groups may access the HFS admin panel. Keep this narrow.",
    },
    accountPrefix: {
        type: "string",
        defaultValue: "authelia-",
        label: "Provisioned account prefix",
        helperText: "Prevents an SSO name from colliding with a local HFS account.",
    },
    requireExternalAuth: {
        type: "boolean",
        defaultValue: true,
        label: "Require SSO on protected paths",
        helperText: "When enabled, unauthenticated protected requests redirect to loginUrl or return 401.",
    },
    _identityHeader: {
        type: "string",
        defaultValue: "Remote-User",
        label: "Identity header",
        helperText: "Advanced: normally Remote-User; this value is not exposed in exports without passwords.",
    },
}

exports.init = api => {
    const { setLoggedIn } = api.require("./auth")
    const { netMatches } = api.misc

    function cfg(name) { return api.getConfig(name) }
    function list(value) {
        return String(value || "").split(",").map(x => x.trim()).filter(Boolean)
    }
    function trusted(ctx) {
        const masks = list(cfg("trustedProxyNetworks"))
        return masks.some(mask => {
            try { return netMatches(ctx.ip, mask, true) }
            catch { return false }
        })
    }
    function safePart(value) {
        return String(value || "").trim().replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80)
    }
    function prefix() {
        const value = String(cfg("accountPrefix") || "").trim().replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 30)
        return value || "authelia-"
    }
    function accountName(user) {
        return `${prefix()}${safePart(user) || "user"}`
    }
    function groupName(group) {
        return `${prefix()}group-${safePart(group) || "default"}`
    }
    function isAdminGroup(groups) {
        const admins = new Set(list(cfg("adminGroups")).map(x => x.toLowerCase()))
        return groups.some(x => admins.has(String(x).toLowerCase()))
    }
    function identity(ctx) {
        if (!trusted(ctx)) return
        const header = String(cfg("_identityHeader") || "Remote-User").toLowerCase()
        const user = String(ctx.get(header) || "").trim()
        if (!user) return
        const groups = list(ctx.get("remote-groups"))
        return { user, groups, admin: isAdminGroup(groups) }
    }
    async function provision(id) {
        const username = accountName(id.user)
        let account = api.getAccount(username)
        if (!account) {
            if (!cfg("autoProvision")) return
            const belongs = id.groups.map(groupName)
            for (const group of belongs) {
                if (!api.getAccount(group))
                    await api.addAccount(group, { plugin: { id: PLUGIN_ID, auth: true, kind: "group" } })
            }
            account = await api.addAccount(username, {
                belongs,
                admin: id.admin || undefined,
                plugin: { id: PLUGIN_ID, auth: true, provider: "authelia", subject: id.user },
            })
        } else if (account.plugin?.id === PLUGIN_ID) {
            const belongs = id.groups.map(groupName)
            for (const group of belongs) {
                if (!api.getAccount(group))
                    await api.addAccount(group, { plugin: { id: PLUGIN_ID, auth: true, kind: "group" } })
            }
            api.updateAccount(account, { belongs, admin: id.admin || undefined })
        }
        return account
    }
    function protectedPath(ctx) {
        const path = ctx.path || "/"
        return list(cfg("protectedPaths")).some(prefix => prefix === "/" || path.startsWith(prefix))
    }
    function redirectToLogin(ctx) {
        const loginUrl = String(cfg("loginUrl") || process.env.AUTH_LOGIN_URL || process.env.AUTH_PORTAL_URL || "https://auth.devinecreations.net/").trim()
        if (!loginUrl) return false
        try {
            const url = new URL(loginUrl)
            const protocol = String(ctx.get("x-forwarded-proto") || ctx.protocol || "https").split(",")[0].trim()
            url.searchParams.set("rd", `${protocol}://${ctx.host}${ctx.originalUrl}`)
            ctx.redirect(url.href)
            return true
        } catch {
            api.log("Invalid Authelia loginUrl; refusing redirect")
            return false
        }
    }

    const onRequest = async ({ ctx }) => {
        if (!cfg("enabled")) return
        const id = identity(ctx)
        if (id) {
            const account = await provision(id)
            if (account && account.plugin?.id === PLUGIN_ID && ctx.session)
                await setLoggedIn(ctx, account.username)
            else if (cfg("requireExternalAuth") && protectedPath(ctx)) {
                ctx.status = 403
                ctx.body = "Authelia identity is not provisioned for HFS"
                return api.events.stop
            }
            return
        }
        if (!cfg("requireExternalAuth") || !protectedPath(ctx) || ctx.state.account) return
        if (ctx.path.startsWith("/api/") || ctx.method !== "GET") {
            ctx.status = 401
            ctx.body = "Authelia authentication required"
        } else if (!redirectToLogin(ctx)) {
            ctx.status = 401
            ctx.body = "Authelia authentication required"
        }
        return api.events.stop
    }

    return {
        unload: api.events.on("request", onRequest),
        customApi: {
            autheliaSsoStatus() {
                return { enabled: Boolean(cfg("enabled")), protectedPaths: list(cfg("protectedPaths")) }
            },
        },
    }
}
