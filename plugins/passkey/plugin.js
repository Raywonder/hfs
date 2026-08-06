"use strict"

const { createHash } = require("node:crypto")

exports.version = 1.0
exports.description = "Use WebAuthn passkeys to sign in to existing HFS accounts."
exports.apiRequired = 12.3
exports.repo = "Raywonder/hfs"
exports.frontend_js = "main.js"

exports.config = {
    enabled: { type: "boolean", defaultValue: true, label: "Enable passkeys" },
    rpId: {
        type: "string",
        defaultValue: "",
        label: "WebAuthn RP ID",
        helperText: "Leave empty to use the HTTPS hostname. Set this when a reverse proxy has a stable public domain.",
    },
    rpName: { type: "string", defaultValue: "HFS File Server", label: "WebAuthn service name" },
    origins: {
        type: "string",
        defaultValue: "",
        label: "Allowed origins",
        helperText: "Comma-separated HTTPS origins. Leave empty to allow only the current HTTPS origin.",
    },
    requireUserVerification: {
        type: "boolean",
        defaultValue: true,
        label: "Require user verification",
        helperText: "Require the passkey device to verify the user with a PIN, fingerprint, or equivalent.",
    },
}

exports.init = async api => {
    const { generateAuthenticationOptions, generateRegistrationOptions,
        verifyAuthenticationResponse, verifyRegistrationResponse } = require("@simplewebauthn/server")
    const { setLoggedIn } = api.require("./auth")
    const db = await api.openDb("passkeys.kv", { defaultPutDelay: 250, maxPutDelay: 2_000 })
    const challenges = new Map()
    const CHALLENGE_TTL = 2 * 60_000

    const cfg = name => api.getConfig(name)
    const now = () => Date.now()
    const list = value => String(value || "").split(",").map(x => x.trim()).filter(Boolean)

    function currentHost(ctx) {
        const forwarded = String(ctx.get("x-forwarded-host") || "").split(",")[0].trim()
        return (forwarded || ctx.host || "").replace(/^https?:\/\//i, "").split(":")[0].toLowerCase()
    }

    function rpId(ctx) {
        const configured = String(cfg("rpId") || "").trim().toLowerCase()
        return configured || currentHost(ctx)
    }

    function origin(ctx) {
        const proto = String(ctx.get("x-forwarded-proto") || ctx.protocol || "https").split(",")[0].trim()
        const host = String(ctx.get("x-forwarded-host") || ctx.host || "").split(",")[0].trim()
        return `${proto}://${host}`
    }

    function expectedOrigins(ctx) {
        const configured = list(cfg("origins"))
        return configured.length ? configured : [origin(ctx)]
    }

    function session(ctx) {
        if (!ctx.session) throw 500
        return ctx.session
    }

    function accountUsername(ctx) {
        return api.getCurrentUsername(ctx)
    }

    function keyForUser(username) { return `user:${username}` }
    function keyForCredential(id) { return `credential:${id}` }

    async function credentialsFor(username) {
        return (await db.get(keyForUser(username))) || []
    }

    async function findCredential(id) {
        return await db.get(keyForCredential(id))
    }

    function pruneChallenges() {
        const cutoff = now() - CHALLENGE_TTL
        for (const [key, rec] of challenges)
            if (rec.created < cutoff) challenges.delete(key)
    }

    function rememberChallenge(ctx, challenge, data) {
        pruneChallenges()
        challenges.set(challenge, { ...data, created: now() })
        session(ctx).passkeyChallenge = challenge
    }

    function takeChallenge(ctx, kind) {
        const challenge = session(ctx).passkeyChallenge
        delete session(ctx).passkeyChallenge
        pruneChallenges()
        const rec = challenge && challenges.get(challenge)
        if (challenge) challenges.delete(challenge)
        if (!rec || rec.kind !== kind || now() - rec.created > CHALLENGE_TTL)
            throw 401
        return { challenge, ...rec }
    }

    function requireEnabled() {
        if (!cfg("enabled")) throw 404
    }

    function requireAccount(ctx) {
        const username = accountUsername(ctx)
        const account = username && api.getAccount(username)
        if (!account || account.disabled) throw 401
        return account
    }

    async function registerOptions({}, ctx) {
        requireEnabled()
        const account = requireAccount(ctx)
        const existing = await credentialsFor(account.username)
        const options = await generateRegistrationOptions({
            rpName: String(cfg("rpName") || "HFS File Server"),
            rpID: rpId(ctx),
            userName: account.username,
            userDisplayName: account.username,
            userID: createHash("sha256").update(`hfs-passkey:${rpId(ctx)}:${account.username}`).digest(),
            attestationType: "none",
            excludeCredentials: existing.map(x => ({ id: x.credentialID, transports: x.transports })),
            authenticatorSelection: { residentKey: "preferred", userVerification: cfg("requireUserVerification") ? "required" : "preferred" },
        })
        rememberChallenge(ctx, options.challenge, { kind: "registration", username: account.username })
        return options
    }

    async function register({ response }, ctx) {
        requireEnabled()
        const rec = takeChallenge(ctx, "registration")
        const account = requireAccount(ctx)
        if (account.username !== rec.username || !response) throw 401
        const verified = await verifyRegistrationResponse({
            response,
            expectedChallenge: rec.challenge,
            expectedOrigin: expectedOrigins(ctx),
            expectedRPID: rpId(ctx),
            requireUserVerification: Boolean(cfg("requireUserVerification")),
        })
        if (!verified.verified || !verified.registrationInfo) throw 401
        const info = verified.registrationInfo
        const record = {
            username: account.username,
            credentialID: info.credentialID,
            publicKey: Buffer.from(info.credentialPublicKey).toString("base64url"),
            counter: info.counter,
            transports: response.response?.transports || undefined,
            created: new Date().toISOString(),
        }
        const existing = await credentialsFor(account.username)
        if (existing.some(x => x.credentialID === record.credentialID)) throw 409
        await db.put(keyForCredential(record.credentialID), record)
        await db.put(keyForUser(account.username), [...existing, record])
        return { username: account.username, credentialID: record.credentialID }
    }

    async function authenticationOptions({ username }, ctx) {
        requireEnabled()
        username = String(username || "").trim().toLowerCase()
        const account = username && api.getAccount(username)
        const existing = account ? await credentialsFor(account.username) : []
        const options = await generateAuthenticationOptions({
            rpID: rpId(ctx),
            allowCredentials: username ? existing.map(x => ({ id: x.credentialID, transports: x.transports })) : undefined,
            userVerification: cfg("requireUserVerification") ? "required" : "preferred",
        })
        rememberChallenge(ctx, options.challenge, { kind: "authentication", username: account?.username || undefined })
        return options
    }

    async function authenticate({ response, username }, ctx) {
        requireEnabled()
        const rec = takeChallenge(ctx, "authentication")
        if (!response?.id) throw 401
        const stored = await findCredential(String(response.id))
        if (!stored || (rec.username && stored.username !== rec.username)) throw 401
        const account = api.getAccount(stored.username)
        if (!account || account.disabled) throw 401
        const verified = await verifyAuthenticationResponse({
            response,
            expectedChallenge: rec.challenge,
            expectedOrigin: expectedOrigins(ctx),
            expectedRPID: rpId(ctx),
            authenticator: {
                credentialID: stored.credentialID,
                credentialPublicKey: Buffer.from(stored.publicKey, "base64url"),
                counter: stored.counter || 0,
                transports: stored.transports,
            },
            requireUserVerification: Boolean(cfg("requireUserVerification")),
        })
        if (!verified.verified) throw 401
        stored.counter = verified.authenticationInfo.newCounter
        await db.put(keyForCredential(stored.credentialID), stored)
        const users = await credentialsFor(stored.username)
        const index = users.findIndex(x => x.credentialID === stored.credentialID)
        if (index >= 0) {
            users[index] = stored
            await db.put(keyForUser(stored.username), users)
        }
        await setLoggedIn(ctx, stored.username)
        return { username: stored.username, redirect: account.redirect }
    }

    return {
        customRest: {
            passkeyRegisterOptions: registerOptions,
            passkeyRegister: register,
            passkeyAuthenticationOptions: authenticationOptions,
            passkeyAuthenticate: authenticate,
        },
        unload() {
            challenges.clear()
        },
    }
}
