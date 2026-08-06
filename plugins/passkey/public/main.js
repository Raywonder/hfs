"use strict"; {
    const HFS = window.HFS

    const b64ToBytes = value => {
        const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(value).length + 3) % 4)
        return Uint8Array.from(atob(normalized), c => c.charCodeAt(0))
    }
    const bytesToB64 = value => {
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : value
        let binary = ""
        for (const byte of bytes) binary += String.fromCharCode(byte)
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
    }
    const creationOptions = options => {
        const publicKey = { ...options, challenge: b64ToBytes(options.challenge), user: { ...options.user, id: b64ToBytes(options.user.id) } }
        if (publicKey.excludeCredentials)
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(x => ({ ...x, id: b64ToBytes(x.id) }))
        return publicKey
    }
    const requestOptions = options => ({
        ...options,
        challenge: b64ToBytes(options.challenge),
        allowCredentials: options.allowCredentials?.map(x => ({ ...x, id: b64ToBytes(x.id) })),
    })
    const registrationResponse = credential => ({
        id: credential.id,
        rawId: bytesToB64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bytesToB64(credential.response.clientDataJSON),
            attestationObject: bytesToB64(credential.response.attestationObject),
            transports: credential.response.getTransports?.(),
        },
        clientExtensionResults: credential.getClientExtensionResults?.() || {},
    })
    const authenticationResponse = credential => ({
        id: credential.id,
        rawId: bytesToB64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: bytesToB64(credential.response.clientDataJSON),
            authenticatorData: bytesToB64(credential.response.authenticatorData),
            signature: bytesToB64(credential.response.signature),
            userHandle: credential.response.userHandle ? bytesToB64(credential.response.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults?.() || {},
    })
    const alert = error => HFS.dialogLib.alertDialog(error?.message || String(error), "error")

    async function enroll() {
        try {
            if (!window.PublicKeyCredential) throw Error("This browser does not support passkeys")
            const options = await HFS.customRestCall("passkeyRegisterOptions")
            const credential = await navigator.credentials.create({ publicKey: creationOptions(options) })
            if (!credential) return
            await HFS.customRestCall("passkeyRegister", { response: registrationResponse(credential) })
            HFS.toast("Passkey added", "success")
        } catch (error) { alert(error) }
    }

    async function login() {
        try {
            if (!window.PublicKeyCredential) throw Error("This browser does not support passkeys")
            const form = document.querySelector(".login-dialog form")
            const username = form?.querySelector("#login_username")?.value?.trim() || ""
            const options = await HFS.customRestCall("passkeyAuthenticationOptions", { username })
            const credential = await navigator.credentials.get({ publicKey: requestOptions(options) })
            if (!credential) return
            await HFS.customRestCall("passkeyAuthenticate", { response: authenticationResponse(credential), username })
            HFS.toast("Logged in", "success")
            location.reload()
        } catch (error) { alert(error) }
    }

    HFS.onEvent("beforeLoginSubmit", () => HFS.h("div", { className: "passkey-login" },
        HFS.h(HFS.Btn, { icon: "key", label: "Use a passkey", onClick: login, onClickAnimation: false })))
    HFS.onEvent("userPanelAfterInfo", () => HFS.h(HFS.Btn, {
        icon: "key", label: "Add a passkey", onClick: enroll, onClickAnimation: false,
    }))
}
