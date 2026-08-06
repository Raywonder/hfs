"use strict"

const fs = require("node:fs")
const path = require("node:path")
const { spawn } = require("node:child_process")

exports.version = 1.0
exports.description = "Manage a safe rclone mount for HFS, including rclone SMB remotes."
exports.apiRequired = 12.3
exports.repo = "Raywonder/hfs"

exports.config = {
    enabled: { type: "boolean", defaultValue: true, label: "Enable rclone mount" },
    autoStart: { type: "boolean", defaultValue: false, label: "Start mount with HFS" },
    rclonePath: { type: "string", defaultValue: "rclone", label: "rclone executable" },
    remoteName: {
        type: "string",
        defaultValue: "",
        label: "rclone remote name",
        helperText: "The remote must already exist in rclone.conf. For SMB, configure an rclone SMB remote there.",
    },
    remotePath: { type: "string", defaultValue: "", label: "Remote path" },
    mountPath: {
        type: "real_path",
        folders: true,
        files: false,
        defaultPath: ".",
        label: "Local mount path",
        helperText: "After mounting, add this folder to the HFS VFS as a shared root.",
    },
    _rcloneConfig: {
        type: "real_path",
        folders: false,
        files: true,
        label: "rclone config file",
        helperText: "Optional. Keep SMB credentials in this file, never in HFS plugin config.",
    },
    readOnly: { type: "boolean", defaultValue: true, label: "Read-only mount" },
    vfsCacheMode: {
        type: "select",
        options: { "Off": "off", "Minimal": "minimal", "Writes": "writes", "Full": "full" },
        defaultValue: "full",
        label: "VFS cache mode",
    },
    dirCacheTime: { type: "number", min: 0, max: 86400, defaultValue: 60, label: "Directory cache seconds" },
    pollInterval: { type: "number", min: 0, max: 3600, defaultValue: 60, label: "Remote poll seconds" },
}

exports.init = api => {
    let child
    let state = { running: false, pid: null, lastExit: null, error: null, mountPath: null }
    const cfg = name => api.getConfig(name)
    const { ctxAdminAccess } = api.require("./adminApis")

    function status() {
        return { ...state, configured: Boolean(cfg("remoteName") && cfg("mountPath")) }
    }
    function assertAdmin(ctx) {
        if (!ctxAdminAccess(ctx)) throw 403
    }
    function executable() {
        const configured = String(cfg("rclonePath") || "").trim()
        if (configured) return configured
        const candidates = process.platform === "win32"
            ? [path.join(process.cwd(), "rclone.exe"), "rclone.exe"]
            : ["/usr/local/bin/rclone", "/opt/homebrew/bin/rclone", "rclone"]
        return candidates.find(candidate => candidate === "rclone" || fs.existsSync(candidate)) || candidates[0]
    }
    function args() {
        const remote = String(cfg("remoteName") || "").trim()
        const remotePath = String(cfg("remotePath") || "").replace(/^\/+/, "")
        if (!/^[a-zA-Z0-9._-]+$/.test(remote)) throw Error("Invalid rclone remote name")
        if (!remotePath.split(/[\\/]+/).every(part => part !== ".."))
            throw Error("Remote path must not contain '..'")
        const configuredMount = String(cfg("mountPath") || "").trim()
        if (!configuredMount) throw Error("A local mount path is required")
        const mount = path.resolve(configuredMount)
        if (!mount || mount === path.parse(mount).root) throw Error("Refusing to mount at a filesystem root")
        const result = ["mount", `${remote}:${remotePath}`, mount,
            "--vfs-cache-mode", String(cfg("vfsCacheMode") || "full"),
            "--dir-cache-time", `${Math.max(0, Number(cfg("dirCacheTime")) || 0)}s`,
            "--poll-interval", `${Math.max(0, Number(cfg("pollInterval")) || 0)}s`,
            "--log-level", "ERROR"]
        const configFile = String(cfg("_rcloneConfig") || "").trim()
        if (configFile) result.push("--config", path.resolve(configFile))
        if (cfg("readOnly")) result.push("--read-only")
        return { result, mount }
    }
    function start() {
        if (child) return status()
        if (!cfg("enabled")) throw Error("rclone plugin is disabled")
        const built = args()
        fs.mkdirSync(built.mount, { recursive: true })
        state = { ...state, running: false, pid: null, error: null, mountPath: built.mount }
        child = spawn(executable(), built.result, { stdio: ["ignore", "ignore", "pipe"], windowsHide: true })
        state = { ...state, running: true, pid: child.pid }
        child.stderr.on("data", data => { state.error = String(data).trim().slice(-1000); api.log("rclone:", state.error) })
        child.once("error", error => { state.error = error.message; state.running = false; child = undefined })
        child.once("exit", (code, signal) => {
            state = { ...state, running: false, pid: null, lastExit: { code, signal }, error: state.error }
            child = undefined
        })
        return status()
    }
    function stop() {
        if (!child) return status()
        child.kill()
        return status()
    }
    if (cfg("autoStart")) {
        try { start() } catch (error) { state.error = error.message; api.log("rclone mount not started:", error.message) }
    }
    return {
        customRest: {
            rcloneStatus({}, ctx) { assertAdmin(ctx); return status() },
            rcloneStart({}, ctx) { assertAdmin(ctx); return start() },
            rcloneStop({}, ctx) { assertAdmin(ctx); return stop() },
        },
        customApi: { rcloneStatus: status },
        unload() { stop() },
    }
}
