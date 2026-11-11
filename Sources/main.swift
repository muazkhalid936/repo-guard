import AppKit
import SwiftUI

// RepoGuard: a window for managing it, a menu bar icon that keeps protection running.

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    let model = AppModel()
    let nav = Navigation()
    let background = CommandLine.arguments.contains("--background") || testMode
    var statusItem: NSStatusItem?
    var window: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !testMode, let id = Bundle.main.bundleIdentifier {
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: id).filter { $0 != NSRunningApplication.current }
            if let first = others.first {
                first.activate(options: [])
                NSApp.terminate(nil)
                return
            }
        }
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        statusItem?.menu = menu
        updateIcon()
        if !testMode {
            if !UserDefaults.standard.bool(forKey: "loginConfigured") {
                model.setLaunchAtLogin(true)
                UserDefaults.standard.set(true, forKey: "loginConfigured")
            } else if model.launchAtLogin {
                model.setLaunchAtLogin(true) // keep the login entry pointing at this copy of the app
            }
        }
        NSApp.mainMenu = buildMainMenu()
        model.onChange = { [weak self] in self?.updateIcon() }
        model.onNewThreats = { [weak self] found in self?.alert(found) }
        model.start()
        GitHubWatcher.shared.onNewThreats = { [weak self] found, fixed in self?.alertGitHub(found, fixed) }
        GitHubWatcher.shared.start()
        MacStore.shared.onNewThreats = { [weak self] found in self?.alertMac(found) }
        MacStore.shared.start()
        // Setup can't be skipped, even when launched quietly at login.
        if !background || !model.setupDone { showWindow() }
    }

    // Opening the app from Finder or the Dock while it's already running.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return true
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        if !background && window?.isVisible != true && NSApp.activationPolicy() == .accessory { showWindow() }
    }

    // Protection keeps running after the window closes.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func windowWillClose(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
    }

    @objc func showWindow() {
        NSApp.setActivationPolicy(.regular)
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 680),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                             backing: .buffered, defer: false)
            w.title = "RepoGuard"
            w.titlebarAppearsTransparent = true
            w.isReleasedWhenClosed = false
            w.delegate = self
            w.contentView = NSHostingView(rootView: RootView(model: model, nav: nav))
            w.center()
            w.setFrameAutosaveName("RepoGuardMain")
            window = w
        }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func buildMainMenu() -> NSMenu {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "Hide RepoGuard", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit RepoGuard", action: #selector(quit), keyEquivalent: "q").target = self
        appItem.submenu = appMenu
        let windowItem = NSMenuItem()
        main.addItem(windowItem)
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Close", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowItem.submenu = windowMenu
        return main
    }

    // MARK: menu bar

    func updateIcon() {
        guard let button = statusItem?.button else { return }
        let threat = !model.active.isEmpty
        let name = threat ? "exclamationmark.shield.fill" : (model.lastError != nil ? "shield.slash" : "checkmark.shield")
        var image = NSImage(systemSymbolName: name, accessibilityDescription: "RepoGuard")
        if threat {
            // white mark on a red shield: readable on light and dark menu bars and over any wallpaper
            image = image?.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [.white, .systemRed]))
            image?.isTemplate = false
        } else {
            image?.isTemplate = true  // follows the menu bar: black on light, white on dark
        }
        button.image = image
        button.contentTintColor = nil
        button.title = threat ? " \(model.active.count)" : ""
        button.toolTip = threat ? "RepoGuard: \(model.active.count) threats" : (model.lastError != nil ? "RepoGuard: not protected" : "RepoGuard: all clear")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let title: String
        if let e = model.lastError { title = "Not protected: \(e)" }
        else if !model.active.isEmpty { title = "\(model.active.count) threat\(model.active.count == 1 ? "" : "s") found" }
        else { title = model.scanning ? "Scanning…" : "All clear" }
        let header = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        header.isEnabled = false
        menu.addItem(header)
        let seen = NSMenuItem(title: "Last scan: \(relativeTime(model.lastScan))", action: nil, keyEquivalent: "")
        seen.isEnabled = false
        menu.addItem(seen)
        menu.addItem(.separator())
        if !model.active.isEmpty { menu.addItem(item("Review Threats…", #selector(showThreats), "")) }
        menu.addItem(item("Open RepoGuard", #selector(showWindow), "o"))
        menu.addItem(item("Scan Now", #selector(scanNow), "r"))
        menu.addItem(.separator())
        menu.addItem(item("Quit RepoGuard", #selector(quit), "q"))
    }

    func item(_ title: String, _ selector: Selector, _ key: String) -> NSMenuItem {
        let i = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        i.target = self
        return i
    }

    @objc func showThreats() { nav.screen = .threats; showWindow() }
    @objc func scanNow() { model.scanNow() }
    @objc func quit() { NSApp.terminate(nil) }

    func alertGitHub(_ found: [GHFinding], _ fixed: [GHFix]) {
        model.refreshActivity()
        if testMode || !model.popupsEnabled { return }
        NSSound(named: "Basso")?.play()
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        let fixedSet = Set(fixed.map { "\($0.repo)|\($0.branch)" })
        a.messageText = fixed.isEmpty ? "Malware pushed to GitHub" : "Malware pushed to GitHub and removed"
        a.informativeText = found.prefix(6).map { f in
            "• \(f.repo) · \(f.branch)\n   \(f.files.prefix(3).joined(separator: ", "))" + (fixedSet.contains(f.id) ? "\n   Removed with a cleanup commit." : "")
        }.joined(separator: "\n") + "\n\nSomeone with access to your GitHub pushed this. Don't pull these branches until they're clean, and check which tokens or machines can push."
        a.addButton(withTitle: "Review")
        a.addButton(withTitle: "Dismiss")
        if a.runModal() == .alertFirstButtonReturn { showThreats() }
    }

    func alertMac(_ found: [ServerFinding]) {
        if testMode || !model.popupsEnabled { return }
        NSSound(named: "Basso")?.play()
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = "Malware found on this Mac"
        a.informativeText = found.prefix(5).map { "• \($0.detail)" }.joined(separator: "\n") + "\n\nOpen This Mac to remove it. Everything removed is backed up first."
        a.addButton(withTitle: "Open This Mac")
        a.addButton(withTitle: "Dismiss")
        if a.runModal() == .alertFirstButtonReturn { nav.screen = .mac; showWindow() }
    }

    func alert(_ found: [Finding]) {
        if testMode || !model.popupsEnabled { return }
        NSSound(named: "Basso")?.play()
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = "Malware warning: suspicious code found"
        let lines = found.prefix(6).map { "• \($0.repoName)/\($0.path)\n   \($0.label)" }.joined(separator: "\n")
        let more = found.count > 6 ? "\n…and \(found.count - 6) more." : ""
        a.informativeText = "\(lines)\(more)\n\nDon't open this project in VS Code, run npm commands, or click Pull or Merge. RepoGuard hasn't run any of this code."
        a.addButton(withTitle: "Review Threats")
        a.addButton(withTitle: "Dismiss")
        if a.runModal() == .alertFirstButtonReturn { showThreats() }
    }
}

// MARK: snapshots, used to check the design without showing a window

func writeSnapshots(to dir: String) {
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    func sampleModel(threats: Bool, failed: Bool = false) -> AppModel {
        let m = AppModel()
        m.watchDirs = ["\(home)/Documents/github"]
        m.setupDone = true
        m.loaded = true
        m.lastScan = Date()
        m.filesChecked = 3303
        let cal = Calendar.current
        m.daily = (0..<14).flatMap { i -> [DayStat] in
            let d = cal.date(byAdding: .day, value: i - 13, to: cal.startOfDay(for: Date()))!
            return [DayStat(day: d, kind: "Found", count: threats ? [0,0,3,1,0,5,2,0,0,8,4,1,0,2][i] : 0),
                    DayStat(day: d, kind: "Removed", count: threats ? [0,0,1,1,0,4,2,0,0,6,4,0,0,1][i] : [0,0,1,0,0,2,0,0,0,3,0,0,0,0][i])]
        }
        m.lastError = failed ? "RepoGuard can't read this folder. Allow access in System Settings." : nil
        m.repos = [RepoInfo(path: "\(home)/Documents/github/shop-app", branch: "main", branches: 2, threats: threats ? 2 : 0),
                   RepoInfo(path: "\(home)/Documents/github/ask-biz", branch: "main", branches: 2, threats: 0),
                   RepoInfo(path: "\(home)/Documents/github/acme/acme-web", branch: "main", branches: 4, threats: threats ? 1 : 0),
                   RepoInfo(path: "\(home)/Documents/github/acme/acme-api", branch: "master", branches: 10, threats: 0)]
        m.activity = [LogEntry(id: 1, time: "2026-11-06 17:09:19", kind: .scan, text: "Scanned 3303 files in 4 repos, nothing new"),
                      LogEntry(id: 2, time: "2026-11-06 15:40:02", kind: .review, text: "shop-app .vscode/tasks.json: File that can run code automatically"),
                      LogEntry(id: 3, time: "2026-11-06 14:21:00", kind: .scan, text: "Scanned 3288 files in 4 repos, nothing new")]
        if threats {
            func f(_ repo: String, _ path: String, _ label: String, _ w: String) -> Finding {
                Finding(key: repo + path + label, root: "\(home)/Documents/github/\(repo)", path: path, rule: "x", label: label, where: w, time: "2026-11-06T17:12:44")
            }
            m.active = [f("shop-app", "postcss.config.mjs", "Code hidden far off-screen", "branch:refs/remotes/origin/main"),
                        f("shop-app", ".vscode/tasks.json", "Runs automatically when the folder opens", "folder"),
                        f("acme/acme-web", "public/fonts/fa-brand-400.orc", "Fake font payload file (.orc)", "incoming:refs/remotes/origin/main")]
            m.activity.insert(LogEntry(id: 0, time: "2026-11-06 17:12:44", kind: .threat, text: "shop-app postcss.config.mjs: Code hidden far off-screen"), at: 0)
            m.reviews = [ReviewItem(root: "\(home)/Documents/github/shop-app", path: "origin/main", label: "Branch history was rewritten (force-push)", where: "x", time: nil)]
        }
        return m
    }
    func render(_ name: String, _ model: AppModel, _ screen: Screen, dark: Bool = false) {
        let nav = Navigation()
        nav.screen = screen
        let host = NSHostingView(rootView: RootView(model: model, nav: nav))
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 680), styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        w.titlebarAppearsTransparent = true
        w.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
        w.contentView = host
        w.layoutIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.8))
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        if let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: "\(dir)/\(name).png"))
        }
    }
    let empty = sampleModel(threats: false); empty.setupDone = false; empty.watchDirs = []
    render("0-welcome-empty", empty, .dashboard)
    let chosen = sampleModel(threats: false); chosen.setupDone = false
    chosen.watchDirs = ["\(home)/Documents/github", "\(home)/Projects/client-work"]
    render("0-welcome-chosen", chosen, .dashboard)
    let many = sampleModel(threats: false); many.watchDirs = ["\(home)/Documents/github", "\(home)/Projects/client-work"]
    render("9-settings-folders", many, .settings)
    render("1-dashboard-clear", sampleModel(threats: false), .dashboard)
    render("2-dashboard-threats", sampleModel(threats: true), .dashboard)
    render("3-threats", sampleModel(threats: true), .threats)
    render("4-repositories", sampleModel(threats: true), .repositories)
    render("5-activity", sampleModel(threats: true), .activity)
    render("6-settings", sampleModel(threats: false), .settings)
    for (n, auth) in [("13-editor-ec2", AuthKind.ec2Connect), ("14-editor-password", AuthKind.password)] {
        var srv = Server(); srv.name = "Example - EC2"; srv.host = "203.0.113.10"; srv.user = "ubuntu"; srv.auth = auth
        srv.awsProfile = "default"; srv.awsRegion = "eu-north-1"; srv.instanceId = "i-0123456789abcdef0"
        let host = NSHostingView(rootView: ServerEditor(server: srv, store: serverStore))
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 640), styleMask: [.titled], backing: .buffered, defer: false)
        w.appearance = NSAppearance(named: .darkAqua); w.contentView = host; w.layoutIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.8))
        if let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try? rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: "\(dir)/\(n).png"))
        }
    }
    render("10-servers", sampleModel(threats: true), .servers)
    render("11-servers-dark", sampleModel(threats: true), .servers, dark: true)
    render("12-dashboard-threats-dark", sampleModel(threats: true), .dashboard, dark: true)
    render("7-dashboard-dark", sampleModel(threats: false), .dashboard, dark: true)
    render("8-not-protected", sampleModel(threats: false, failed: true), .dashboard)
}

// A closed SSH pipe must not kill the app; the write fails and the error is reported instead.
signal(SIGPIPE, SIG_IGN)

// Test hook: REPOGUARD_SERVER_TEST=scan|clean with a server JSON file runs the real SSH path and prints the report.
if let mode = env["REPOGUARD_SERVER_TEST"], let file = env["REPOGUARD_SERVER_FILE"],
   let d = FileManager.default.contents(atPath: file), let s = try? JSONDecoder().decode(Server.self, from: d) {
    if let pw = env["REPOGUARD_TEST_PASSWORD"] { Keychain.set(pw, for: "\(s.id).ssh") }
    let ids = (env["REPOGUARD_SERVER_IDS"] ?? "").split(separator: ",").map(String.init)
    let roots = s.roots.split(separator: " ").map(String.init)
    let args = (mode == "clean" ? ["clean", "--ids"] + ids : ["scan"]) + ["--roots"] + roots
    switch serverStore.runAgentForTest(s, args: args) {
    case .success(let r): print(String(data: (try? JSONEncoder().encode(r)) ?? Data(), encoding: .utf8) ?? "")
    case .failure(let e): print("ERROR: \(e.localizedDescription)")
    }
    if env["REPOGUARD_TEST_PASSWORD"] != nil { Keychain.delete("\(s.id).ssh") }
    exit(0)
}

let app = NSApplication.shared
// Design check: shows the server editor on screen and saves a screenshot of it.
if let out = env["REPOGUARD_EDITOR_PREVIEW"] {
    app.setActivationPolicy(.regular)
    var srv = Server(); srv.name = "Example - EC2"; srv.host = "203.0.113.10"; srv.user = "ubuntu"
    srv.auth = env["REPOGUARD_EDITOR_AUTH"] == "password" ? .password : .ec2Connect
    srv.awsProfile = "default"; srv.awsRegion = "eu-north-1"; srv.instanceId = "i-0123456789abcdef0"
    let w = NSWindow(contentRect: NSRect(x: 200, y: 100, width: 620, height: 820), styleMask: [.titled], backing: .buffered, defer: false)
    w.appearance = NSAppearance(named: env["REPOGUARD_EDITOR_LIGHT"] != nil ? .aqua : .darkAqua)
    w.contentView = NSHostingView(rootView: ServerEditor(server: srv, store: serverStore))
    w.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
        _ = runProcess("/usr/sbin/screencapture", ["-x", "-o", "-l", String(w.windowNumber), out])
        exit(0)
    }
    app.run()
}
if let dir = env["REPOGUARD_SNAPSHOT"] {
    app.setActivationPolicy(.accessory)
    writeSnapshots(to: dir)
    exit(0)
}
let delegate = AppDelegate()
app.setActivationPolicy(delegate.background ? .accessory : .regular)
app.delegate = delegate
app.run()
