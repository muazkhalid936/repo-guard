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
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "RepoGuard")
        image?.isTemplate = !threat
        button.image = image
        button.contentTintColor = threat ? .systemRed : nil
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
    render("7-dashboard-dark", sampleModel(threats: false), .dashboard, dark: true)
    render("8-not-protected", sampleModel(threats: false, failed: true), .dashboard)
}

let app = NSApplication.shared
if let dir = env["REPOGUARD_SNAPSHOT"] {
    app.setActivationPolicy(.accessory)
    writeSnapshots(to: dir)
    exit(0)
}
let delegate = AppDelegate()
app.setActivationPolicy(delegate.background ? .accessory : .regular)
app.delegate = delegate
app.run()
