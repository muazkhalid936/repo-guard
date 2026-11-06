import AppKit
import CoreServices
import Foundation

// RepoGuard: menu bar app that watches a folder and scans changes for repo malware.
// All detection lives in Resources/engine.py and Resources/rules.json.

struct Finding: Decodable {
    let key: String
    let root: String
    let path: String
    let label: String
    let `where`: String
}

struct ScanResult: Decodable {
    let new: [Finding]
    let active: [Finding]
    let files: Int
    let repos: Int
}

let env = ProcessInfo.processInfo.environment
let testMode = env["REPOGUARD_TEST"] != nil
let home = FileManager.default.homeDirectoryForCurrentUser.path
let watchDir = env["REPOGUARD_WATCH"] ?? "\(home)/Documents/github"
let supportDir = env["REPOGUARD_SUPPORT"] ?? "\(home)/Library/Application Support/RepoGuard"
let logFile = env["REPOGUARD_LOG"] ?? "\(home)/Library/Logs/RepoGuard.log"
let agentLabel = "local.repoguard.app"
let agentPath = "\(home)/Library/LaunchAgents/\(agentLabel).plist"

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let scanQueue = DispatchQueue(label: "repoguard.scan")
    let lock = NSLock()
    var pending = Set<String>()
    var debounce: DispatchWorkItem?
    var stream: FSEventStreamRef?
    var active: [Finding] = []
    var lastScan = "Starting…"
    var lastError: String?
    var scanning = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        if !testMode {
            let same = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
            if same.count > 1 { NSApp.terminate(nil); return }
        }
        try? FileManager.default.createDirectory(atPath: supportDir, withIntermediateDirectories: true)
        statusItem.menu = NSMenu()
        statusItem.menu?.delegate = self
        updateIcon()
        if !testMode && !UserDefaults.standard.bool(forKey: "loginConfigured") {
            setLaunchAtLogin(true)
            UserDefaults.standard.set(true, forKey: "loginConfigured")
        }
        startWatching()
        runEngine(mode: "full", paths: nil)
    }

    // MARK: watching

    func startWatching() {
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info = info else { return }
            let me = Unmanaged<AppDelegate>.fromOpaque(info).takeUnretainedValue()
            let array = unsafeBitCast(eventPaths, to: NSArray.self)
            var paths: [String] = []
            for i in 0..<count { if let p = array[i] as? String { paths.append(p) } }
            me.queue(paths)
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagNoDefer)
        stream = FSEventStreamCreate(kCFAllocatorDefault, callback, &context, [watchDir] as CFArray,
                                     FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 1.0, flags)
        if let stream = stream {
            FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
            FSEventStreamStart(stream)
        }
    }

    func queue(_ paths: [String]) {
        let skip = ["/node_modules/", "/.next/", "/.git/objects/", "/.git/logs/", "/.git/index", "/.git/lfs/"]
        let useful = paths.filter { p in !skip.contains { p.contains($0) } }
        if useful.isEmpty { return }
        lock.lock()
        pending.formUnion(useful)
        debounce?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.flush() }
        debounce = work
        lock.unlock()
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5, execute: work)
    }

    func flush() {
        lock.lock()
        let batch = Array(pending)
        pending.removeAll()
        lock.unlock()
        if !batch.isEmpty { runEngine(mode: "event", paths: batch) }
    }

    // MARK: scanning

    func runEngine(mode: String, paths: [String]?) {
        scanQueue.async { [weak self] in
            guard let self = self else { return }
            DispatchQueue.main.async { self.scanning = true; self.updateIcon() }
            let result = self.execute(mode: mode, paths: paths)
            DispatchQueue.main.async {
                self.scanning = false
                switch result {
                case .success(let r):
                    self.active = r.active
                    self.lastError = nil
                    let f = DateFormatter(); f.timeStyle = .short
                    self.lastScan = "Last scan \(f.string(from: Date())): \(r.files) files"
                    if !r.new.isEmpty { self.alert(r.new) }
                case .failure(let e):
                    self.lastError = e.localizedDescription
                }
                self.updateIcon()
            }
        }
    }

    func execute(mode: String, paths: [String]?) -> Result<ScanResult, Error> {
        guard let engine = Bundle.main.path(forResource: "engine", ofType: "py"),
              let rules = Bundle.main.path(forResource: "rules", ofType: "json") else {
            return .failure(NSError(domain: "RepoGuard", code: 1, userInfo: [NSLocalizedDescriptionKey: "Engine files are missing from the app"]))
        }
        var args = ["-I", engine, mode, "--watch", watchDir, "--state", "\(supportDir)/state.json", "--rules", rules, "--log", logFile]
        if let paths = paths {
            let file = "\(supportDir)/paths.json"
            do {
                try JSONSerialization.data(withJSONObject: paths).write(to: URL(fileURLWithPath: file))
            } catch { return .failure(error) }
            args += ["--paths-file", file]
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = args
        p.currentDirectoryURL = URL(fileURLWithPath: "/")
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        do { try p.run() } catch { return .failure(error) }
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        group.wait()
        if p.terminationStatus != 0 {
            let text = String(data: errData, encoding: .utf8) ?? ""
            appendLog("ENGINE ERROR: \(text)")
            return .failure(NSError(domain: "RepoGuard", code: 2, userInfo: [NSLocalizedDescriptionKey: "Scan failed. See the log."]))
        }
        do { return .success(try JSONDecoder().decode(ScanResult.self, from: data)) } catch { return .failure(error) }
    }

    func appendLog(_ text: String) {
        guard let h = FileHandle(forWritingAtPath: logFile) else {
            FileManager.default.createFile(atPath: logFile, contents: text.data(using: .utf8))
            return
        }
        h.seekToEndOfFile()
        h.write(text.data(using: .utf8) ?? Data())
        h.closeFile()
    }

    // MARK: UI

    func updateIcon() {
        guard let button = statusItem.button else { return }
        let threat = !active.isEmpty
        let name = threat ? "exclamationmark.shield.fill" : (lastError != nil ? "shield.slash" : "checkmark.shield")
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "RepoGuard")
        image?.isTemplate = !threat
        button.image = image
        button.contentTintColor = threat ? .systemRed : nil
        button.title = threat ? " \(active.count)" : ""
        button.toolTip = threat ? "RepoGuard: \(active.count) threats" : "RepoGuard: all clear"
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let title: String
        if let e = lastError { title = "Not protected: \(e)" }
        else if !active.isEmpty { title = "\(active.count) threat\(active.count == 1 ? "" : "s") found" }
        else { title = scanning ? "Scanning…" : "All clear" }
        menu.addItem(disabled(title))
        menu.addItem(disabled("Watching \((watchDir as NSString).abbreviatingWithTildeInPath)"))
        menu.addItem(disabled(lastScan))
        if !active.isEmpty {
            menu.addItem(.separator())
            for f in active.prefix(10) {
                let repo = (f.root as NSString).lastPathComponent
                let item = NSMenuItem(title: "\(repo): \(f.path) (\(f.label))", action: #selector(reveal(_:)), keyEquivalent: "")
                item.target = self
                item.representedObject = "\(f.root)/\(f.path)"
                menu.addItem(item)
            }
            if active.count > 10 { menu.addItem(disabled("…and \(active.count - 10) more, see the log")) }
        }
        menu.addItem(.separator())
        menu.addItem(action("Scan Everything Now", #selector(scanNow), "s"))
        menu.addItem(action("Open Log", #selector(openLog), "l"))
        if !active.isEmpty { menu.addItem(action("Mark All as False Alarm…", #selector(ignoreAll), "")) }
        let login = action("Launch at Login", #selector(toggleLogin), "")
        login.state = FileManager.default.fileExists(atPath: agentPath) ? .on : .off
        menu.addItem(login)
        menu.addItem(.separator())
        menu.addItem(action("Quit RepoGuard", #selector(quit), "q"))
    }

    func disabled(_ title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    func action(_ title: String, _ selector: Selector, _ key: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        item.target = self
        return item
    }

    func alert(_ found: [Finding]) {
        if testMode { return }
        NSSound(named: "Basso")?.play()
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .critical
        a.messageText = "Malware warning: suspicious code found"
        let lines = found.prefix(8).map { "• \(($0.root as NSString).lastPathComponent)/\($0.path)\n   \($0.label)" }.joined(separator: "\n")
        let more = found.count > 8 ? "\n…and \(found.count - 8) more." : ""
        a.informativeText = "\(lines)\(more)\n\nDon't open this project in VS Code or run npm commands in it. Don't click Pull or Merge if this came from a fetch. Nothing from it has been run by RepoGuard."
        a.addButton(withTitle: "Show in Finder")
        a.addButton(withTitle: "OK")
        if a.runModal() == .alertFirstButtonReturn, let f = found.first {
            revealPath("\(f.root)/\(f.path)", root: f.root)
        }
    }

    func revealPath(_ path: String, root: String) {
        let target = FileManager.default.fileExists(atPath: path) ? path : root
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: target)])
    }

    @objc func reveal(_ sender: NSMenuItem) {
        guard let p = sender.representedObject as? String else { return }
        var root = p
        if let f = active.first(where: { "\($0.root)/\($0.path)" == p }) { root = f.root }
        revealPath(p, root: root)
    }

    @objc func scanNow() { runEngine(mode: "full", paths: nil) }

    @objc func openLog() {
        if !FileManager.default.fileExists(atPath: logFile) { FileManager.default.createFile(atPath: logFile, contents: nil) }
        NSWorkspace.shared.open(URL(fileURLWithPath: logFile))
    }

    @objc func ignoreAll() {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = "Mark \(active.count) findings as false alarms?"
        a.informativeText = "Only do this if you're sure this code is safe. RepoGuard stops warning about these exact file versions, and warns again if they change."
        a.addButton(withTitle: "Cancel")
        a.addButton(withTitle: "Mark as False Alarm")
        guard a.runModal() == .alertSecondButtonReturn else { return }
        runEngine(mode: "ignore-active", paths: nil)
    }

    @objc func toggleLogin() {
        setLaunchAtLogin(!FileManager.default.fileExists(atPath: agentPath))
    }

    func setLaunchAtLogin(_ on: Bool) {
        if on {
            let plist: [String: Any] = [
                "Label": agentLabel,
                "ProgramArguments": [Bundle.main.executablePath ?? ""],
                "RunAtLoad": true,
                "LimitLoadToSessionType": "Aqua",
                "ProcessType": "Interactive",
            ]
            try? FileManager.default.createDirectory(atPath: (agentPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            (plist as NSDictionary).write(toFile: agentPath, atomically: true)
        } else {
            try? FileManager.default.removeItem(atPath: agentPath)
        }
    }

    @objc func quit() { NSApp.terminate(nil) }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
