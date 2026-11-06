import AppKit
import CoreServices
import Foundation

// Detection lives in Resources/engine.py and Resources/rules.json.
// This model watches the folder, runs the engine, and publishes results to the UI.

struct Finding: Decodable, Identifiable, Hashable {
    let key: String
    let root: String
    let path: String
    let rule: String?
    let label: String
    let `where`: String
    let time: String?
    var id: String { key }
    var repoName: String { (root as NSString).lastPathComponent }
    var location: String { describeLocation(`where`) }
}

struct ReviewItem: Decodable, Identifiable, Hashable {
    let root: String
    let path: String
    let label: String
    let `where`: String
    let time: String?
    var id: String { "\(root)|\(path)|\(label)" }
    var repoName: String { (root as NSString).lastPathComponent }
}

struct RepoInfo: Decodable, Identifiable, Hashable {
    let path: String
    let branch: String
    let branches: Int
    let threats: Int
    var id: String { path }
    var name: String { (path as NSString).lastPathComponent }
}

struct LastFull: Decodable { let files: Int; let time: String }

struct ScanResult: Decodable {
    let new: [Finding]
    let active: [Finding]
    let files: Int
    let repos: Int
    let repo_info: [RepoInfo]?
    let recent_reviews: [ReviewItem]?
    let last_full: LastFull?
    let errors: [String]?
}

struct LogEntry: Identifiable, Hashable {
    enum Kind { case threat, review, scan, error }
    let id: Int
    let time: String
    let kind: Kind
    let text: String
}

func describeLocation(_ w: String) -> String {
    func short(_ r: String) -> String {
        r.replacingOccurrences(of: "refs/heads/", with: "")
            .replacingOccurrences(of: "refs/remotes/", with: "")
            .replacingOccurrences(of: "refs/tags/", with: "tag ")
    }
    if w == "folder" { return "In the files on disk" }
    if w == "git-config" { return "In the repo's Git settings" }
    if w.hasPrefix("branch:") { return "On branch \(short(String(w.dropFirst(7))))" }
    if w.hasPrefix("incoming:") { return "In new commits on \(short(String(w.dropFirst(9))))" }
    return w
}

let env = ProcessInfo.processInfo.environment
let testMode = env["REPOGUARD_TEST"] != nil
let home = FileManager.default.homeDirectoryForCurrentUser.path
let supportDir = env["REPOGUARD_SUPPORT"] ?? "\(home)/Library/Application Support/RepoGuard"
let logFile = env["REPOGUARD_LOG"] ?? "\(home)/Library/Logs/RepoGuard.log"
let agentLabel = "local.repoguard.app"
let agentPath = "\(home)/Library/LaunchAgents/\(agentLabel).plist"
let legacyWatch = "\(home)/Documents/github"

/// Folders too broad to watch: they'd scan the whole Mac and trigger many permission prompts.
func tooBroad(_ path: String) -> Bool {
    let p = (path as NSString).standardizingPath
    return ["/", home, "/Users", "/Applications", "/System", "/Library", "/Volumes", "\(home)/Library"].contains(p)
}

final class AppModel: ObservableObject {
    @Published var active: [Finding] = []
    @Published var reviews: [ReviewItem] = []
    @Published var repos: [RepoInfo] = []
    @Published var activity: [LogEntry] = []
    @Published var filesChecked = 0
    @Published var lastScan: Date?
    @Published var scanning = false
    @Published var lastError: String?
    @Published var loaded = false
    @Published var watchDirs: [String]
    @Published var setupDone: Bool
    @Published var launchAtLogin = FileManager.default.fileExists(atPath: agentPath)
    @Published var popupsEnabled = UserDefaults.standard.object(forKey: "popups") as? Bool ?? true {
        didSet { UserDefaults.standard.set(popupsEnabled, forKey: "popups") }
    }

    /// Called on the main thread when a scan changes state, or finds new threats.
    var onChange: (() -> Void)?
    var onNewThreats: (([Finding]) -> Void)?

    private let scanQueue = DispatchQueue(label: "repoguard.scan")
    private let lock = NSLock()
    private var pending = Set<String>()
    private var debounce: DispatchWorkItem?
    private var stream: FSEventStreamRef?

    init() {
        if let forced = env["REPOGUARD_WATCH"] {
            watchDirs = [forced]
            setupDone = true
        } else {
            let saved = UserDefaults.standard.stringArray(forKey: "watchDirs")
            setupDone = saved != nil && !(saved ?? []).isEmpty
            // Someone upgrading from the version that always watched one fixed folder sees it pre-filled.
            let upgraded = FileManager.default.fileExists(atPath: "\(supportDir)/state.json")
            watchDirs = saved ?? (upgraded ? [legacyWatch] : [])
        }
    }

    var watchSummary: String {
        if watchDirs.count == 1 { return (watchDirs[0] as NSString).abbreviatingWithTildeInPath }
        return "\(watchDirs.count) folders"
    }

    var isProtected: Bool { lastError == nil }
    var threatRepoCount: Int { Set(active.map(\.root)).count }

    func start() {
        try? FileManager.default.createDirectory(atPath: supportDir, withIntermediateDirectories: true)
        refreshActivity()
        guard setupDone else {
            lastError = "Choose the folders where your repos are."
            onChange?()
            return
        }
        startWatching()
        run(mode: "full", paths: nil)
    }

    func finishSetup() {
        guard !watchDirs.isEmpty else { return }
        UserDefaults.standard.set(watchDirs, forKey: "watchDirs")
        setupDone = true
        lastError = nil
        startWatching()
        run(mode: "full", paths: nil)
    }

    /// Adds folders, ignoring ones already covered. Returns folders refused as too broad.
    @discardableResult func addFolders(_ paths: [String]) -> [String] {
        var refused: [String] = []
        for p in paths {
            if tooBroad(p) { refused.append(p); continue }
            if watchDirs.contains(where: { p == $0 || p.hasPrefix($0 + "/") }) { continue }
            watchDirs.removeAll { $0.hasPrefix(p + "/") }
            watchDirs.append(p)
        }
        watchDirs.sort()
        if setupDone { applyFolders() }
        return refused
    }

    func removeFolder(_ path: String) {
        watchDirs.removeAll { $0 == path }
        if setupDone { applyFolders() }
    }

    private func applyFolders() {
        UserDefaults.standard.set(watchDirs, forKey: "watchDirs")
        startWatching()
        if watchDirs.isEmpty {
            active = []
            repos = []
            lastError = "No folders are being watched. Add a folder in Settings."
            onChange?()
        } else {
            lastError = nil
            run(mode: "full", paths: nil)
        }
    }

    // MARK: watching

    private func startWatching() {
        if let old = stream {
            FSEventStreamStop(old)
            FSEventStreamInvalidate(old)
            FSEventStreamRelease(old)
            stream = nil
        }
        if watchDirs.isEmpty { return }
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info = info else { return }
            let me = Unmanaged<AppModel>.fromOpaque(info).takeUnretainedValue()
            let array = unsafeBitCast(eventPaths, to: NSArray.self)
            var paths: [String] = []
            for i in 0..<count { if let p = array[i] as? String { paths.append(p) } }
            me.enqueue(paths)
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagNoDefer)
        stream = FSEventStreamCreate(kCFAllocatorDefault, callback, &context, watchDirs as CFArray,
                                     FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 1.0, flags)
        if let stream = stream {
            FSEventStreamSetDispatchQueue(stream, DispatchQueue.global(qos: .utility))
            FSEventStreamStart(stream)
        }
    }

    private func enqueue(_ paths: [String]) {
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

    private func flush() {
        lock.lock()
        let batch = Array(pending)
        pending.removeAll()
        lock.unlock()
        if !batch.isEmpty { run(mode: "event", paths: batch) }
    }

    // MARK: scanning

    func scanNow() { run(mode: "full", paths: nil) }

    func markAllFalseAlarm() {
        scanQueue.async { [weak self] in
            guard let self = self else { return }
            _ = self.execute(mode: "ignore-active", paths: nil)
            self.run(mode: "full", paths: nil)
        }
    }

    private func run(mode: String, paths: [String]?) {
        scanQueue.async { [weak self] in
            guard let self = self else { return }
            DispatchQueue.main.async { self.scanning = true; self.onChange?() }
            let result = self.execute(mode: mode, paths: paths)
            DispatchQueue.main.async {
                self.scanning = false
                self.loaded = true
                switch result {
                case .success(let r):
                    self.active = r.active
                    if let info = r.repo_info { self.repos = info }
                    if let rv = r.recent_reviews { self.reviews = rv.reversed() }
                    if let lf = r.last_full { self.filesChecked = lf.files }
                    self.lastScan = Date()
                    self.lastError = (r.errors ?? []).first
                    if !r.new.isEmpty { self.onNewThreats?(r.new) }
                case .failure(let e):
                    self.lastError = e.localizedDescription
                }
                self.refreshActivity()
                self.onChange?()
            }
        }
    }

    private func execute(mode: String, paths: [String]?) -> Result<ScanResult, Error> {
        guard let engine = Bundle.main.path(forResource: "engine", ofType: "py"),
              let rules = Bundle.main.path(forResource: "rules", ofType: "json") else {
            return .failure(NSError(domain: "RepoGuard", code: 1, userInfo: [NSLocalizedDescriptionKey: "The app's scan files are missing. Reinstall RepoGuard."]))
        }
        var args = ["-I", engine, mode, "--state", "\(supportDir)/state.json", "--rules", rules, "--log", logFile]
        for dir in watchDirs { args += ["--watch", dir] }
        if let paths = paths {
            let file = "\(supportDir)/paths.json"
            do { try JSONSerialization.data(withJSONObject: paths).write(to: URL(fileURLWithPath: file)) } catch { return .failure(error) }
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
            let message = "The scan failed. See Activity for details."
            return .failure(NSError(domain: "RepoGuard", code: 2, userInfo: [NSLocalizedDescriptionKey: message]))
        }
        do { return .success(try JSONDecoder().decode(ScanResult.self, from: data)) } catch { return .failure(error) }
    }

    private func appendLog(_ text: String) {
        guard let h = FileHandle(forWritingAtPath: logFile) else {
            FileManager.default.createFile(atPath: logFile, contents: text.data(using: .utf8))
            return
        }
        h.seekToEndOfFile()
        h.write(text.data(using: .utf8) ?? Data())
        h.closeFile()
    }

    func refreshActivity() {
        guard let text = try? String(contentsOfFile: logFile, encoding: .utf8) else { return }
        let lines = text.split(separator: "\n").suffix(400)
        var out: [LogEntry] = []
        for (i, raw) in lines.enumerated() {
            let line = String(raw)
            let time = line.count > 19 ? String(line.prefix(19)) : ""
            let body = line.count > 20 ? String(line.dropFirst(20)) : line
            if body.hasPrefix("THREAT ") { out.append(LogEntry(id: i, time: time, kind: .threat, text: shortenPaths(String(body.dropFirst(7))))) }
            else if body.hasPrefix("REVIEW ") { out.append(LogEntry(id: i, time: time, kind: .review, text: shortenPaths(String(body.dropFirst(7))))) }
            else if body.hasPrefix("scan done") {
                // Only full-looking scans are worth showing. Quiet per-file checks would drown everything else.
                if body.contains("new=0"), let f = body.range(of: "files="), let num = Int(body[f.upperBound...].prefix(while: \.isNumber)), num < 50 { continue }
                out.append(LogEntry(id: i, time: time, kind: .scan, text: humanScan(body)))
            }
            else if body.hasPrefix("FOLDER ERROR ") { out.append(LogEntry(id: i, time: time, kind: .error, text: String(body.dropFirst(13)))) }
            else if line.contains("ENGINE ERROR") { out.append(LogEntry(id: i, time: "", kind: .error, text: "A scan failed: \(line.replacingOccurrences(of: "ENGINE ERROR: ", with: ""))")) }
        }
        activity = out.reversed()
    }

    private func shortenPaths(_ s: String) -> String {
        watchDirs.reduce(s) { $0.replacingOccurrences(of: $1 + "/", with: "") }
    }

    private func humanScan(_ body: String) -> String {
        func value(_ k: String) -> String {
            guard let r = body.range(of: k + "=") else { return "0" }
            return String(body[r.upperBound...].prefix(while: \.isNumber))
        }
        let new = value("new")
        return "Scanned \(value("files")) files in \(value("repos")) repos" + (new == "0" ? ", nothing new" : ", \(new) new threats")
    }

    // MARK: actions

    func reveal(_ f: Finding) {
        let path = "\(f.root)/\(f.path)"
        let target = FileManager.default.fileExists(atPath: path) ? path : f.root
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: target)])
    }

    func revealFolder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    func openLog() {
        if !FileManager.default.fileExists(atPath: logFile) { FileManager.default.createFile(atPath: logFile, contents: nil) }
        NSWorkspace.shared.open(URL(fileURLWithPath: logFile))
    }

    func setLaunchAtLogin(_ on: Bool) {
        if on {
            let plist: [String: Any] = [
                "Label": agentLabel,
                "ProgramArguments": [Bundle.main.executablePath ?? "", "--background"],
                "RunAtLoad": true,
                "LimitLoadToSessionType": "Aqua",
                "ProcessType": "Interactive",
            ]
            try? FileManager.default.createDirectory(atPath: (agentPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            (plist as NSDictionary).write(toFile: agentPath, atomically: true)
        } else {
            try? FileManager.default.removeItem(atPath: agentPath)
        }
        launchAtLogin = FileManager.default.fileExists(atPath: agentPath)
    }
}
