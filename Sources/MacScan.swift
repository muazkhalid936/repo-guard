import AppKit
import Foundation
import SwiftUI

// This Mac: startup items, running programs and risky folders, checked by mac_agent.py.
// Runs at launch and every 15 minutes; it takes about a second.

struct StartupItem: Codable, Identifiable, Hashable {
    let id: String
    let label: String
    let plist: String
    let program: String
    let command: String
    let signer: String
    let `where`: String
    let root: Bool
    let runs_at_load: Bool
    let keep_alive: Bool
    let disabled: Bool
    let changed: String

    var trusted: Bool { ["Apple", "App Store", "Homebrew", "RepoGuard", "needs admin to check"].contains(signer) || signer.hasPrefix("Developer ID") }
    var signerLabel: String {
        if signer.hasPrefix("Developer ID: ") {
            let name = String(signer.dropFirst(14))
            return name.replacingOccurrences(of: #"\s*\([A-Z0-9]{10}\)$"#, with: "", options: .regularExpression)
        }
        switch signer {
        case "missing": return "Program missing"
        case "unsigned": return "Unsigned"
        case "ad-hoc": return "Not verified"
        case "script": return "Script"
        default: return signer
        }
    }
}

struct MacFixResult: Codable, Hashable {
    let id: String
    let ok: Bool
    let path: String?
    let result: String
    let needs_admin: Bool?
}

struct MacReport: Codable {
    var findings: [ServerFinding] = []
    var inventory: [StartupItem] = []
    var errors: [String]? = []
    var results: [MacFixResult]? = nil
    var backup: String? = nil
    var time: Date? = nil
    var failure: String? = nil
}

final class MacStore: ObservableObject {
    static let shared = MacStore()
    @Published var report: MacReport?
    @Published var busy: String?
    /// Called on the main thread with threats that weren't there on the previous scan.
    var onNewThreats: (([ServerFinding]) -> Void)?

    private let file = "\(supportDir)/mac-report.json"
    private var timer: Timer?
    private let queue = DispatchQueue(label: "repoguard.mac")

    init() {
        if let d = FileManager.default.contents(atPath: file), let r = try? JSONDecoder().decode(MacReport.self, from: d) { report = r }
    }

    var threats: [ServerFinding] { report?.findings.filter { $0.severity == "block" } ?? [] }
    var reviews: [ServerFinding] { report?.findings.filter { $0.severity != "block" } ?? [] }

    func start() {
        scan()
        timer = Timer.scheduledTimer(withTimeInterval: 15 * 60, repeats: true) { [weak self] _ in self?.scan() }
    }

    func scan() {
        guard busy == nil else { return }
        busy = "Scanning…"
        let before = Set(threats.map(\.id))
        queue.async {
            var r: MacReport
            switch self.run(["scan"]) {
            case .success(let x): r = x
            case .failure(let e): r = self.report ?? MacReport(); r.failure = e.localizedDescription
            }
            r.time = Date()
            r.results = nil
            DispatchQueue.main.async {
                let prevResults = self.report?.results
                self.report = r
                self.report?.results = prevResults
                self.busy = nil
                self.save()
                let new = r.findings.filter { $0.severity == "block" && !before.contains($0.id) }
                if !new.isEmpty && r.failure == nil {
                    appendToLog("MAC SCAN: \(new.count) new threat(s): " + new.map(\.detail).prefix(3).joined(separator: " | "))
                    self.onNewThreats?(new)
                }
            }
        }
    }

    /// Fixes the given findings or turns off the given startup items. Items in /Library need the
    /// administrator password, which macOS asks for in its own dialog.
    func clean(ids: [String]) {
        guard !ids.isEmpty, busy == nil else { return }
        busy = "Removing…"
        queue.async {
            var r: MacReport
            switch self.run(["clean", "--ids"] + ids) {
            case .success(let x): r = x
            case .failure(let e): r = self.report ?? MacReport(); r.failure = e.localizedDescription
            }
            let admin = (r.results ?? []).filter { $0.needs_admin == true }.map(\.id)
            if !admin.isEmpty && r.failure == nil {
                DispatchQueue.main.async { self.busy = "Waiting for your password…" }
                switch self.run(["clean", "--ids"] + admin, asAdmin: true) {
                case .success(let x):
                    let fixed = Dictionary(uniqueKeysWithValues: (x.results ?? []).map { ($0.id, $0) })
                    r.results = (r.results ?? []).map { fixed[$0.id] ?? $0 }
                    r.findings = x.findings
                    r.inventory = x.inventory
                case .failure(let e):
                    r.results = (r.results ?? []).map { $0.needs_admin == true ? MacFixResult(id: $0.id, ok: false, path: $0.path, result: "not changed: \(e.localizedDescription)", needs_admin: true) : $0 }
                }
            }
            r.time = Date()
            DispatchQueue.main.async {
                self.report = r
                self.busy = nil
                self.save()
                for x in r.results ?? [] { appendToLog("MAC \(x.ok ? "CLEANED" : "MANUAL") \(x.path ?? x.id): \(x.result)") }
            }
        }
    }

    func showBackups() {
        let dir = report?.backup ?? "\(supportDir)/quarantine"
        NSWorkspace.shared.open(URL(fileURLWithPath: FileManager.default.fileExists(atPath: dir) ? dir : "\(supportDir)/quarantine"))
    }

    private func save() {
        if let d = try? JSONEncoder().encode(report) { FileManager.default.createFile(atPath: file, contents: d, attributes: [.posixPermissions: 0o600]) }
    }

    private func run(_ args: [String], asAdmin: Bool = false) -> Result<MacReport, Error> {
        guard let agent = Bundle.main.path(forResource: "mac_agent", ofType: "py") else { return .failure(err("RepoGuard is missing mac_agent.py. Reinstall it.")) }
        let backup = "\(supportDir)/quarantine"
        try? FileManager.default.createDirectory(atPath: backup, withIntermediateDirectories: true)
        let full = ["-I", agent] + args + ["--backup", backup]
        let r: ProcResult
        if asAdmin {
            let cmd = "REPOGUARD_USER=\(shellQuote(NSUserName())) /usr/bin/python3 " + full.map(shellQuote).joined(separator: " ")
            let escaped = cmd.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            r = runProcess("/usr/bin/osascript", ["-e", "do shell script \"\(escaped)\" with administrator privileges"], timeout: 600)
            if r.status != 0 && r.errText.contains("-128") { return .failure(err("you cancelled the password prompt")) }
        } else {
            r = runProcess("/usr/bin/python3", full, timeout: 600)
        }
        guard let line = String(data: r.out, encoding: .utf8)?.split(separator: "\n").last(where: { $0.hasPrefix("{") }),
              let rep = try? JSONDecoder().decode(MacReport.self, from: Data(line.utf8)) else {
            return .failure(err("The Mac scan failed: \(r.errText.trimmingCharacters(in: .whitespacesAndNewlines).suffix(300))"))
        }
        return .success(rep)
    }
}

func appendToLog(_ line: String) {
    let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
    let text = "\(fmt.string(from: Date())) \(line)\n"
    guard let h = FileHandle(forWritingAtPath: logFile) else {
        FileManager.default.createFile(atPath: logFile, contents: Data(text.utf8)); return
    }
    h.seekToEndOfFile(); h.write(Data(text.utf8)); h.closeFile()
}

// MARK: view

struct MacView: View {
    @ObservedObject var store = MacStore.shared
    @State private var confirmRemove = false
    @State private var turnOff: StartupItem?
    @State private var showAll = false

    private var tint: Color { store.report?.failure != nil ? cautionOrange : (store.threats.isEmpty ? safeGreen : dangerRed) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "This Mac", subtitle: "Startup items, running programs, shell files and temp folders") {
                    Button { store.scan() } label: {
                        HStack(spacing: 6) {
                            if store.busy != nil { ProgressView().controlSize(.small).scaleEffect(0.75).frame(width: 14, height: 14) } else { Image(systemName: "arrow.clockwise") }
                            Text(store.busy ?? "Scan Now")
                        }.frame(minWidth: 96)
                    }
                    .controlSize(.large).disabled(store.busy != nil)
                }
                summary
                if !store.threats.isEmpty || !store.reviews.isEmpty { findings }
                if let results = store.report?.results, !results.isEmpty { lastClean(results) }
                startupItems
            }
            .padding(24)
        }
        .alert("Remove \(store.threats.count) threat\(store.threats.count == 1 ? "" : "s") from this Mac?", isPresented: $confirmRemove) {
            Button("Remove Threats", role: .destructive) { store.clean(ids: store.threats.map(\.id)) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Bad startup items are turned off, bad programs are stopped, and bad lines are cut out of shell and editor files. Everything removed is backed up in RepoGuard's quarantine folder first. Items in /Library ask for your administrator password.")
        }
        .alert(item: $turnOff) { item in
            Alert(title: Text("Turn off \(item.label)?"),
                  message: Text("It stops now and won't start at login. Its file is moved to RepoGuard's quarantine folder, so you can put it back.\(item.root ? " macOS will ask for your administrator password." : "")"),
                  primaryButton: .destructive(Text("Turn Off")) { store.clean(ids: [item.id]) },
                  secondaryButton: .cancel())
        }
    }

    private var summary: some View {
        Card {
            HStack(spacing: 16) {
                ZStack {
                    Circle().fill(tint.opacity(0.16)).frame(width: 52, height: 52)
                    Image(systemName: store.threats.isEmpty ? "laptopcomputer" : "exclamationmark.triangle.fill").font(.title2).foregroundColor(tint)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.title3.bold())
                    Text(detail).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                if !store.threats.isEmpty {
                    Button { confirmRemove = true } label: { Label("Remove Threats…", systemImage: "trash") }
                        .buttonStyle(.borderedProminent).tint(dangerRed).controlSize(.large).disabled(store.busy != nil)
                }
            }
        }
    }

    private var title: String {
        if let f = store.report?.failure { return "Couldn't scan: \(f)" }
        if store.report == nil { return store.busy != nil ? "Scanning this Mac…" : "Not scanned yet" }
        if !store.threats.isEmpty { return "\(store.threats.count) threat\(store.threats.count == 1 ? "" : "s") on this Mac" }
        return "Nothing malicious is running or set to start"
    }

    private var detail: String {
        guard let r = store.report, let t = r.time else { return "Checks launch agents, login items, cron, shell files, editor settings and running programs." }
        var s = "Checked \(relativeTime(t)) · \(r.inventory.count) startup items"
        if !store.reviews.isEmpty { s += " · \(store.reviews.count) to review" }
        return s
    }

    private var findings: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Findings").font(.headline)
                ForEach(store.threats) { f in FindingRow(f: f, color: dangerRed, fix: nil) }
                ForEach(store.reviews) { f in
                    FindingRow(f: f, color: cautionOrange, fix: f.fix.hasPrefix("review") ? nil : { store.clean(ids: [f.id]) })
                }
                if let errs = store.report?.errors, !errs.isEmpty {
                    Text(errs.prefix(2).joined(separator: " ")).font(.caption).foregroundColor(.secondary)
                }
            }
        }
    }

    private func lastClean(_ results: [MacFixResult]) -> some View {
        Card {
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text("Last removal").font(.headline)
                    Spacer()
                    Button("Show Backups") { store.showBackups() }.controlSize(.small)
                }
                ForEach(results, id: \.id) { r in
                    Label("\(((r.path ?? r.id) as NSString).lastPathComponent): \(r.result)", systemImage: r.ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundColor(r.ok ? safeGreen : cautionOrange).font(.callout).lineLimit(2)
                }
            }
        }
    }

    private var startupItems: some View {
        let items = (store.report?.inventory ?? []).sorted { ($0.trusted ? 1 : 0, $0.label) < ($1.trusted ? 1 : 0, $1.label) }
        let shown = showAll ? items : Array(items.prefix(12))
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Starts automatically").font(.headline)
                    Spacer()
                    Text("\(items.count) items").foregroundColor(.secondary).font(.callout)
                }
                if items.isEmpty {
                    Text(store.report == nil ? "Scan to list what starts with your Mac." : "Nothing starts automatically.").foregroundColor(.secondary)
                }
                ForEach(shown) { item in
                    HStack(spacing: 10) {
                        Image(systemName: item.where == "login item" ? "person.crop.circle" : (item.where == "system daemon" ? "gearshape.2" : "bolt.circle"))
                            .foregroundColor(.secondary).frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.label).lineLimit(1)
                            Text(item.program.isEmpty ? "(no program)" : (item.program as NSString).abbreviatingWithTildeInPath)
                                .font(.system(.caption, design: .monospaced)).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Text(item.where).font(.caption).foregroundColor(.secondary)
                        Pill(text: item.signerLabel, color: item.trusted ? safeGreen : (item.signer == "missing" ? .secondary : cautionOrange))
                        if item.signer != "RepoGuard" {
                            Button("Turn Off") { turnOff = item }.controlSize(.small).disabled(store.busy != nil)
                        }
                    }
                    if item.id != shown.last?.id { Divider() }
                }
                if items.count > 12 {
                    Button(showAll ? "Show Less" : "Show All \(items.count)") { showAll.toggle() }.buttonStyle(.link)
                }
            }
        }
    }
}
