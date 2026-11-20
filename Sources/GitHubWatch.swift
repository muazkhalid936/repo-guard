import AppKit
import SwiftUI

// GitHub watch: every few minutes, checks every repo you can push to for new pushes, scans only what
// changed, and (optionally) removes malware right away with a commit on top. Off/on in Settings.

struct GHFinding: Decodable, Identifiable, Hashable {
    let repo: String
    let branch: String
    let sha: String
    let files: [String]
    let labels: [String]
    let time: String
    let existing: Bool
    var id: String { "\(repo)|\(branch)" }
}

struct GHFix: Decodable, Hashable {
    let repo: String
    let branch: String
    let commit: String
    let notes: [String]
}

struct GHResult: Decodable {
    var repos: Int = 0
    var changed: [String] = []
    var new_findings: [GHFinding] = []
    var fixed: [GHFix] = []
    var manual: [String] = []
    var errors: [String] = []
    var findings: [GHFinding] = []
    var rate_remaining: Int?
    var time: String?
    var error: String?
}

final class GitHubWatcher: ObservableObject {
    static let shared = GitHubWatcher()

    @Published var enabled = UserDefaults.standard.object(forKey: "ghWatch") as? Bool ?? true {
        didSet { UserDefaults.standard.set(enabled, forKey: "ghWatch"); reschedule() }
    }
    // Off by default: fixes happen only after the person reviews them (Review & Fix on GitHub).
    @Published var autoFix = UserDefaults.standard.object(forKey: "ghAutoFix") as? Bool ?? false {
        didSet { UserDefaults.standard.set(autoFix, forKey: "ghAutoFix") }
    }
    @Published var minutes = UserDefaults.standard.object(forKey: "ghMinutes") as? Int ?? 3 {
        didSet { UserDefaults.standard.set(minutes, forKey: "ghMinutes"); reschedule() }
    }
    @Published var result: GHResult?
    @Published var running = false
    @Published var lastFixAll: GHResult?
    @Published var plan: GHPlan?
    @Published var previewing = false
    @Published var previewError: String?

    var onNewThreats: (([GHFinding], [GHFix]) -> Void)?
    private var timer: Timer?
    private let queue = DispatchQueue(label: "repoguard.github")

    var findings: [GHFinding] { result?.findings ?? [] }

    init() {
        // show what the last check found, before the next one runs
        if let d = FileManager.default.contents(atPath: "\(supportDir)/github-watch.json"),
           let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
           let f = obj["findings"] as? [String: Any],
           let data = try? JSONSerialization.data(withJSONObject: Array(f.values)),
           let list = try? JSONDecoder().decode([GHFinding].self, from: data) {
            result = GHResult(findings: list.sorted { ($0.repo, $0.branch) < ($1.repo, $1.branch) }, time: obj["last_poll"] as? String)
        }
    }

    func start() { reschedule() }

    private func reschedule() {
        timer?.invalidate()
        timer = nil
        guard enabled, !testMode else { return }
        timer = Timer.scheduledTimer(withTimeInterval: TimeInterval(max(1, minutes) * 60), repeats: true) { [weak self] _ in self?.poll() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self] in self?.poll() }
    }

    /// Works out what Fix All on GitHub would change. Reads from GitHub only.
    func preview() {
        guard !previewing, !running else { return }
        previewing = true
        previewError = nil
        queue.async { [weak self] in
            guard let self = self else { return }
            var plan: GHPlan?
            var err = "RepoGuard is missing its GitHub files. Reinstall it."
            if let script = Bundle.main.path(forResource: "github_watch", ofType: "py"),
               let rules = Bundle.main.path(forResource: "rules", ofType: "json") {
                let r = runProcess("/usr/bin/python3", ["-I", script, "preview", "--rules", rules, "--state", "\(supportDir)/github-watch.json"], timeout: 600)
                plan = try? JSONDecoder().decode(GHPlan.self, from: r.out)
                err = "Couldn't read the branches from GitHub: \(r.errText.trimmingCharacters(in: .whitespacesAndNewlines).suffix(200))"
            }
            DispatchQueue.main.async {
                self.previewing = false
                if let p = plan { self.plan = p } else { self.previewError = err }
            }
        }
    }

    /// `approved`: branch ids from the review sheet. Fix All only touches those exact branch versions.
    func poll(fixExisting: Bool = false, approved: [String]? = nil) {
        guard enabled || fixExisting, !running else { return }
        running = true
        let fix = autoFix
        queue.async { [weak self] in
            guard let self = self else { return }
            let r = self.execute(fix: fix, fixExisting: fixExisting, approved: approved)
            DispatchQueue.main.async {
                self.running = false
                self.result = r
                if fixExisting { self.lastFixAll = r }
                if !r.new_findings.isEmpty || !r.fixed.isEmpty, !fixExisting { self.onNewThreats?(r.new_findings, r.fixed) }
            }
        }
    }

    private func execute(fix: Bool, fixExisting: Bool, approved: [String]?) -> GHResult {
        guard let script = Bundle.main.path(forResource: "github_watch", ofType: "py"),
              let rules = Bundle.main.path(forResource: "rules", ofType: "json") else {
            return GHResult(error: "RepoGuard is missing its GitHub files. Reinstall it.")
        }
        var args = ["-I", script, "poll", "--rules", rules, "--state", "\(supportDir)/github-watch.json", "--log", logFile]
        if fix { args.append("--fix") }
        if fixExisting { args.append("--fix-existing") }
        if let ids = approved {
            let file = "\(supportDir)/github-approved.json"
            guard let d = try? JSONEncoder().encode(ids), FileManager.default.createFile(atPath: file, contents: d) else {
                return GHResult(error: "Couldn't save your approval. Nothing was changed.")
            }
            args += ["--approved", file]
        }
        let r = runProcess("/usr/bin/python3", args, timeout: 1500)
        let text = String(data: r.out, encoding: .utf8) ?? ""
        if let line = text.split(separator: "\n").last(where: { $0.hasPrefix("{") }),
           let res = try? JSONDecoder().decode(GHResult.self, from: Data(line.utf8)) {
            return res
        }
        return GHResult(error: "GitHub check failed: \(r.errText.trimmingCharacters(in: .whitespacesAndNewlines).suffix(300))")
    }
}

// MARK: views

struct GitHubSettingsCard: View {
    @ObservedObject var gh = GitHubWatcher.shared
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "dot.radiowaves.left.and.right").foregroundColor(.accentColor)
                    Text("GitHub live watch").font(.headline)
                }
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Watch my GitHub repos for malware")
                        Text("Checks every repo you can push to for new pushes and scans only the files that changed. Uses your GitHub CLI login.")
                            .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: $gh.enabled).labelsHidden()
                }
                if gh.enabled {
                    Divider()
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Remove malware right away")
                            Text("Adds one cleanup commit on top of the infected branch. No force-push, so no history is rewritten. Protected branches are left for you.")
                                .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer()
                        Toggle("", isOn: $gh.autoFix).labelsHidden()
                    }
                    Divider()
                    HStack {
                        Text("Check every")
                        Picker("", selection: $gh.minutes) {
                            ForEach([1, 3, 5, 10, 30], id: \.self) { Text("\($0) min").tag($0) }
                        }.labelsHidden().frame(width: 100)
                        Spacer()
                        if gh.running { ProgressView().controlSize(.small) }
                        Text(status).font(.callout).foregroundColor(gh.result?.error != nil ? cautionOrange : .secondary)
                        Button("Check Now") { gh.poll() }.disabled(gh.running)
                    }
                }
            }
            .toggleStyle(.switch)
        }
    }
    private var status: String {
        if let e = gh.result?.error { return e }
        guard let r = gh.result, let t = r.time else { return gh.running ? "Checking…" : "Not checked yet" }
        return "\(r.repos) repos · last check \(niceTime(t).suffix(5))" + (r.rate_remaining.map { " · \($0) API calls left" } ?? "")
    }
}

struct GitHubThreatsSection: View {
    @ObservedObject var gh = GitHubWatcher.shared
    @State private var open = true

    var body: some View {
        if !gh.findings.isEmpty || gh.lastFixAll != nil {
            VStack(alignment: .leading, spacing: 10) {
                Button { withAnimation(.snappy) { open.toggle() } } label: {
                    HStack(spacing: 8) {
                        Image(systemName: "chevron.right").rotationEffect(.degrees(open ? 90 : 0)).foregroundColor(.secondary)
                        Image(systemName: "network").foregroundColor(dangerRed)
                        Text("On GitHub").font(.title3.bold())
                        Text("\(gh.findings.count) infected branch\(gh.findings.count == 1 ? "" : "es")").foregroundColor(.secondary)
                        Spacer()
                    }.contentShape(Rectangle())
                }.buttonStyle(.plain)
                .overlay(alignment: .trailing) {
                    if !gh.findings.isEmpty {
                        Button(gh.running ? "Fixing…" : gh.previewing ? "Preparing review…" : "Review & Fix on GitHub…") { gh.preview() }
                            .buttonStyle(.borderedProminent).tint(dangerRed).disabled(gh.running || gh.previewing)
                    }
                }
                if let e = gh.previewError { Text(e).font(.callout).foregroundColor(cautionOrange) }
                if let r = gh.lastFixAll {
                    Card {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("\(r.fixed.count) GitHub branches fixed", systemImage: "checkmark.seal.fill").foregroundColor(safeGreen)
                            ForEach(r.manual.prefix(8), id: \.self) { Text("• " + $0).font(.callout).foregroundColor(cautionOrange) }
                        }
                    }
                }
                if open {
                    ForEach(gh.findings) { f in
                        Card {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: "arrow.triangle.branch").font(.title3).foregroundColor(dangerRed).frame(width: 24)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("\(f.repo)").font(.headline)
                                    Text("Branch \(f.branch)").font(.system(.callout, design: .monospaced))
                                    Text(f.files.joined(separator: ", ")).font(.callout).foregroundColor(.secondary).lineLimit(2)
                                    Text(f.labels.joined(separator: " · ") + (f.existing ? " · infected before the watch started" : "")).font(.caption).foregroundColor(.secondary)
                                }
                                Spacer()
                                Button("Open on GitHub") {
                                    if let u = URL(string: "https://github.com/\(f.repo)/tree/\(f.branch)") { NSWorkspace.shared.open(u) }
                                }
                            }
                        }
                        .transition(.opacity.combined(with: .move(edge: .top)))
                    }
                }
            }
            .sheet(item: $gh.plan) { GHPreviewSheet(plan: $0) }
        }
    }
}
