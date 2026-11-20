import AppKit
import Charts
import Foundation
import SwiftUI

// Cleanup: storage analytics, cleaning developer caches, and archiving old projects to GitHub.
// storage.py does the work and streams one JSON object per line, so every step shows live progress.

struct CleanItem: Codable, Identifiable, Hashable {
    let id: String
    let category: String
    let title: String
    let path: String
    let size: Int64
    let detail: String
    let selected: Bool
    let kind: String
    var paths: [String]? = nil
    var udid: String? = nil
}

struct DevProject: Codable, Identifiable, Hashable {
    var id: String { path }
    let path: String
    let name: String
    let parent: String
    let size: Int64
    let rebuild_size: Int64
    let idle_days: Int
    let last_opened: String
    let envs: [String]
    let infected: Bool
    let git: Bool
    let remote: String
    let branches: Int
    let unpushed: Int
    let no_upstream: [String]
    let dirty: Int
    let stashes: Int
    let current: String
}

struct DiskInfo: Codable, Hashable { let total: Int64; let free: Int64 }

struct DiskNode: Codable, Hashable, Identifiable {
    var id: String { path }
    let path: String
    let name: String
    let size: Int64
    let children: [DiskNode]
}
struct APFSVolume: Codable, Hashable { let name: String; let role: String; let used: Int64 }
struct APFSContainer: Codable, Hashable { let total: Int64; let free: Int64; let volumes: [APFSVolume] }
struct Insight: Codable, Hashable, Identifiable {
    var id: String { title }
    let title: String
    let size: Int64
    let detail: String
    let action: String
    let path: String
}
struct LargeFile: Codable, Hashable, Identifiable {
    var id: String { path }
    let path: String
    let size: Int64
    let apparent: Int64
    let modified: String
}
struct Blocked: Codable, Hashable { let name: String; let path: String }
struct DiskMap: Codable {
    let container: APFSContainer?
    let roots: [DiskNode]
    let blocked: [Blocked]
    let large: [LargeFile]
    let insights: [Insight]
    let measured: Int64
    let time: String
}

struct StorageResult: Codable {
    let items: [CleanItem]
    let projects: [DevProject]
    let disk: DiskInfo
    let stale_days: Int
    let time: String
}

struct CleanRecord: Codable, Hashable {
    let time: Date
    let freeBefore: Int64
    let freeAfter: Int64
    let total: Int64
    let byCategory: [String: Int64]
    let failed: [String]
    var freed: Int64 { max(0, freeAfter - freeBefore) }
}

struct DiskPoint: Codable, Hashable, Identifiable {
    var id: Date { time }
    let time: Date
    let free: Int64
    let total: Int64
}

struct ArchiveStep: Identifiable, Hashable {
    var id: Int { n }
    let n: Int
    let title: String
    var status: String
    var detail: String
}

func bytes(_ n: Int64) -> String { ByteCountFormatter.string(fromByteCount: n, countStyle: .file) }

final class StorageStore: ObservableObject {
    static let shared = StorageStore()

    @Published var result: StorageResult?
    @Published var selected: Set<String> = []
    @Published var analyzing = false
    @Published var cleaning = false
    @Published var progressTitle = ""
    @Published var progress: Double = 0
    @Published var lastClean: CleanRecord?
    @Published var history: [DiskPoint] = []
    @Published var error: String?
    // archive
    @Published var archiving: String?
    @Published var steps: [ArchiveStep] = []
    @Published var archiveResult: [String: AnyCodableValue] = [:]

    private let resultFile = "\(supportDir)/storage-result.json"
    private let historyFile = "\(supportDir)/storage-history.json"
    private let cleanFile = "\(supportDir)/storage-last-clean.json"

    init() {
        let dec = JSONDecoder()
        if let d = FileManager.default.contents(atPath: resultFile), let r = try? dec.decode(StorageResult.self, from: d) {
            result = r
            selected = Set(r.items.filter(\.selected).map(\.id))
        }
        if let d = FileManager.default.contents(atPath: historyFile), let h = try? dec.decode([DiskPoint].self, from: d) { history = h }
        if let d = FileManager.default.contents(atPath: cleanFile), let c = try? dec.decode(CleanRecord.self, from: d) { lastClean = c }
        loadMap()
        recordDisk()
    }

    static func diskNow() -> DiskInfo? {
        guard let v = try? URL(fileURLWithPath: "/").resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityForImportantUsageKey]),
              let total = v.volumeTotalCapacity, let free = v.volumeAvailableCapacityForImportantUsage else { return nil }
        return DiskInfo(total: Int64(total), free: free)
    }

    var disk: DiskInfo? { Self.diskNow() ?? result?.disk }

    /// One point per hour at most, kept for 90 days, for the free-space history chart.
    func recordDisk(force: Bool = false) {
        guard let d = Self.diskNow() else { return }
        let now = Date()
        if !force, let last = history.last, now.timeIntervalSince(last.time) < 3600 { return }
        history.append(DiskPoint(time: now, free: d.free, total: d.total))
        history = history.filter { now.timeIntervalSince($0.time) < 90 * 86400 }
        if let data = try? JSONEncoder().encode(history) { FileManager.default.createFile(atPath: historyFile, contents: data) }
    }

    var items: [CleanItem] { result?.items ?? [] }
    var selectedSize: Int64 { items.filter { selected.contains($0.id) }.reduce(0) { $0 + $1.size } }
    var reclaimable: Int64 { items.reduce(0) { $0 + $1.size } }
    var categories: [String] {
        let order = ["Old projects", "Build output", "Docker", "Simulators", "Xcode", "Editors", "Package caches", "Android", "Downloads", "System"]
        return Array(Set(items.map(\.category))).sorted { (order.firstIndex(of: $0) ?? 99, $0) < (order.firstIndex(of: $1) ?? 99, $1) }
    }
    func size(of category: String) -> Int64 { items.filter { $0.category == category }.reduce(0) { $0 + $1.size } }

    // MARK: running storage.py

    private func stream(_ args: [String], onLine: @escaping ([String: Any]) -> Void, done: @escaping (Int32, String) -> Void) {
        guard let script = Bundle.main.path(forResource: "storage", ofType: "py") else { done(1, "RepoGuard is missing storage.py. Reinstall it."); return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-I", script] + args
        p.currentDirectoryURL = URL(fileURLWithPath: "/")
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        var buffer = Data()
        var errData = Data()
        let lock = NSLock()
        out.fileHandleForReading.readabilityHandler = { h in
            let chunk = h.availableData
            guard !chunk.isEmpty else { return }
            lock.lock()
            buffer.append(chunk)
            var lines: [Data] = []
            while let nl = buffer.firstIndex(of: 0x0A) {
                lines.append(buffer.subdata(in: buffer.startIndex..<nl))
                buffer.removeSubrange(buffer.startIndex...nl)
            }
            lock.unlock()
            for l in lines {
                if let obj = try? JSONSerialization.jsonObject(with: l) as? [String: Any] {
                    DispatchQueue.main.async { onLine(obj) }
                }
            }
        }
        err.fileHandleForReading.readabilityHandler = { h in
            let c = h.availableData
            lock.lock(); errData.append(c); lock.unlock()
        }
        p.terminationHandler = { proc in
            out.fileHandleForReading.readabilityHandler = nil
            err.fileHandleForReading.readabilityHandler = nil
            // whatever is left after the last newline
            let rest = out.fileHandleForReading.readDataToEndOfFile()
            lock.lock(); buffer.append(rest); let tail = buffer; let e = String(data: errData, encoding: .utf8) ?? ""; lock.unlock()
            for l in tail.split(separator: 0x0A) {
                if let obj = try? JSONSerialization.jsonObject(with: Data(l)) as? [String: Any] { DispatchQueue.main.async { onLine(obj) } }
            }
            DispatchQueue.main.async { done(proc.terminationStatus, e) }
        }
        do { try p.run() } catch { done(1, error.localizedDescription) }
    }

    /// Maps the whole disk first (where space goes), then finds what can be cleaned.
    func analyze(model: AppModel) {
        guard !analyzing, !cleaning else { return }
        analyzing = true; error = nil; progress = 0; progressTitle = "Starting…"
        phase = "Mapping the disk"
        stream(["diskmap"], onLine: { obj in
            switch obj["type"] as? String {
            case "progress":
                self.progressTitle = obj["title"] as? String ?? ""
                self.progress = (obj["pct"] as? Double ?? 0) / 200
            case "result":
                if let d = try? JSONSerialization.data(withJSONObject: obj), let m = try? JSONDecoder().decode(DiskMap.self, from: d) {
                    self.map = m
                    self.explorePath = []
                    FileManager.default.createFile(atPath: self.mapFile, contents: d)
                }
            default: break
            }
        }, done: { status, err in
            if status != 0 { self.error = "Mapping the disk failed: \(err.suffix(300))" }
            self.analyzing = false
            self.findCleanable(model: model)
        })
    }

    @Published var phase = ""
    @Published var map: DiskMap?
    /// Folders the explorer drilled into, outermost first.
    @Published var explorePath: [DiskNode] = []
    @Published var loadingChildren: String?
    private let mapFile = "\(supportDir)/storage-map.json"

    /// Drops a folder that was moved to the Trash from the explorer without measuring again.
    func removeFromMap(_ path: String) {
        explorePath = explorePath.map { prune($0, path) }
        if let m = map { map = DiskMap(container: m.container, roots: m.roots.map { prune($0, path) }, blocked: m.blocked, large: m.large, insights: m.insights, measured: m.measured, time: m.time) }
        recordDisk(force: true)
    }

    private func prune(_ n: DiskNode, _ path: String) -> DiskNode {
        guard path.hasPrefix(n.path + "/") else { return n }
        let removed = n.children.first { $0.path == path }?.size ?? 0
        return DiskNode(path: n.path, name: n.name, size: n.size - removed, children: n.children.filter { $0.path != path }.map { prune($0, path) })
    }

    func loadMap() {
        if map == nil, let d = FileManager.default.contents(atPath: mapFile), let m = try? JSONDecoder().decode(DiskMap.self, from: d) { map = m }
    }

    /// Opens a folder in the explorer, measuring it first if the map didn't go that deep.
    func explore(_ node: DiskNode) {
        if !node.children.isEmpty || node.size < 200_000_000 {
            explorePath.append(node); return
        }
        loadingChildren = node.path
        stream(["children", "--path", node.path], onLine: { obj in
            if obj["type"] as? String == "result", let n = obj["node"],
               let d = try? JSONSerialization.data(withJSONObject: n), let full = try? JSONDecoder().decode(DiskNode.self, from: d) {
                self.explorePath.append(full)
            }
        }, done: { _, _ in self.loadingChildren = nil })
    }

    func explore(path: String) {
        guard let m = map else { return }
        var trail: [DiskNode] = []
        var level = m.roots
        while let n = level.first(where: { path == $0.path || path.hasPrefix($0.path + "/") }) {
            trail.append(n)
            if n.path == path { break }
            level = n.children
        }
        explorePath = trail
    }

    private func findCleanable(model: AppModel) {
        analyzing = true; phase = "Finding what can be cleaned"
        var args = ["analyze", "--state", "\(supportDir)/state.json", "--stale-days", String(staleDays)]
        for w in model.watchDirs { args += ["--watch", w] }
        stream(args, onLine: { obj in
            switch obj["type"] as? String {
            case "progress":
                self.progressTitle = obj["title"] as? String ?? ""
                self.progress = 0.5 + (obj["pct"] as? Double ?? 0) / 200
            case "result":
                if let d = try? JSONSerialization.data(withJSONObject: obj), let r = try? JSONDecoder().decode(StorageResult.self, from: d) {
                    self.result = r
                    self.selected = Set(r.items.filter(\.selected).map(\.id))
                    FileManager.default.createFile(atPath: self.resultFile, contents: d)
                }
            default: break
            }
        }, done: { status, err in
            self.analyzing = false
            if status != 0 { self.error = "Analysis failed: \(err.suffix(300))" }
            self.recordDisk(force: true)
        })
    }

    var staleDays: Int {
        get { UserDefaults.standard.object(forKey: "staleDays") as? Int ?? 30 }
        set { UserDefaults.standard.set(newValue, forKey: "staleDays"); objectWillChange.send() }
    }

    func clean() {
        let chosen = items.filter { selected.contains($0.id) }
        guard !chosen.isEmpty, !cleaning, !analyzing else { return }
        cleaning = true; error = nil; progress = 0; progressTitle = "Starting…"
        let before = Self.diskNow()
        let file = "\(supportDir)/clean-items.json"
        guard let d = try? JSONEncoder().encode(chosen) else { cleaning = false; return }
        FileManager.default.createFile(atPath: file, contents: d, attributes: [.posixPermissions: 0o600])
        var results: [[String: Any]] = []
        stream(["clean", "--items", file], onLine: { obj in
            switch obj["type"] as? String {
            case "progress":
                self.progressTitle = obj["title"] as? String ?? ""
                self.progress = (obj["pct"] as? Double ?? 0) / 100
            case "result":
                results = obj["results"] as? [[String: Any]] ?? []
            default: break
            }
        }, done: { status, err in
            try? FileManager.default.removeItem(atPath: file)
            let after = Self.diskNow()
            var byCat: [String: Int64] = [:]
            var failed: [String] = []
            for r in results {
                guard let id = r["id"] as? String, let item = chosen.first(where: { $0.id == id }) else { continue }
                if r["ok"] as? Bool == true { byCat[item.category, default: 0] += item.size } else { failed.append("\(item.title): \(r["result"] as? String ?? "")") }
            }
            if let b = before, let a = after {
                let rec = CleanRecord(time: Date(), freeBefore: b.free, freeAfter: a.free, total: a.total, byCategory: byCat, failed: failed)
                self.lastClean = rec
                if let data = try? JSONEncoder().encode(rec) { FileManager.default.createFile(atPath: self.cleanFile, contents: data) }
                appendToLog("CLEANUP freed \(bytes(rec.freed)) (\(bytes(b.free)) → \(bytes(a.free)) free)")
            }
            // Drop cleaned items from the list without a full re-analysis.
            let ok = Set(results.filter { $0["ok"] as? Bool == true }.compactMap { $0["id"] as? String })
            if let r = self.result {
                self.result = StorageResult(items: r.items.filter { !ok.contains($0.id) }, projects: r.projects, disk: after ?? r.disk, stale_days: r.stale_days, time: r.time)
                if let data = try? JSONEncoder().encode(self.result) { FileManager.default.createFile(atPath: self.resultFile, contents: data) }
            }
            self.selected.subtract(ok)
            self.cleaning = false
            if status != 0 { self.error = "Cleaning stopped: \(err.suffix(300))" }
            self.recordDisk(force: true)
        })
    }

    struct ArchiveOptions {
        var saveEnv = true
        var push = true
        var createRepo = true
        var remove = "trash"   // trash, delete, keep
        var acceptIgnored = false
    }

    func archive(_ p: DevProject, options: ArchiveOptions) {
        guard archiving == nil else { return }
        archiving = p.path
        archiveResult = [:]
        steps = ["Check for malware", "Save .env files to Notes", "Commit unsaved work", "Push to GitHub", "Check GitHub has everything", "Remove from this Mac"]
            .enumerated().map { ArchiveStep(n: $0.offset + 1, title: $0.element, status: "waiting", detail: "") }
        var args = ["archive", "--project", p.path, "--state", "\(supportDir)/state.json", "--remove", options.remove]
        if !options.saveEnv { args.append("--no-notes") }
        if !options.push { args.append("--no-push") }
        if options.createRepo { args.append("--create-repo") }
        if options.acceptIgnored { args.append("--accept-ignored") }
        let before = Self.diskNow()
        stream(args, onLine: { obj in
            switch obj["type"] as? String {
            case "step":
                guard let n = obj["n"] as? Int, n >= 1, n <= self.steps.count else { return }
                self.steps[n - 1].status = obj["status"] as? String ?? ""
                self.steps[n - 1].detail = obj["detail"] as? String ?? ""
            case "result":
                var r: [String: AnyCodableValue] = [:]
                for (k, v) in obj { r[k] = AnyCodableValue(v) }
                self.archiveResult = r
            default: break
            }
        }, done: { status, err in
            if status != 0 && self.archiveResult.isEmpty { self.archiveResult = ["ok": AnyCodableValue(false), "error": AnyCodableValue("Archive failed: \(err.suffix(300))")] }
            let ok = self.archiveResult["ok"]?.bool == true
            appendToLog("ARCHIVE \(ok ? "DONE" : "STOPPED") \(p.path): \(self.archiveResult["error"]?.string ?? self.steps.last?.detail ?? "")")
            if ok, options.remove != "keep", let r = self.result {
                self.result = StorageResult(items: r.items.filter { $0.path != p.path }, projects: r.projects.filter { $0.path != p.path }, disk: Self.diskNow() ?? r.disk, stale_days: r.stale_days, time: r.time)
                if let data = try? JSONEncoder().encode(self.result) { FileManager.default.createFile(atPath: self.resultFile, contents: data) }
                if let b = before, let a = Self.diskNow(), options.remove == "delete" {
                    self.lastClean = CleanRecord(time: Date(), freeBefore: b.free, freeAfter: a.free, total: a.total, byCategory: ["Archived projects": p.size], failed: [])
                }
            }
            self.archiving = nil
            self.recordDisk(force: true)
        })
    }
}

/// Small wrapper so archive results (strings, numbers, bools) can live in a @Published dictionary.
struct AnyCodableValue: Hashable {
    let raw: String
    let isBool: Bool
    init(_ v: Any) {
        if let b = v as? Bool { raw = b ? "true" : "false"; isBool = true } else { raw = "\(v)"; isBool = false }
    }
    var bool: Bool? { isBool ? raw == "true" : nil }
    var string: String { raw }
}

// MARK: views

struct CleanupView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var store = StorageStore.shared
    @State private var confirmClean = false
    @State private var archiveTarget: DevProject?
    @State private var openCats: Set<String> = []
    @State private var onlyStale = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "Cleanup", subtitle: "See what fills your disk, clear developer caches, and archive old projects to GitHub") {
                    Button { store.analyze(model: model) } label: {
                        HStack(spacing: 6) {
                            if store.analyzing { ProgressView().controlSize(.small).scaleEffect(0.75).frame(width: 14, height: 14) } else { Image(systemName: "magnifyingglass") }
                            Text(store.analyzing ? "Analyzing…" : (store.result == nil ? "Analyze" : "Analyze Again"))
                        }.frame(minWidth: 110)
                    }
                    .controlSize(.large).disabled(store.analyzing || store.cleaning)
                }
                if store.analyzing || store.cleaning { progressCard }
                if let e = store.error { Label(e, systemImage: "exclamationmark.triangle.fill").foregroundColor(cautionOrange) }
                StorageOverview(store: store)
                if let m = store.map {
                    WhereSpaceGoes(map: m)
                    if !m.blocked.isEmpty { FullDiskAccessBanner(blocked: m.blocked) }
                }
                if let rec = store.lastClean { BeforeAfterCard(rec: rec) }
                if let m = store.map, !m.insights.isEmpty {
                    InsightsCard(map: m, store: store) { cat in
                        withAnimation { _ = openCats.insert(cat) }
                    }
                }
                if store.map != nil { ExplorerCard(store: store) }
                HStack(alignment: .top, spacing: 12) {
                    Card { CategoryChart(store: store) }
                    Card { FreeSpaceHistory(points: store.history) }
                }
                if store.result == nil && !store.analyzing {
                    EmptyState(icon: "internaldrive", color: .secondary, title: "Analyze your Mac",
                               detail: "RepoGuard measures Xcode, simulators, package caches, Android images, Docker and your projects. Nothing is deleted until you choose.")
                }
                if !store.items.isEmpty { cleanables }
                if let r = store.result, !r.projects.isEmpty { projects(r) }
                if let m = store.map, !m.large.isEmpty { LargeFilesCard(files: m.large) }
            }
            .padding(24)
        }
        .sheet(isPresented: $confirmClean) { CleanReviewSheet(store: store) }
        .sheet(item: $archiveTarget) { p in ArchiveSheet(project: p, store: store) }
    }

    private var progressCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    Text(store.cleaning ? "Cleaning" : store.phase).font(.callout.weight(.medium))
                    Text(store.progressTitle).font(.callout).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Text("\(Int(store.progress * 100))%").font(.callout.monospacedDigit()).foregroundColor(.secondary)
                }
                ProgressView(value: store.progress)
            }
        }
    }

    private var cleanables: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Safe to clean").font(.headline)
                    Spacer()
                    Text("\(bytes(store.selectedSize)) selected of \(bytes(store.reclaimable))").foregroundColor(.secondary).font(.callout)
                    Button { confirmClean = true } label: { Label("Review & Clean…", systemImage: "sparkles") }
                        .buttonStyle(.borderedProminent).disabled(store.selected.isEmpty || store.cleaning || store.analyzing)
                }
                ForEach(store.categories, id: \.self) { cat in
                    categoryRow(cat)
                    if cat != store.categories.last { Divider() }
                }
            }
        }
    }

    private func categoryRow(_ cat: String) -> some View {
        let its = store.items.filter { $0.category == cat }.sorted { $0.size > $1.size }
        let open = openCats.contains(cat)
        let selCount = its.filter { store.selected.contains($0.id) }.count
        return VStack(alignment: .leading, spacing: 6) {
            Button {
                withAnimation(.snappy(duration: 0.25)) { if open { openCats.remove(cat) } else { openCats.insert(cat) } }
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .bold)).foregroundColor(.secondary).rotationEffect(.degrees(open ? 90 : 0))
                    Circle().fill(categoryColor(cat)).frame(width: 9, height: 9)
                    Text(cat).font(.body.weight(.medium))
                    Text("\(its.count) item\(its.count == 1 ? "" : "s") · \(selCount) selected").font(.caption).foregroundColor(.secondary)
                    Spacer()
                    Text(bytes(store.size(of: cat))).font(.body.monospacedDigit())
                }.contentShape(Rectangle())
            }.buttonStyle(.plain)
            if open {
                ForEach(its) { it in
                    HStack(alignment: .top, spacing: 10) {
                        Toggle("", isOn: Binding(get: { store.selected.contains(it.id) },
                                                 set: { on in if on { store.selected.insert(it.id) } else { store.selected.remove(it.id) } }))
                            .labelsHidden().toggleStyle(.checkbox)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(it.title).lineLimit(1)
                            Text(it.detail).font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer()
                        Text(bytes(it.size)).font(.callout.monospacedDigit()).foregroundColor(.secondary)
                    }
                    .padding(.leading, 30)
                }
            }
        }
    }

    private func projects(_ r: StorageResult) -> some View {
        let all = r.projects
        let shown = onlyStale ? all.filter { $0.idle_days >= r.stale_days } : all
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Projects").font(.headline)
                    Spacer()
                    Picker("", selection: $onlyStale) {
                        Text("Not opened in \(r.stale_days)+ days").tag(true)
                        Text("All \(all.count)").tag(false)
                    }.pickerStyle(.segmented).labelsHidden().frame(width: 300)
                }
                Text("Archive saves each project's .env files to Notes, commits unsaved work to a new branch, pushes every branch to GitHub without force, checks GitHub has it all, and only then removes the folder.")
                    .font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                if shown.isEmpty {
                    Text(onlyStale ? "Every project was used in the last \(r.stale_days) days." : "No projects found.").foregroundColor(.secondary)
                }
                ForEach(shown.sorted { $0.size > $1.size }) { p in
                    ProjectRow(p: p, archive: { archiveTarget = p }, busy: store.archiving != nil)
                    if p.id != shown.sorted(by: { $0.size > $1.size }).last?.id { Divider() }
                }
            }
        }
    }
}

let categoryPalette: [String: Color] = [
    "Old projects": Color(red: 0.36, green: 0.42, blue: 0.95), "Simulators": Color(red: 0.12, green: 0.62, blue: 0.86),
    "Xcode": Color(red: 0.20, green: 0.70, blue: 0.62), "Package caches": Color(red: 0.95, green: 0.62, blue: 0.16),
    "Android": Color(red: 0.42, green: 0.72, blue: 0.27), "Docker": Color(red: 0.13, green: 0.47, blue: 0.80),
    "Downloads": Color(red: 0.78, green: 0.38, blue: 0.80), "System": Color(red: 0.55, green: 0.55, blue: 0.60),
    "Archived projects": Color(red: 0.36, green: 0.42, blue: 0.95),
    "Build output": Color(red: 0.90, green: 0.40, blue: 0.40), "Editors": Color(red: 0.60, green: 0.45, blue: 0.85),
]
func categoryColor(_ c: String) -> Color { categoryPalette[c] ?? .gray }

struct StorageOverview: View {
    @ObservedObject var store: StorageStore
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Macintosh HD").font(.headline)
                    Spacer()
                    if let d = store.disk {
                        Text("\(bytes(d.free)) free of \(bytes(d.total))").foregroundColor(.secondary)
                        if store.selectedSize > 0 {
                            Image(systemName: "arrow.right").foregroundColor(.secondary).font(.caption)
                            Text("\(bytes(d.free + min(store.selectedSize, d.total - d.free))) after cleaning").foregroundColor(safeGreen).fontWeight(.medium)
                        }
                    }
                }
                if let d = store.disk {
                    let used = d.total - d.free
                    let can = min(store.reclaimable, used)
                    let sel = min(store.selectedSize, can)
                    GeometryReader { g in
                        let w = g.size.width
                        HStack(spacing: 2) {
                            Rectangle().fill(Color.secondary.opacity(0.45)).frame(width: max(0, w * CGFloat(used - can) / CGFloat(d.total)))
                            Rectangle().fill(Color.accentColor.opacity(0.45)).frame(width: max(0, w * CGFloat(can - sel) / CGFloat(d.total)))
                            Rectangle().fill(Color.accentColor).frame(width: max(0, w * CGFloat(sel) / CGFloat(d.total)))
                            Rectangle().fill(safeGreen.opacity(0.35))
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 7))
                    }
                    .frame(height: 22)
                    HStack(spacing: 18) {
                        Legend(color: Color.secondary.opacity(0.45), title: "Used", value: bytes(used - can))
                        Legend(color: Color.accentColor.opacity(0.45), title: "Could also free", value: bytes(can - sel))
                        Legend(color: .accentColor, title: "Selected to clean", value: bytes(sel))
                        Legend(color: safeGreen.opacity(0.35), title: "Free", value: bytes(d.free))
                        Spacer()
                    }
                }
            }
        }
    }
}

struct Legend: View {
    let color: Color; let title: String; let value: String
    var body: some View {
        HStack(spacing: 6) {
            RoundedRectangle(cornerRadius: 3).fill(color).frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(.caption).foregroundColor(.secondary).lineLimit(1)
                Text(value).font(.callout.monospacedDigit()).lineLimit(1).fixedSize()
            }
        }
    }
}

struct BeforeAfterCard: View {
    let rec: CleanRecord
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "checkmark.circle.fill").foregroundColor(safeGreen)
                    Text("Last cleanup freed \(bytes(rec.freed))").font(.headline)
                    Spacer()
                    Text(relativeTime(rec.time)).foregroundColor(.secondary).font(.callout)
                }
                Chart {
                    BarMark(x: .value("Free", Double(rec.freeBefore) / 1e9), y: .value("When", "Before"))
                        .foregroundStyle(Color.secondary.opacity(0.5))
                        .annotation(position: .trailing) { Text(bytes(rec.freeBefore)).font(.caption.monospacedDigit()) }
                    BarMark(x: .value("Free", Double(rec.freeAfter) / 1e9), y: .value("When", "After"))
                        .foregroundStyle(safeGreen)
                        .annotation(position: .trailing) { Text(bytes(rec.freeAfter)).font(.caption.monospacedDigit()) }
                }
                .chartXAxisLabel("Free space (GB)")
                .chartXScale(domain: 0...(Double(rec.total) / 1e9 * 0.25 + Double(rec.freeAfter) / 1e9))
                .frame(height: 90)
                if !rec.byCategory.isEmpty {
                    HStack(spacing: 14) {
                        ForEach(rec.byCategory.sorted { $0.value > $1.value }, id: \.key) { k, v in
                            Legend(color: categoryColor(k), title: k, value: bytes(v))
                        }
                    }
                }
                if !rec.failed.isEmpty {
                    Text("Not cleaned: " + rec.failed.prefix(3).joined(separator: "; ")).font(.caption).foregroundColor(cautionOrange)
                }
            }
        }
    }
}

struct CategoryChart: View {
    @ObservedObject var store: StorageStore
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("What can be freed").font(.headline)
                Spacer()
                Text(bytes(store.reclaimable)).foregroundColor(.secondary).font(.callout)
            }
            if store.items.isEmpty {
                Text("Analyze to see a breakdown.").foregroundColor(.secondary).frame(maxWidth: .infinity, minHeight: 170)
            } else {
                let data = store.categories.map { ($0, store.size(of: $0)) }
                HStack(spacing: 14) {
                    if #available(macOS 14, *) {
                        Chart(data, id: \.0) { c, s in
                            SectorMark(angle: .value("Size", Double(s)), innerRadius: .ratio(0.62), angularInset: 1.2)
                                .foregroundStyle(categoryColor(c)).cornerRadius(3)
                        }
                        .frame(width: 120, height: 120)
                    }
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(data, id: \.0) { c, s in
                            HStack(spacing: 6) {
                                Circle().fill(categoryColor(c)).frame(width: 8, height: 8)
                                Text(c).font(.callout).lineLimit(1).minimumScaleFactor(0.85)
                                Spacer(minLength: 6)
                                Text(bytes(s)).font(.callout.monospacedDigit()).foregroundColor(.secondary).lineLimit(1).fixedSize()
                            }
                        }
                    }
                    .frame(minWidth: 150)
                }
            }
        }
    }
}

struct FreeSpaceHistory: View {
    let points: [DiskPoint]
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Free space over time").font(.headline)
                Spacer()
                if let f = points.first, let l = points.last, points.count > 1 {
                    let delta = l.free - f.free
                    Text("\(delta >= 0 ? "+" : "−")\(bytes(abs(delta))) since \(f.time.formatted(.dateTime.month().day()))")
                        .font(.callout).foregroundColor(delta >= 0 ? safeGreen : cautionOrange)
                }
            }
            if points.count < 2 {
                Text("Builds up as you use RepoGuard and clean.").foregroundColor(.secondary).frame(maxWidth: .infinity, minHeight: 170)
            } else {
                Chart(points) { p in
                    AreaMark(x: .value("Time", p.time), y: .value("Free GB", Double(p.free) / 1e9))
                        .foregroundStyle(LinearGradient(colors: [safeGreen.opacity(0.35), safeGreen.opacity(0.03)], startPoint: .top, endPoint: .bottom))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("Time", p.time), y: .value("Free GB", Double(p.free) / 1e9))
                        .foregroundStyle(safeGreen).interpolationMethod(.monotone)
                }
                .chartYAxisLabel("GB free")
                .frame(height: 170)
            }
        }
    }
}

struct ProjectRow: View {
    let p: DevProject
    let archive: () -> Void
    let busy: Bool
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: p.infected ? "xmark.shield.fill" : "folder.fill").font(.title3)
                .foregroundColor(p.infected ? dangerRed : .accentColor).frame(width: 24)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(p.name).font(.body.weight(.medium))
                    Text(p.parent).foregroundColor(.secondary)
                }
                HStack(spacing: 6) {
                    Pill(text: p.idle_days >= 9999 ? "never opened" : "\(p.idle_days)d idle", color: p.idle_days >= 60 ? cautionOrange : .secondary)
                    if !p.git { Pill(text: "no git", color: cautionOrange) }
                    else if p.remote.isEmpty { Pill(text: "no GitHub remote", color: cautionOrange) }
                    if p.dirty > 0 { Pill(text: "\(p.dirty) unsaved", color: cautionOrange) }
                    if p.unpushed > 0 { Pill(text: "\(p.unpushed) unpushed", color: cautionOrange) }
                    if !p.no_upstream.isEmpty { Pill(text: "\(p.no_upstream.count) local-only branch\(p.no_upstream.count == 1 ? "" : "es")", color: cautionOrange) }
                    if p.stashes > 0 { Pill(text: "\(p.stashes) stash", color: .secondary) }
                    if !p.envs.isEmpty { Pill(text: "\(p.envs.count) .env", color: .accentColor) }
                    if p.infected { Pill(text: "malware", color: dangerRed) }
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(bytes(p.size)).font(.body.monospacedDigit())
                if p.rebuild_size > 0 { Text("\(bytes(p.rebuild_size)) rebuildable").font(.caption).foregroundColor(.secondary) }
            }
            Button("Archive…", action: archive).disabled(busy || p.infected)
                .help(p.infected ? "Remove the malware first, so it isn't pushed to GitHub." : "Save .env to Notes, push everything to GitHub, then remove the folder")
        }
    }
}

struct ArchiveSheet: View {
    let project: DevProject
    @ObservedObject var store: StorageStore
    @Environment(\.dismiss) private var dismiss
    @State private var opts = StorageStore.ArchiveOptions()
    @State private var started = false

    private var running: Bool { store.archiving == project.path }
    private var finished: Bool { started && !running }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(Color.accentColor.opacity(0.15)).frame(width: 44, height: 44)
                    Image(systemName: "archivebox.fill").foregroundColor(.accentColor).font(.title3)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Archive \(project.parent)/\(project.name)").font(.title3.bold())
                    Text("\(bytes(project.size)) · not opened in \(project.idle_days) days").foregroundColor(.secondary)
                }
            }
            if !started {
                Form {
                    Section {
                        Toggle("Save \(project.envs.count) .env file\(project.envs.count == 1 ? "" : "s") to Notes", isOn: $opts.saveEnv).disabled(project.envs.isEmpty)
                        Toggle("Push every branch to GitHub", isOn: $opts.push)
                        Toggle("Create a private GitHub repo if it has none", isOn: $opts.createRepo).disabled(!opts.push)
                    } footer: {
                        Text("Unsaved changes are committed to a new branch, never on top of yours. Nothing is force-pushed; a branch GitHub already moved past is pushed under a new name. .env files are never committed. Notes syncs with iCloud, so lock the note in Notes if you want it password-protected.")
                    }
                    Section {
                        Picker("Then", selection: $opts.remove) {
                            Text("Move the folder to the Trash").tag("trash")
                            Text("Delete it now (frees space immediately)").tag("delete")
                            Text("Keep the folder").tag("keep")
                        }
                        Toggle("Remove even if git-ignored files would be lost", isOn: $opts.acceptIgnored)
                    } footer: {
                        Text("The folder is only removed after GitHub is confirmed to have every commit. Ignored files that aren't rebuildable (local databases, uploads) stop the archive unless you allow it.")
                    }
                }
                .formStyle(.grouped).scrollContentBackground(.hidden).frame(height: 330)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(store.steps) { s in
                        HStack(alignment: .top, spacing: 10) {
                            Group {
                                switch s.status {
                                case "running": ProgressView().controlSize(.small)
                                case "done": Image(systemName: "checkmark.circle.fill").foregroundColor(safeGreen)
                                case "failed": Image(systemName: "xmark.octagon.fill").foregroundColor(dangerRed)
                                case "skipped": Image(systemName: "minus.circle").foregroundColor(.secondary)
                                default: Image(systemName: "circle").foregroundColor(.secondary)
                                }
                            }.frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.title).foregroundColor(s.status == "waiting" || s.status == "skipped" ? .secondary : .primary)
                                if !s.detail.isEmpty { Text(s.detail).font(.caption).foregroundColor(s.status == "failed" ? dangerRed : .secondary).fixedSize(horizontal: false, vertical: true) }
                            }
                        }
                    }
                    let done = store.steps.filter { $0.status == "done" || $0.status == "skipped" || $0.status == "failed" }.count
                    ProgressView(value: Double(done), total: Double(max(1, store.steps.count))).padding(.top, 4)
                    if finished {
                        if store.archiveResult["ok"]?.bool == true {
                            Label("Archived. Everything is on GitHub.", systemImage: "checkmark.seal.fill").foregroundColor(safeGreen)
                        } else if let e = store.archiveResult["error"]?.string {
                            Label("Stopped, nothing was removed: \(e)", systemImage: "exclamationmark.triangle.fill").foregroundColor(cautionOrange).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .frame(minHeight: 330, alignment: .top)
            }
            HStack {
                Spacer()
                if !started {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Archive") { started = true; store.archive(project, options: opts) }
                        .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                } else {
                    Button("Done") { dismiss() }.disabled(running).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}

/// Shown before anything is deleted: every selected item with its path, grouped by category, each with
/// its own checkbox. Items that hold the person's own data (simulators, runtimes, archives, Downloads,
/// emulators) are marked, so nothing like that goes without being seen.
struct CleanReviewSheet: View {
    @ObservedObject var store: StorageStore
    @Environment(\.dismiss) private var dismiss
    /// The rows stay listed after being unticked, so a mis-click can be undone.
    @State private var listed: [CleanItem] = []

    static func holdsData(_ it: CleanItem) -> Bool {
        ["simulator", "runtime", "trash", "avd", "backupfile"].contains(it.kind) || it.id == "xcode-archives" || it.category == "Old projects"
    }

    private var chosen: [CleanItem] { listed.filter { store.selected.contains($0.id) } }
    private var chosenSize: Int64 { chosen.reduce(0) { $0 + $1.size } }
    private var cats: [String] { store.categories.filter { c in listed.contains { $0.category == c } } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(cautionOrange.opacity(0.15)).frame(width: 44, height: 44)
                    Image(systemName: "trash.fill").foregroundColor(cautionOrange).font(.title3)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Review what will be deleted").font(.title3.bold())
                    Text("Untick anything you want to keep. Caches and build folders are rebuilt when needed; items marked “your data” are gone for good. Files from Downloads go to the Trash.")
                        .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            HStack(spacing: 10) {
                Button("Select All") { store.selected.formUnion(listed.map(\.id)) }
                Button("Only Caches") {
                    store.selected.subtract(listed.filter(Self.holdsData).map(\.id))
                }.help("Untick simulators, runtimes, archives, Downloads and other items that hold your data")
                Button("Select None") { store.selected.subtract(listed.map(\.id)) }
                Spacer()
                let dataCount = chosen.filter(Self.holdsData).count
                if dataCount > 0 { Pill(text: "\(dataCount) with your data", color: cautionOrange) }
            }.controlSize(.small)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(cats, id: \.self) { cat in
                        let its = listed.filter { $0.category == cat }
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 8) {
                                Circle().fill(categoryColor(cat)).frame(width: 9, height: 9)
                                Text(cat).font(.headline)
                                Spacer()
                                Text(bytes(its.filter { store.selected.contains($0.id) }.reduce(0) { $0 + $1.size })).font(.callout.monospacedDigit()).foregroundColor(.secondary)
                            }
                            ForEach(its) { it in row(it) }
                        }
                        if cat != cats.last { Divider() }
                    }
                }.padding(.trailing, 8)
            }
            .frame(minHeight: 260, maxHeight: 440)
            HStack {
                Text("\(chosen.count) of \(listed.count) items · \(bytes(chosenSize))").foregroundColor(.secondary).font(.callout)
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(role: .destructive) { store.clean(); dismiss() } label: {
                    Text(chosen.isEmpty ? "Delete" : "Delete \(chosen.count) item\(chosen.count == 1 ? "" : "s") (\(bytes(chosenSize)))")
                }
                .buttonStyle(.borderedProminent).tint(dangerRed).disabled(chosen.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 640)
        .onAppear { listed = store.items.filter { store.selected.contains($0.id) }.sorted { $0.size > $1.size } }
    }

    private func row(_ it: CleanItem) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Toggle("", isOn: Binding(get: { store.selected.contains(it.id) },
                                     set: { on in if on { store.selected.insert(it.id) } else { store.selected.remove(it.id) } }))
                .labelsHidden().toggleStyle(.checkbox)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(it.title).lineLimit(1)
                    if Self.holdsData(it) { Pill(text: "your data", color: cautionOrange) }
                }
                if !it.path.isEmpty {
                    Text(it.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")).font(.caption.monospaced()).foregroundColor(.secondary)
                        .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                }
                Text(it.detail).font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Text(bytes(it.size)).font(.callout.monospacedDigit()).foregroundColor(.secondary)
        }
        .padding(.leading, 17)
        .opacity(store.selected.contains(it.id) ? 1 : 0.55)
    }
}
