import AppKit
import Charts
import SwiftUI

// Where the disk space goes: the whole APFS container split into macOS, swap, apps, home folders and
// what RepoGuard can't read, plus plain-language insights, a drill-down explorer and large files.

private let segmentColors: [Color] = [
    Color(red: 0.36, green: 0.42, blue: 0.95), Color(red: 0.12, green: 0.62, blue: 0.86), Color(red: 0.95, green: 0.62, blue: 0.16),
    Color(red: 0.42, green: 0.72, blue: 0.27), Color(red: 0.78, green: 0.38, blue: 0.80), Color(red: 0.20, green: 0.70, blue: 0.62),
    Color(red: 0.90, green: 0.40, blue: 0.40),
]

struct Segment: Identifiable, Hashable {
    var id: String { name }
    let name: String
    let size: Int64
    let color: Color
    var path: String = ""
}

func segments(for m: DiskMap) -> [Segment] {
    guard let c = m.container else { return [] }
    var out: [Segment] = []
    let sys = c.volumes.filter { ["System", "Preboot", "Recovery", "Update"].contains($0.role) }.reduce(0) { $0 + $1.used }
    let vm = c.volumes.filter { $0.role == "VM" }.reduce(0) { $0 + $1.used }
    let data = c.volumes.filter { $0.role == "Data" }.reduce(0) { $0 + $1.used }
    out.append(Segment(name: "macOS", size: sys, color: Color.gray.opacity(0.75)))
    if vm > 0 { out.append(Segment(name: "Swap", size: vm, color: Color.gray.opacity(0.5)) )}
    var measured: Int64 = 0
    var i = 0
    if let home = m.roots.first {
        // the biggest folders of the home folder each get their own colour, the rest are grouped
        let top = home.children.prefix(5)
        for n in top {
            out.append(Segment(name: n.name.hasPrefix(".") ? n.name : (n.name == "Library" ? "Library (apps' data)" : n.name), size: n.size, color: segmentColors[i % segmentColors.count], path: n.path))
            i += 1
        }
        let rest = home.size - top.reduce(0) { $0 + $1.size }
        if rest > 0 { out.append(Segment(name: "Rest of home folder", size: rest, color: segmentColors[5], path: home.path)) }
        measured += home.size
    }
    let others = m.roots.dropFirst().reduce(0) { $0 + $1.size }
    if let apps = m.roots.first(where: { $0.path == "/Applications" }) {
        out.append(Segment(name: "Applications", size: apps.size, color: segmentColors[6], path: apps.path))
        out.append(Segment(name: "Homebrew and system files", size: others - apps.size, color: Color.brown.opacity(0.7)))
    } else {
        out.append(Segment(name: "Other folders", size: others, color: Color.brown.opacity(0.7)))
    }
    measured += others
    let unknown = max(0, data - measured)
    if unknown > 0 {
        out.append(Segment(name: m.blocked.isEmpty ? "Other system data" : "Can't see yet", size: unknown, color: Color.secondary.opacity(0.35)))
    }
    out.append(Segment(name: "Free", size: c.free, color: safeGreen.opacity(0.45)))
    return out.filter { $0.size > 0 }
}

struct WhereSpaceGoes: View {
    let map: DiskMap
    @State private var hover: String?
    var body: some View {
        let segs = segments(for: map)
        let total = max(1, segs.reduce(0) { $0 + $1.size })
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Where your space goes").font(.headline)
                    Spacer()
                    Text("Measured \(relativeTime(parseEngineTime(map.time)))").font(.callout).foregroundColor(.secondary)
                }
                GeometryReader { g in
                    HStack(spacing: 1.5) {
                        ForEach(segs) { s in
                            Rectangle().fill(s.color)
                                .frame(width: max(2, (g.size.width - CGFloat(segs.count) * 1.5) * CGFloat(s.size) / CGFloat(total)))
                                .opacity(hover == nil || hover == s.name ? 1 : 0.35)
                                .onHover { hover = $0 ? s.name : nil }
                                .help("\(s.name): \(bytes(s.size))")
                        }
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 7))
                }
                .frame(height: 26)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 10, alignment: .leading)], alignment: .leading, spacing: 8) {
                    ForEach(segs) { s in
                        Legend(color: s.color, title: s.name, value: bytes(s.size))
                            .opacity(hover == nil || hover == s.name ? 1 : 0.45)
                            .onHover { hover = $0 ? s.name : nil }
                    }
                }
            }
        }
    }
}

let fullDiskAccessURL = URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles")!

struct FullDiskAccessBanner: View {
    let blocked: [Blocked]
    var body: some View {
        Card {
            HStack(spacing: 14) {
                Image(systemName: "lock.shield").font(.title2).foregroundColor(cautionOrange)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Some space is hidden from RepoGuard").font(.headline)
                    Text("macOS keeps \(blocked.map(\.name).joined(separator: ", ")) private. Give RepoGuard Full Disk Access to measure them (nothing there is deleted without asking), then choose Analyze Again.")
                        .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button("Open Settings") { NSWorkspace.shared.open(fullDiskAccessURL) }.controlSize(.large)
            }
        }
    }
}

struct InsightsCard: View {
    let map: DiskMap
    @ObservedObject var store: StorageStore
    let showCategory: (String) -> Void
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 12) {
                Text("Why the disk is full").font(.headline)
                ForEach(map.insights) { i in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: icon(i)).font(.title3).foregroundColor(.accentColor).frame(width: 26)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(i.title).font(.body.weight(.medium))
                                Spacer()
                                Text(bytes(i.size)).font(.body.monospacedDigit())
                            }
                            Text(i.detail).font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                            if let b = button(i) { b.padding(.top, 2) }
                        }
                    }
                    if i.id != map.insights.last?.id { Divider() }
                }
            }
        }
    }

    private func icon(_ i: Insight) -> String {
        switch true {
        case i.title.contains("Docker"): return "shippingbox"
        case i.title.contains("simulator"): return "iphone"
        case i.title.contains("Android"): return "smartphone"
        case i.title.contains("Cursor"): return "bubble.left.and.text.bubble.right"
        case i.title.contains("iCloud"): return "icloud"
        case i.title.contains("macOS"): return "apple.logo"
        case i.title.contains("Swap"): return "memorychip"
        case i.title.contains("can't see"): return "eye.slash"
        case i.title.contains("Applications"): return "square.grid.2x2"
        case i.title.contains("Hidden"): return "folder.badge.gearshape"
        default: return "folder"
        }
    }

    private func button(_ i: Insight) -> AnyView? {
        if i.action == "fda" { return AnyView(Button("Open Full Disk Access Settings") { NSWorkspace.shared.open(fullDiskAccessURL) }.controlSize(.small)) }
        if i.action == "explore" { return AnyView(Button("Explore") { store.explore(path: i.path) }.controlSize(.small)) }
        if i.action == "reveal" { return AnyView(Button("Show in Finder") { reveal(i.path) }.controlSize(.small)) }
        if i.action.hasPrefix("category:") {
            let cat = String(i.action.dropFirst(9))
            if store.items.contains(where: { $0.category == cat }) {
                return AnyView(Button("Show in Safe to clean") { showCategory(cat) }.controlSize(.small))
            }
        }
        return nil
    }
}

func reveal(_ path: String) {
    let url = URL(fileURLWithPath: path)
    if FileManager.default.fileExists(atPath: path) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
    else { NSWorkspace.shared.open(url.deletingLastPathComponent()) }
}

/// Only your own files can be moved to the Trash from here; app data and system folders can't.
func trashable(_ path: String) -> Bool {
    let mine = ["Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures"].map { "\(home)/\($0)/" }
    return mine.contains { path.hasPrefix($0) }
}

struct ExplorerCard: View {
    @ObservedObject var store: StorageStore
    @State private var confirmTrash: DiskNode?

    var body: some View {
        let roots = store.map?.roots ?? []
        let current = store.explorePath.last
        let rows = current?.children ?? roots
        let parentSize = current?.size ?? max(1, roots.reduce(0) { $0 + $1.size })
        return Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Text("Explore").font(.headline)
                    Spacer()
                    if store.loadingChildren != nil { ProgressView().controlSize(.small); Text("Measuring…").font(.caption).foregroundColor(.secondary) }
                }
                // breadcrumb
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 4) {
                        Button("All") { store.explorePath = [] }.buttonStyle(.link)
                        ForEach(Array(store.explorePath.enumerated()), id: \.offset) { idx, n in
                            Image(systemName: "chevron.right").font(.caption2).foregroundColor(.secondary)
                            Button(idx == 0 ? n.name : (n.path as NSString).lastPathComponent) { store.explorePath = Array(store.explorePath.prefix(idx + 1)) }
                                .buttonStyle(.link).lineLimit(1)
                        }
                    }
                }
                if let c = current {
                    HStack {
                        Text((c.path as NSString).abbreviatingWithTildeInPath).font(.system(.caption, design: .monospaced)).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(bytes(c.size)).font(.callout.monospacedDigit())
                        Button("Show in Finder") { reveal(c.path) }.controlSize(.small)
                    }
                }
                if rows.isEmpty {
                    Text("Nothing here is 100 MB or more.").foregroundColor(.secondary)
                }
                ForEach(rows.prefix(25)) { n in
                    HStack(spacing: 10) {
                        Image(systemName: "folder.fill").foregroundColor(.accentColor.opacity(0.8))
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(current == nil ? n.name : (n.path as NSString).lastPathComponent).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Text(bytes(n.size)).font(.callout.monospacedDigit()).foregroundColor(.secondary)
                            }
                            GeometryReader { g in
                                Capsule().fill(Color.accentColor.opacity(0.75))
                                    .frame(width: max(3, g.size.width * CGFloat(n.size) / CGFloat(max(1, parentSize))))
                            }
                            .frame(height: 5)
                        }
                        Button { reveal(n.path) } label: { Image(systemName: "magnifyingglass") }.buttonStyle(.borderless).help("Show in Finder")
                        if trashable(n.path) {
                            Button { confirmTrash = n } label: { Image(systemName: "trash") }.buttonStyle(.borderless).help("Move to Trash")
                        }
                        Button { store.explore(n) } label: { Image(systemName: "chevron.right") }.buttonStyle(.borderless)
                            .disabled(store.loadingChildren != nil).help("Open")
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { store.explore(n) }
                }
            }
        }
        .alert(item: $confirmTrash) { n in
            Alert(title: Text("Move \((n.path as NSString).lastPathComponent) to the Trash?"),
                  message: Text("\(bytes(n.size)) at \((n.path as NSString).abbreviatingWithTildeInPath). You can put it back from the Trash until you empty it."),
                  primaryButton: .destructive(Text("Move to Trash")) {
                      NSWorkspace.shared.recycle([URL(fileURLWithPath: n.path)]) { _, error in
                          if error == nil { DispatchQueue.main.async { store.removeFromMap(n.path) } }
                      }
                  },
                  secondaryButton: .cancel())
        }
    }
}

struct LargeFilesCard: View {
    let files: [LargeFile]
    @State private var confirm: LargeFile?
    @State private var gone: Set<String> = []
    var body: some View {
        let shown = files.filter { !gone.contains($0.path) && FileManager.default.fileExists(atPath: $0.path) }
        return Card {
            VStack(alignment: .leading, spacing: 9) {
                Text("Largest files").font(.headline)
                Text("Real space on disk. Some files, like Docker's, report a much bigger size than they use.").font(.caption).foregroundColor(.secondary)
                ForEach(shown.prefix(15)) { f in
                    HStack(spacing: 10) {
                        Image(systemName: "doc.fill").foregroundColor(.secondary)
                        VStack(alignment: .leading, spacing: 1) {
                            Text((f.path as NSString).lastPathComponent).lineLimit(1).truncationMode(.middle)
                            Text(((f.path as NSString).deletingLastPathComponent as NSString).abbreviatingWithTildeInPath)
                                .font(.system(.caption, design: .monospaced)).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Text(bytes(f.size)).font(.callout.monospacedDigit())
                        Button { reveal(f.path) } label: { Image(systemName: "magnifyingglass") }.buttonStyle(.borderless).help("Show in Finder")
                        if trashable(f.path) {
                            Button { confirm = f } label: { Image(systemName: "trash") }.buttonStyle(.borderless).help("Move to Trash")
                        }
                    }
                }
            }
        }
        .alert(item: $confirm) { f in
            Alert(title: Text("Move \((f.path as NSString).lastPathComponent) to the Trash?"), message: Text(bytes(f.size)),
                  primaryButton: .destructive(Text("Move to Trash")) {
                      NSWorkspace.shared.recycle([URL(fileURLWithPath: f.path)]) { _, e in if e == nil { DispatchQueue.main.async { gone.insert(f.path) } } }
                  }, secondaryButton: .cancel())
        }
    }
}
