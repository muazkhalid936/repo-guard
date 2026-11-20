import AppKit
import SwiftUI

// Review before removing: the cleaner works out every change first (changing nothing), the person
// reads exactly which files are deleted and which code is cut, and only an approval runs it.

struct PlanItem: Decodable, Identifiable, Hashable {
    let repo: String
    let path: String
    let action: String          // delete | clean | manual
    var why: String? = nil
    let notes: [String]
    let removed: [String]
    let kept: [String]
    let more_removed: Int
    let more_kept: Int
    let removed_chars: Int
    let `where`: [String]
    let found: [String]
    var id: String { repo + "|" + path + "|" + `where`.joined(separator: ",") }
}

struct PlanRef: Decodable, Hashable {
    let repo: String
    let ref: String
    let kind: String            // github | branch | tag
    let files: [String]
    var checked_out: Bool? = nil
    var plan: String? = nil     // move | commit
}

struct PlanNote: Decodable, Hashable { let path: String; let why: String }

struct CleanPlan: Decodable, Identifiable {
    let fingerprint: String
    let items: [PlanItem]
    let refs: [PlanRef]
    let manual: [PlanNote]
    let skipped: [PlanNote]
    var id: String { fingerprint }
}

struct GHPlanBranch: Decodable, Identifiable, Hashable {
    let id: String
    let repo: String
    let branch: String
    let items: [PlanItem]
    let error: String
}

struct GHPlan: Decodable, Identifiable {
    let branches: [GHPlanBranch]
    var id: String { branches.map(\.id).joined(separator: ",") }
}

enum CleanMode: String, CaseIterable, Identifiable {
    case mac = "This Mac only", github = "This Mac and GitHub", permanent = "Permanently"
    var id: String { rawValue }
    var detail: String {
        switch self {
        case .mac: return "Cleans your files and local branches. GitHub is not touched."
        case .github: return "Also pushes one \"Remove malware (RepoGuard)\" commit to each infected GitHub branch. A normal push, no force-push, so no history is rewritten. Teammates will see that commit."
        case .permanent: return "Also deletes infected tags and purges the infected commits from this Mac's git history. This can't be undone."
        }
    }
}

private func shortPath(_ p: String) -> String { p.replacingOccurrences(of: home + "/", with: "~/") }

// MARK: one file

struct PlanItemRow: View {
    let item: PlanItem
    var startOpen = false
    @State private var showCode = false

    private var icon: (String, Color) {
        switch item.action {
        case "delete": return ("trash.fill", dangerRed)
        case "clean": return ("scissors", cautionOrange)
        default: return ("hand.raised.fill", .secondary)
        }
    }
    private var headline: String {
        switch item.action {
        case "delete": return "Delete the whole file. All of it is malware."
        case "clean": return "Cut out \(item.removed_chars.formatted()) characters of malware and keep the rest of the file."
        default: return "Left unchanged; needs a manual look: \(item.why ?? "")"
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon.0).foregroundColor(icon.1).frame(width: 20).padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text(item.path).font(.system(.body, design: .monospaced).bold()).textSelection(.enabled)
                Text(headline).font(.callout)
                Text("Found: " + item.found.joined(separator: " · ")).font(.caption).foregroundColor(.secondary)
                Text("In: " + item.where.joined(separator: " · ")).font(.caption).foregroundColor(.secondary)
                if !item.notes.isEmpty {
                    Text("Changes: " + item.notes.joined(separator: " · ")).font(.caption).foregroundColor(.secondary)
                }
                if !item.removed.isEmpty {
                    Button(showCode ? "Hide code" : "Show the code being removed") { withAnimation(.snappy) { showCode.toggle() } }
                        .buttonStyle(.link).font(.callout)
                    if showCode { codeBox }
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 6)
        .onAppear { if startOpen { showCode = true } }
    }

    private var codeBox: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(item.action == "delete" ? "File contents (all removed):" : "Removed lines:").font(.caption.bold()).foregroundColor(dangerRed)
            ForEach(Array(item.removed.enumerated()), id: \.offset) { _, l in
                Text("− " + l).foregroundColor(dangerRed)
            }
            if item.more_removed > 0 { Text("… and \(item.more_removed) more lines").foregroundColor(.secondary) }
            if !item.kept.isEmpty {
                Text("Replaced with (your code, kept):").font(.caption.bold()).foregroundColor(safeGreen).padding(.top, 6)
                ForEach(Array(item.kept.enumerated()), id: \.offset) { _, l in
                    Text("+ " + l).foregroundColor(safeGreen)
                }
                if item.more_kept > 0 { Text("… and \(item.more_kept) more lines").foregroundColor(.secondary) }
            } else if item.action == "clean" {
                Text("Those lines are removed with nothing in their place.").font(.caption).foregroundColor(.secondary).padding(.top, 4)
            }
            Text("RepoGuard only shows this code as text. It never runs it.").font(.caption2).foregroundColor(.secondary).padding(.top, 4)
        }
        .font(.system(.caption, design: .monospaced))
        .textSelection(.enabled)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
    }
}

private func summaryLine(_ items: [PlanItem]) -> String {
    let d = items.filter { $0.action == "delete" }.count
    let c = items.filter { $0.action == "clean" }.count
    let m = items.filter { $0.action == "manual" }.count
    var parts: [String] = []
    if d > 0 { parts.append("delete \(d) file\(d == 1 ? "" : "s")") }
    if c > 0 { parts.append("cut malware out of \(c) file\(c == 1 ? "" : "s")") }
    var s = parts.isEmpty ? "Nothing can be removed automatically." : "RepoGuard will " + parts.joined(separator: " and ") + "."
    if m > 0 { s += " \(m) will be left for you to check by hand." }
    return s
}

// MARK: local Remove Malware

struct CleanPreviewSheet: View {
    let plan: CleanPlan
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var mode: CleanMode = .mac
    var openFirst = false  // snapshots only

    private var grouped: [(String, [PlanItem])] {
        Dictionary(grouping: plan.items, by: \.repo).sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    private func refAction(_ r: PlanRef) -> String {
        switch r.kind {
        case "github":
            return mode == .mac
                ? "Download it from GitHub again. If GitHub still has the malware, delete this local copy (GitHub keeps its own)."
                : "Download it from GitHub again. If it's still infected, push a \"Remove malware (RepoGuard)\" commit to GitHub."
        case "branch":
            let base = r.plan == "move"
                ? "Move it back to the clean GitHub version. The only differences are malware."
                : "Add a \"Remove malware (RepoGuard)\" commit on top. Your own work is kept."
            return base + (r.checked_out == true ? " Your open files update too. If you have unsaved edits in the same files, it stops and asks you to commit them first." : "")
        default:
            return mode == .permanent ? "Delete this tag." : "Kept as it is. Only Permanently deletes it."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Review before removing").font(.title2.bold())
                Text(summaryLine(plan.items)).foregroundColor(.secondary)
                Text("Nothing has been changed yet. Every original is backed up first, read-only.").font(.callout).foregroundColor(.secondary)
            }.padding(20)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(grouped, id: \.0) { repo, items in
                        VStack(alignment: .leading, spacing: 2) {
                            Label(shortPath(repo), systemImage: "folder.fill").font(.headline)
                            ForEach(items) { PlanItemRow(item: $0, startOpen: openFirst && $0.id == plan.items.first(where: { $0.action == "clean" })?.id) }
                            let refs = plan.refs.filter { $0.repo == repo }
                            if !refs.isEmpty {
                                Text("Git branches").font(.subheadline.bold()).padding(.top, 6)
                                ForEach(refs, id: \.self) { r in
                                    HStack(alignment: .top, spacing: 10) {
                                        Image(systemName: r.kind == "tag" ? "tag" : "arrow.triangle.branch").frame(width: 20).foregroundColor(.secondary)
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(r.ref).font(.system(.callout, design: .monospaced).bold())
                                            Text(refAction(r)).font(.callout)
                                        }
                                    }.padding(.vertical, 3)
                                }
                            }
                        }
                    }
                    if !plan.manual.isEmpty || !plan.skipped.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Not touched").font(.headline)
                            ForEach(plan.manual + plan.skipped, id: \.self) { n in
                                Text("• \(shortPath(n.path)): \(n.why)").font(.callout).foregroundColor(.secondary)
                            }
                        }
                    }
                }.padding(20)
            }
            Divider()
            VStack(alignment: .leading, spacing: 10) {
                Picker("Where", selection: $mode) {
                    ForEach(CleanMode.allCases) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented).labelsHidden()
                Text(mode.detail).font(.callout).foregroundColor(mode == .permanent ? dangerRed : .secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Open Backup Folder") { NSWorkspace.shared.open(URL(fileURLWithPath: "\(supportDir)/quarantine", isDirectory: true)) }
                        .buttonStyle(.link)
                    Spacer()
                    Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                    Button(mode == .permanent ? "Remove Permanently" : "Remove Malware") {
                        model.removeMalware(permanent: mode == .permanent, fixGithub: mode != .mac, expect: plan.fingerprint)
                        dismiss()
                    }
                    .buttonStyle(.borderedProminent).tint(dangerRed)
                    .disabled(plan.items.allSatisfy { $0.action == "manual" } && plan.refs.isEmpty)
                }
            }.padding(20)
        }
        .frame(minWidth: 720, idealWidth: 820, minHeight: 520, idealHeight: 680)
    }
}

// MARK: Fix All on GitHub

struct GHPreviewSheet: View {
    let plan: GHPlan
    @ObservedObject var gh = GitHubWatcher.shared
    @Environment(\.dismiss) private var dismiss
    @State private var selected: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Review before fixing on GitHub").font(.title2.bold())
                Text(summaryLine(plan.branches.flatMap(\.items))).foregroundColor(.secondary)
                Text("Each ticked branch gets one \"Remove malware (RepoGuard)\" commit on top. It's a normal push, not a force-push. Teammates will see that commit. Nothing has been changed yet.")
                    .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            }.padding(20)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    ForEach(plan.branches) { b in
                        VStack(alignment: .leading, spacing: 2) {
                            Toggle(isOn: Binding(get: { selected.contains(b.id) },
                                                 set: { if $0 { selected.insert(b.id) } else { selected.remove(b.id) } })) {
                                HStack(spacing: 6) {
                                    Text(b.repo).font(.headline)
                                    Text(b.branch).font(.system(.callout, design: .monospaced)).foregroundColor(.secondary)
                                }
                            }
                            .disabled(!b.error.isEmpty || b.items.allSatisfy { $0.action == "manual" })
                            if !b.error.isEmpty { Text(b.error).font(.callout).foregroundColor(cautionOrange) }
                            ForEach(b.items) { PlanItemRow(item: $0).padding(.leading, 20) }
                        }
                    }
                }.padding(20)
            }
            Divider()
            HStack {
                Text("A branch pushed to after this review is skipped, so only what you saw here is changed.")
                    .font(.caption).foregroundColor(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Fix \(selected.count) Branch\(selected.count == 1 ? "" : "es") on GitHub") {
                    gh.poll(fixExisting: true, approved: Array(selected))
                    dismiss()
                }
                .buttonStyle(.borderedProminent).tint(dangerRed).disabled(selected.isEmpty)
            }.padding(20)
        }
        .frame(minWidth: 720, idealWidth: 820, minHeight: 520, idealHeight: 680)
        .onAppear {
            selected = Set(plan.branches.filter { $0.error.isEmpty && $0.items.contains { $0.action != "manual" } }.map(\.id))
        }
    }
}
