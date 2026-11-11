import AppKit
import Charts
import SwiftUI

enum Screen: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", threats = "Threats", repositories = "Repositories", servers = "Servers", activity = "Activity", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .threats: return "exclamationmark.triangle"
        case .repositories: return "folder"
        case .servers: return "server.rack"
        case .activity: return "clock.arrow.circlepath"
        case .settings: return "gearshape"
        }
    }
}

final class Navigation: ObservableObject {
    @Published var screen: Screen? = .dashboard
    @Published var confirmingFalseAlarm = false
    @Published var confirmingClean = false
    @Published var activityFilter = 0
}

let safeGreen = Color(red: 0.11, green: 0.62, blue: 0.40)
let dangerRed = Color(red: 0.84, green: 0.20, blue: 0.20)
let cautionOrange = Color(red: 0.90, green: 0.55, blue: 0.12)

// MARK: root

struct RootView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation
    var body: some View {
        if model.setupDone {
            ContentView(model: model, nav: nav)
        } else {
            WelcomeView(model: model)
        }
    }
}

/// Folder picker shared by first-run setup and Settings.
func chooseFolders(model: AppModel) {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = true
    panel.canChooseFiles = false
    panel.allowsMultipleSelection = true
    panel.message = "Choose the folder that holds your repos. Folders inside it are included."
    panel.prompt = "Watch"
    guard panel.runModal() == .OK else { return }
    let refused = model.addFolders(panel.urls.map(\.path))
    if !refused.isEmpty {
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = "That folder is too broad to watch"
        a.informativeText = "Scanning \(refused.joined(separator: ", ")) would cover your whole Mac and trigger many permission prompts. Choose the folder that holds your code, such as Documents/github or Developer."
        a.runModal()
    }
}

struct WatchedFolderList: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(spacing: 0) {
            ForEach(model.watchDirs, id: \.self) { dir in
                HStack(spacing: 10) {
                    Image(systemName: "folder.fill").foregroundColor(.accentColor)
                    Text((dir as NSString).abbreviatingWithTildeInPath).font(.system(.body, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    Spacer()
                    Button {
                        model.removeFolder(dir)
                    } label: {
                        Image(systemName: "minus.circle.fill").foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Stop watching this folder")
                }
                .padding(.vertical, 8)
                if dir != model.watchDirs.last { Divider() }
            }
        }
    }
}

struct WelcomeView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        VStack(spacing: 18) {
            Spacer(minLength: 20)
            Image(systemName: "checkmark.shield.fill").font(.system(size: 60)).foregroundColor(safeGreen)
            VStack(spacing: 6) {
                Text("Welcome to RepoGuard").font(.system(size: 28, weight: .bold))
                Text("Where do you keep your repos?").font(.title3).foregroundColor(.secondary)
            }
            Text("RepoGuard watches these folders and warns you when suspicious code arrives, from GitHub Desktop, VS Code, the terminal or an unzipped folder. It reads files but never runs them, and nothing leaves this Mac.")
                .multilineTextAlignment(.center).foregroundColor(.secondary).frame(maxWidth: 520).fixedSize(horizontal: false, vertical: true)
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    if model.watchDirs.isEmpty {
                        HStack(spacing: 10) {
                            Image(systemName: "folder.badge.questionmark").foregroundColor(.secondary)
                            Text("No folders chosen yet").foregroundColor(.secondary)
                        }
                        .padding(.vertical, 8)
                    } else {
                        WatchedFolderList(model: model)
                    }
                    Divider()
                    Button {
                        chooseFolders(model: model)
                    } label: {
                        Label("Add Folder…", systemImage: "plus")
                    }
                    .controlSize(.large)
                    Text("Choose the folder that holds your repos, and add more if they live in different places. Folders inside are included.")
                        .font(.callout).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: 560)
            Button {
                model.finishSetup()
            } label: {
                Text("Start Protecting").frame(minWidth: 180)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.watchDirs.isEmpty)
            Text("macOS may ask for permission to read these folders. Click Allow, or RepoGuard can't scan them.")
                .font(.callout).foregroundColor(.secondary)
            Spacer(minLength: 20)
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.windowBackgroundColor))
        .ignoresSafeArea()
        .frame(minWidth: 860, minHeight: 580)
    }
}

struct ContentView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(model: model, nav: nav)
            Divider()
            Group {
                switch nav.screen ?? .dashboard {
                case .dashboard: DashboardView(model: model, nav: nav)
                case .threats: ThreatsView(model: model, nav: nav)
                case .repositories: RepositoriesView(model: model)
                case .servers: ServersView()
                case .activity: ActivityView(model: model, nav: nav)
                case .settings: SettingsView(model: model)
                }
            }
            .padding(.top, 14)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(NSColor.windowBackgroundColor))
        }
        .ignoresSafeArea()
        .frame(minWidth: 860, minHeight: 580)
    }
}

struct Sidebar: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation

    private var statusText: String {
        if !model.isProtected { return "Not protected" }
        if !model.active.isEmpty { return "\(model.active.count) threat\(model.active.count == 1 ? "" : "s") found" }
        return model.loaded ? "Protected" : "Starting…"
    }
    private var statusColor: Color {
        if !model.isProtected { return cautionOrange }
        return model.active.isEmpty ? safeGreen : dangerRed
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 8) {
                Image(systemName: !model.isProtected ? "shield.slash.fill" : (model.active.isEmpty ? "checkmark.shield.fill" : "exclamationmark.shield.fill")).font(.title2).foregroundColor(statusColor)
                Text("RepoGuard").font(.system(size: 16, weight: .bold))
            }
            .padding(.horizontal, 10)
            .padding(.top, 46)
            .padding(.bottom, 14)
            ForEach(Screen.allCases) { screen in
                SidebarRow(screen: screen, selected: (nav.screen ?? .dashboard) == screen, badge: screen == .threats ? model.active.count : 0) {
                    nav.screen = screen
                }
            }
            Spacer()
            HStack(spacing: 7) {
                Circle().fill(statusColor).frame(width: 8, height: 8)
                Text(statusText).font(.callout).foregroundColor(.secondary)
            }
            .padding(10)
        }
        .padding(.horizontal, 10)
        .padding(.bottom, 8)
        .frame(width: 212)
        .frame(maxHeight: .infinity)
        .background(.thinMaterial)
    }
}

struct SidebarRow: View {
    let screen: Screen
    let selected: Bool
    let badge: Int
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 9) {
                Image(systemName: screen.icon).frame(width: 20)
                Text(screen.rawValue)
                Spacer()
                if badge > 0 {
                    Text("\(badge)").font(.caption.bold()).foregroundColor(.white)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Capsule().fill(dangerRed))
                }
            }
            .padding(.horizontal, 10)
            .frame(height: 32)
            .foregroundColor(selected ? .white : .primary)
            .background(RoundedRectangle(cornerRadius: 8).fill(selected ? Color.accentColor : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

// MARK: shared pieces

struct PageHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder var trailing: () -> Trailing
    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 24, weight: .bold))
                Text(subtitle).foregroundColor(.secondary)
            }
            Spacer()
            trailing()
        }
    }
}

struct Card<Content: View>: View {
    @ViewBuilder var content: () -> Content
    var body: some View {
        content()
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .modifier(GlassCard())
    }
}

/// Liquid Glass on macOS 26+, a frosted material card before that.
struct GlassCard: ViewModifier {
    var radius: CGFloat = 16
    func body(content: Content) -> some View {
        if #available(macOS 26, *) {
            content.glassEffect(.regular, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
        } else {
            content
                .background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(.regularMaterial))
                .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).stroke(Color.primary.opacity(0.08)))
        }
    }
}


struct EmptyState: View {
    let icon: String
    let color: Color
    let title: String
    let detail: String
    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 44)).foregroundColor(color)
            Text(title).font(.title3.bold())
            Text(detail).foregroundColor(.secondary).multilineTextAlignment(.center).frame(maxWidth: 380)
        }
        .frame(maxWidth: .infinity, minHeight: 280)
    }
}

func relativeTime(_ date: Date?) -> String {
    guard let date = date else { return "Not yet" }
    if Date().timeIntervalSince(date) < 60 { return "Just now" }
    let f = RelativeDateTimeFormatter()
    f.unitsStyle = .short
    return f.localizedString(for: date, relativeTo: Date())
}

func niceTime(_ iso: String) -> String {
    let parts = iso.replacingOccurrences(of: "T", with: " ")
    return String(parts.prefix(16))
}

struct HeroButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .foregroundColor(Color(red: 0.08, green: 0.22, blue: 0.20))
            .padding(.horizontal, 16).padding(.vertical, 9)
            .background(Capsule().fill(Color.white.opacity(configuration.isPressed ? 0.8 : 1)))
    }
}

/// A thin bar under the header while a full scan runs; results from the last scan stay on screen meanwhile.
struct ScanProgressBar: View {
    @ObservedObject var model: AppModel
    var body: some View {
        if model.scanning, let p = model.progress {
            Card {
                VStack(alignment: .leading, spacing: 7) {
                    HStack {
                        Text(p.phase == "branches" ? "Checking git branches" : "Checking files")
                            .font(.callout.weight(.medium))
                        if !p.where.isEmpty {
                            Text(projectName(p.where)).font(.callout).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Text(p.expected > 0 ? "\(p.files.formatted()) of ~\(p.expected.formatted())" : "\(p.files.formatted()) files")
                            .font(.callout.monospacedDigit()).foregroundColor(.secondary)
                    }
                    if p.expected > 0 {
                        ProgressView(value: min(Double(p.files), Double(p.expected)), total: Double(p.expected))
                    } else {
                        ProgressView().progressViewStyle(.linear)
                    }
                    Text("Showing results from the last scan until this one finishes.")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
        }
    }
}

struct ScanButton: View {
    @ObservedObject var model: AppModel
    var prominent = false
    var body: some View {
        Button {
            model.scanNow()
        } label: {
            HStack(spacing: 6) {
                if model.scanning {
                    ProgressView().controlSize(.small).scaleEffect(0.75).frame(width: 14, height: 14)
                } else {
                    Image(systemName: "arrow.clockwise")
                }
                Text(model.scanning ? model.scanLabel : "Scan Now")
            }
            .frame(minWidth: 96)
        }
        .disabled(model.scanning)
        .controlSize(.large)
        .keyboardShortcut("r", modifiers: .command)
    }
}

// MARK: dashboard

struct DashboardView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation

    private var heroColors: [Color] {
        if !model.isProtected { return [cautionOrange, Color(red: 0.75, green: 0.38, blue: 0.08)] }
        if !model.active.isEmpty { return [dangerRed, Color(red: 0.62, green: 0.10, blue: 0.16)] }
        return [safeGreen, Color(red: 0.05, green: 0.42, blue: 0.36)]
    }
    private var heroIcon: String {
        if !model.isProtected { return "shield.slash.fill" }
        return model.active.isEmpty ? "checkmark.shield.fill" : "exclamationmark.shield.fill"
    }
    private var heroTitle: String {
        if !model.isProtected { return "Not protected" }
        if !model.active.isEmpty { return "\(model.active.count) threat\(model.active.count == 1 ? "" : "s") found" }
        return model.loaded ? "You're protected" : "Loading…"
    }
    private var heroDetail: String {
        if let e = model.lastError { return e }
        if !model.active.isEmpty {
            let inBranches = model.active.filter { $0.where.hasPrefix("branch:") || $0.where.hasPrefix("incoming:") }.count
            let onDisk = model.active.count - inBranches
            if onDisk == 0 { return "All \(inBranches) are inside git branches, not in your files on disk. Use Remove Malware and Fix GitHub to clean those branches." }
            return "\(onDisk) in your files, \(inBranches) inside git branches. Don't open the affected project in VS Code or run npm commands in it."
        }
        return "Watching \(model.watchSummary) for suspicious code from GitHub Desktop, VS Code, the terminal and unzipped folders."
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 18) {
                    Image(systemName: heroIcon).font(.system(size: 54)).foregroundColor(.white)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(heroTitle).font(.system(size: 26, weight: .bold)).foregroundColor(.white)
                        Text(heroDetail).foregroundColor(.white.opacity(0.92)).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    if !model.active.isEmpty {
                        Button("Review Threats") { nav.screen = .threats }.buttonStyle(HeroButtonStyle())
                    } else {
                        Button {
                            model.scanNow()
                        } label: {
                            HStack(spacing: 6) {
                                Image(systemName: model.scanning ? "hourglass" : "arrow.clockwise")
                                Text(model.scanning ? model.scanLabel : "Scan Now")
                            }
                        }
                        .buttonStyle(HeroButtonStyle())
                        .disabled(model.scanning)
                    }
                }
                .padding(22)
                .background(RoundedRectangle(cornerRadius: 16).fill(LinearGradient(colors: heroColors, startPoint: .topLeading, endPoint: .bottomTrailing)))

                ScanProgressBar(model: model)

                HStack(spacing: 12) {
                    StatTile(value: model.isProtected ? "\(model.active.count)" : "Unknown", label: "Active threats", icon: "exclamationmark.triangle.fill", color: !model.isProtected ? cautionOrange : (model.active.isEmpty ? .secondary : dangerRed))
                    StatTile(value: "\(model.repos.count)", label: "Repositories", icon: "folder.fill", color: .accentColor)
                    StatTile(value: model.filesChecked.formatted(), label: "Files checked", icon: "doc.text.fill", color: .accentColor)
                    StatTile(value: model.isProtected ? relativeTime(model.lastScan) : "Failed", label: "Last scan", icon: "clock.fill", color: model.isProtected ? .accentColor : cautionOrange)
                }

                HStack(alignment: .top, spacing: 12) {
                    Card { TrendChart(stats: model.daily) }
                    Card { ProjectChart(findings: model.active) { nav.screen = .threats } }
                }
                if !model.active.isEmpty {
                    if #available(macOS 14, *) { Card { TypeChart(findings: model.active) } }
                }

                HStack(alignment: .top, spacing: 12) {
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            SectionTitle("Repositories") { nav.screen = .repositories }
                            if model.repos.isEmpty {
                                Text(model.loaded ? "No Git repos in this folder yet." : "Loading…").foregroundColor(.secondary)
                            }
                            ForEach(model.repos.sorted { $0.threats > $1.threats }.prefix(5)) { r in
                                HStack(spacing: 9) {
                                    Image(systemName: !model.isProtected ? "questionmark.circle.fill" : (r.threats > 0 ? "xmark.circle.fill" : "checkmark.circle.fill"))
                                        .foregroundColor(!model.isProtected ? cautionOrange : (r.threats > 0 ? dangerRed : safeGreen))
                                    Text(r.name).lineLimit(1)
                                    Spacer()
                                    Text(!model.isProtected ? "Not checked" : (r.threats > 0 ? "\(r.threats) threat\(r.threats == 1 ? "" : "s")" : "Clean")).font(.callout).foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            SectionTitle("Recent activity") { nav.screen = .activity }
                            if model.activity.isEmpty {
                                Text("Nothing yet.").foregroundColor(.secondary)
                            }
                            ForEach(model.activity.prefix(5)) { e in
                                HStack(alignment: .firstTextBaseline, spacing: 9) {
                                    ActivityDot(kind: e.kind)
                                    Text(e.text).lineLimit(1).truncationMode(.tail)
                                    Spacer(minLength: 6)
                                    Text(String(e.time.dropFirst(11).prefix(5))).font(.callout).foregroundColor(.secondary)
                                }
                            }
                        }
                    }
                }
            }
            .padding(24)
        }
    }
}

struct SectionTitle: View {
    let title: String
    let action: () -> Void
    init(_ title: String, action: @escaping () -> Void) { self.title = title; self.action = action }
    var body: some View {
        HStack {
            Text(title).font(.headline)
            Spacer()
            Button("View All", action: action).buttonStyle(.link).font(.callout)
        }
    }
}

struct StatTile: View {
    let value: String
    let label: String
    let icon: String
    let color: Color
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Image(systemName: icon).foregroundColor(color).frame(height: 18)
                Text(value).font(.system(size: 22, weight: .semibold)).lineLimit(1).minimumScaleFactor(0.6)
                Text(label).font(.callout).foregroundColor(.secondary).lineLimit(1)
            }
        }
    }
}

// MARK: threats

struct ThreatsView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation

    private var grouped: [(String, [Finding])] {
        Dictionary(grouping: model.active, by: \.repoName).sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "Threats", subtitle: !model.isProtected ? "RepoGuard can't scan right now, so this list may be out of date." : model.active.isEmpty ? "Nothing needs your attention." : "\(model.active.count) in \(model.threatRepoCount) \(model.threatRepoCount == 1 ? "project" : "projects")") {
                    if !model.active.isEmpty {
                        HStack(spacing: 8) {
                            Button("Mark All as False Alarm…") { nav.confirmingFalseAlarm = true }.controlSize(.large)
                            Button(model.cleaning ? "Removing…" : "Remove Malware…") { nav.confirmingClean = true }
                                .buttonStyle(.borderedProminent).tint(dangerRed).controlSize(.large).disabled(model.cleaning || model.scanning)
                        }
                    }
                }
                if model.cleaning {
                    Card {
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text("Removing malware. Re-fetching clean branches from GitHub can take a few minutes.").foregroundColor(.secondary)
                        }
                    }
                }
                if let s = model.cleanSummary {
                    CleanResultCard(summary: s, model: model)
                }
                GitHubThreatsSection()
                if !model.isProtected {
                    EmptyState(icon: "shield.slash.fill", color: cautionOrange, title: "Not protected", detail: model.lastError ?? "The last scan failed.")
                } else if model.active.isEmpty {
                    EmptyState(icon: "checkmark.shield.fill", color: safeGreen, title: "No active threats", detail: "RepoGuard warns you here and with a popup if suspicious code arrives. Warnings clear themselves once the code is fixed.")
                } else {
                    Card {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: "hand.raised.fill").foregroundColor(dangerRed)
                            VStack(alignment: .leading, spacing: 3) {
                                Text("What to do").font(.headline)
                                Text("Don't open the project in VS Code, run npm commands, or click Pull or Merge. Check the file first. If it came from a teammate, warn them too.")
                                    .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    ForEach(grouped, id: \.0) { repo, items in
                        VStack(alignment: .leading, spacing: 8) {
                            Label(repo, systemImage: "folder.fill").font(.headline)
                            ForEach(items) { f in ThreatRow(finding: f, model: model) }
                        }
                    }
                }
                if !model.reviews.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Worth a look").font(.headline).padding(.top, 6)
                        Text("Not always harmful, so these don't trigger a popup.").font(.callout).foregroundColor(.secondary)
                        ForEach(model.reviews.prefix(12)) { r in
                            HStack(spacing: 9) {
                                Image(systemName: "eye.fill").foregroundColor(cautionOrange)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(r.label)
                                    Text("\(r.repoName) · \(r.path)").font(.callout).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                                }
                                Spacer()
                            }
                            .padding(.vertical, 3)
                        }
                    }
                }
            }
            .padding(24)
        }
        .confirmationDialog("Remove malware from \(model.threatRepoCount) \(model.threatRepoCount == 1 ? "project" : "projects")?", isPresented: $nav.confirmingClean, titleVisibility: .visible) {
            Button("Remove Malware and Fix GitHub") { model.removeMalware(permanent: false, fixGithub: true) }
            Button("Remove Malware (this Mac only)") { model.removeMalware(permanent: false) }
            Button("Remove Permanently", role: .destructive) { model.removeMalware(permanent: true) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only the injected code is cut out; the rest of each file is kept. Files that are entirely malware are deleted. Every original is saved to a backup first. Local branches are cleaned without losing your work.\n\nFix GitHub also cleans branches that are infected on GitHub itself: it pushes one malware-removal commit on top of each one. It's a normal push, not a force-push, so no history is rewritten.\n\nRemove Permanently also deletes infected tags (including evidence and backup tags) and purges the infected commits from git history. That can't be undone.")
        }
        .alert("Mark \(model.active.count) findings as false alarms?", isPresented: $nav.confirmingFalseAlarm) {
            Button("Cancel", role: .cancel) {}
            Button("Mark as False Alarm", role: .destructive) { model.markAllFalseAlarm() }
        } message: {
            Text("Only do this if you're sure this code is safe. RepoGuard stops warning about these exact file versions, and warns again if they change.")
        }
    }
}

struct CleanResultCard: View {
    let summary: CleanSummary
    @ObservedObject var model: AppModel
    var body: some View {
        Card {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: summary.manual == 0 ? "checkmark.seal.fill" : "exclamationmark.bubble.fill")
                    .font(.title2).foregroundColor(summary.manual == 0 ? safeGreen : cautionOrange)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Malware removed").font(.headline)
                    Text("\(summary.files) files cleaned · \(summary.refs) branches fixed" + (summary.purged > 0 ? " · history purged in \(summary.purged) repos" : ""))
                    if (summary.pushed ?? 0) > 0 { Text("\(summary.pushed ?? 0) GitHub branches fixed with a pushed cleanup commit.").foregroundColor(safeGreen) }
                    if summary.manual > 0 {
                        Text("\(summary.manual) need a manual look; RepoGuard left them unchanged:").foregroundColor(cautionOrange)
                        ForEach(summary.manual_items ?? [], id: \.self) { Text("• " + $0).font(.callout).foregroundColor(.secondary).lineLimit(2) }
                    }
                    if summary.kept_tags > 0 { Text("\(summary.kept_tags) infected tags kept. Use Remove Permanently to delete them.").foregroundColor(.secondary) }
                    if summary.fetch_failed > 0 { Text("\(summary.fetch_failed) repos couldn't reach GitHub; run it again when online.").foregroundColor(.secondary) }
                    if summary.skipped > 0 { Text("\(summary.skipped) library files skipped (likely false alarms).").foregroundColor(.secondary) }
                    Text("Originals are backed up in \(summary.backup)").font(.callout).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                }
                Spacer()
                Button("Open Report") { model.openCleanReport() }
            }
        }
    }
}

struct ThreatRow: View {
    let finding: Finding
    @ObservedObject var model: AppModel
    @State private var viewing = false
    var body: some View {
        Card {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.octagon.fill").font(.title2).foregroundColor(dangerRed)
                VStack(alignment: .leading, spacing: 3) {
                    Text(finding.label).font(.headline)
                    Text(finding.path).font(.system(.callout, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                    Text(finding.location + (finding.time.map { " · \(niceTime($0))" } ?? "")).font(.callout).foregroundColor(.secondary)
                }
                Spacer()
                Button("View") { viewing = true }
            }
        }
        .sheet(isPresented: $viewing) { FindingViewer(finding: finding, model: model) }
    }
}

// MARK: repositories

struct RepositoriesView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                PageHeader(title: "Repositories", subtitle: "Every Git repo found in \(model.watchSummary)") {
                    ScanButton(model: model)
                }
                ScanProgressBar(model: model)
                if model.repos.isEmpty {
                    EmptyState(icon: "folder", color: .secondary, title: model.loaded ? "No repositories yet" : "Loading…", detail: "Clone a repo into a watched folder and it appears here automatically.")
                }
                ForEach(model.repos.sorted { ($0.threats, $1.name) > ($1.threats, $0.name) }) { r in
                    Card {
                        HStack(spacing: 12) {
                            Image(systemName: !model.isProtected ? "questionmark.diamond.fill" : (r.threats > 0 ? "xmark.shield.fill" : "checkmark.shield.fill"))
                                .font(.title2).foregroundColor(!model.isProtected ? cautionOrange : (r.threats > 0 ? dangerRed : safeGreen))
                            VStack(alignment: .leading, spacing: 3) {
                                Text(r.name).font(.headline)
                                Text((r.path as NSString).abbreviatingWithTildeInPath).font(.callout).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                            }
                            Spacer()
                            VStack(alignment: .trailing, spacing: 3) {
                                Text(!model.isProtected ? "Not checked" : (r.threats > 0 ? "\(r.threats) threat\(r.threats == 1 ? "" : "s")" : "Clean"))
                                    .font(.callout.bold()).foregroundColor(!model.isProtected ? cautionOrange : (r.threats > 0 ? dangerRed : safeGreen))
                                Text("\(r.branch.isEmpty ? "No branch" : r.branch) · \(r.branches) branch\(r.branches == 1 ? "" : "es")")
                                    .font(.callout).foregroundColor(.secondary)
                            }
                            Button {
                                model.revealFolder(r.path)
                            } label: {
                                Image(systemName: "folder")
                            }
                            .help("Show in Finder")
                        }
                    }
                }
            }
            .padding(24)
        }
    }
}

// MARK: activity

struct ActivityDot: View {
    let kind: LogEntry.Kind
    var body: some View {
        Circle().fill(color).frame(width: 8, height: 8)
    }
    private var color: Color {
        switch kind {
        case .threat: return dangerRed
        case .review: return cautionOrange
        case .scan: return safeGreen
        case .error: return dangerRed
        case .fixed: return .accentColor
        }
    }
}

struct ActivityView: View {
    @ObservedObject var model: AppModel
    @ObservedObject var nav: Navigation

    private var items: [LogEntry] {
        switch nav.activityFilter {
        case 1: return model.activity.filter { $0.kind == .threat || $0.kind == .error }
        case 2: return model.activity.filter { $0.kind == .review }
        default: return model.activity
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeader(title: "Activity", subtitle: "Scans and findings on this Mac") {
                Button("Open Full Log") { model.openLog() }.controlSize(.large)
            }
            Picker("", selection: $nav.activityFilter) {
                Text("All").tag(0)
                Text("Threats").tag(1)
                Text("Worth a look").tag(2)
            }
            .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 320).padding(.leading, -9)
            if items.isEmpty {
                EmptyState(icon: "clock", color: .secondary, title: "Nothing here yet", detail: "Scans and findings show up here as they happen.")
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(items) { e in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                ActivityDot(kind: e.kind)
                                Text(e.text).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 10)
                                Text(e.time).font(.system(.callout, design: .monospaced)).foregroundColor(.secondary)
                            }
                            .padding(.vertical, 8)
                            Divider()
                        }
                    }
                }
            }
        }
        .padding(24)
    }
}

// MARK: settings

struct SettingsView: View {
    @ObservedObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "Settings", subtitle: "RepoGuard keeps running in the menu bar when you close this window.") { EmptyView() }
                Card {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Watched folders").font(.headline)
                            Spacer()
                            Button {
                                chooseFolders(model: model)
                            } label: {
                                Label("Add Folder…", systemImage: "plus")
                            }
                        }
                        if model.watchDirs.isEmpty {
                            Text("No folders are being watched, so RepoGuard isn't protecting anything.").foregroundColor(cautionOrange)
                        } else {
                            WatchedFolderList(model: model)
                        }
                        Text("Folders inside these are included. Repos anywhere else aren't checked.").font(.callout).foregroundColor(.secondary)
                    }
                }
                Card {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Start at login")
                                Text("Runs quietly in the menu bar, without opening this window.").font(.callout).foregroundColor(.secondary)
                            }
                            Spacer()
                            Toggle("", isOn: Binding(get: { model.launchAtLogin }, set: { model.setLaunchAtLogin($0) })).labelsHidden()
                        }
                        Divider()
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Show a popup and play a sound for threats")
                                Text("If this is off, the red menu bar icon and this window are your only warning.").font(.callout).foregroundColor(.secondary)
                            }
                            Spacer()
                            Toggle("", isOn: $model.popupsEnabled).labelsHidden()
                        }
                    }
                    .toggleStyle(.switch)
                }
                GitHubSettingsCard()
                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("What RepoGuard can't do").font(.headline)
                        ForEach(["It warns after files arrive, so it can't stop them landing.",
                                 "It looks for known techniques and can miss a brand-new attack.",
                                 "It doesn't check inside npm packages.",
                                 "Malware already running on this Mac could turn it off."], id: \.self) { line in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text("•")
                                Text(line).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
                Text("RepoGuard 2.0. Scans stay on this Mac and never run the code they read.").font(.callout).foregroundColor(.secondary)
            }
            .padding(24)
        }
    }
}

// MARK: finding viewer: shows the infected lines, from disk or straight from the branch

struct FindingContent {
    var lines: [(number: Int, text: String, bad: Bool)] = []
    var note: String?
    var onDisk = false
    var error: String?
}

func loadFindingContent(_ f: Finding) -> FindingContent {
    var c = FindingContent()
    var data: Data?
    let w = f.where
    if w == "folder" {
        let p = "\(f.root)/\(f.path)"
        c.onDisk = FileManager.default.fileExists(atPath: p)
        data = FileManager.default.contents(atPath: p)
        if data == nil { c.error = "This file is no longer on disk. Run Scan Now to refresh the list." }
    } else if w == "git-config" {
        data = FileManager.default.contents(atPath: "\(f.root)/.git/config")
        c.note = "From the repo's Git settings (.git/config)."
    } else {
        let ref = w.hasPrefix("branch:") ? String(w.dropFirst(7)) : (w.hasPrefix("incoming:") ? String(w.dropFirst(9)) : w)
        let r = runProcess("/usr/bin/git", ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
                                            "-C", f.root, "show", "\(ref):\(f.path)"], timeout: 30)
        if r.status == 0 { data = r.out } else { c.error = "This branch or file no longer exists. Run Scan Now to refresh the list." }
        let short = describeLocation(w).replacingOccurrences(of: "On branch ", with: "")
        c.note = "This copy is inside the git branch \(short), not in the file you have open on disk. That's why the file on disk can look clean."
    }
    guard let d = data else { return c }
    if d.prefix(8000).contains(0) { c.error = "Binary file (\(d.count) bytes); it can't be shown as text."; return c }
    let text = String(decoding: d.prefix(2_000_000), as: UTF8.self)
    var patterns: [NSRegularExpression] = []
    if let rulesPath = Bundle.main.path(forResource: "rules", ofType: "json"),
       let rd = FileManager.default.contents(atPath: rulesPath),
       let rules = try? JSONSerialization.jsonObject(with: rd) as? [String: Any] {
        for key in ["content_rules", "git_config_rules"] {
            for rule in (rules[key] as? [[String: Any]]) ?? [] where (rule["id"] as? String) == f.rule || (rule["label"] as? String) == f.label {
                if let p = rule["pattern"] as? String, let rx = try? NSRegularExpression(pattern: p, options: [.anchorsMatchLines, .caseInsensitive]) { patterns.append(rx) }
            }
        }
    }
    let offscreen = try! NSRegularExpression(pattern: "\\S[ \\t]{100,}\\S")
    var hiddenFound = false
    for (i, raw) in text.components(separatedBy: "\n").enumerated() {
        let line = raw.replacingOccurrences(of: "\r", with: "")
        let range = NSRange(line.startIndex..., in: line)
        var bad = patterns.contains { $0.firstMatch(in: line, range: range) != nil }
        var shown = line
        // code pushed far to the right is invisible in an editor; pull it into view
        if let m = try? NSRegularExpression(pattern: "^(.*?\\S)([ \\t]{100,})(\\S.*)$").firstMatch(in: line, range: range),
           let a = Range(m.range(at: 1), in: line), let gap = Range(m.range(at: 2), in: line), let b = Range(m.range(at: 3), in: line) {
            shown = "\(line[a])   ⟶ [\(line[gap].count) spaces hidden] ⟶   \(line[b])"
            bad = true; hiddenFound = true
        } else if offscreen.firstMatch(in: line, range: range) != nil { bad = true }
        if shown.count > 600 { shown = String(shown.prefix(600)) + " … (\(shown.count) characters)" }
        c.lines.append((i + 1, shown, bad))
    }
    if hiddenFound {
        c.note = (c.note.map { $0 + "\n\n" } ?? "") + "Code was hidden far to the right of a line, so it doesn't show when you open the file. It's pulled into view below."
    }
    if !c.lines.contains(where: \.bad) {
        c.note = (c.note.map { $0 + "\n\n" } ?? "") + "The whole file is flagged by its name or type (\(f.label)), not by one line."
    }
    return c
}

struct FindingViewer: View {
    let finding: Finding
    @ObservedObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var content: FindingContent?
    @State private var onlyBad = true

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(finding.label).font(.title3.bold())
                    Text("\(finding.repoName)/\(finding.path)").font(.system(.callout, design: .monospaced))
                    Text(finding.location).font(.callout).foregroundColor(.secondary)
                }
                Spacer()
                Toggle("Only flagged lines", isOn: $onlyBad).toggleStyle(.switch).controlSize(.small)
            }
            if let c = content {
                if let n = c.note { Text(n).font(.callout).foregroundColor(cautionOrange).fixedSize(horizontal: false, vertical: true) }
                if let e = c.error {
                    Text(e).foregroundColor(.secondary).frame(maxWidth: .infinity, minHeight: 200)
                } else {
                    ScrollView([.vertical, .horizontal]) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(c.lines.filter { !onlyBad || $0.bad || !c.lines.contains(where: \.bad) }, id: \.number) { l in
                                HStack(alignment: .top, spacing: 10) {
                                    Text("\(l.number)").foregroundColor(.secondary).frame(width: 44, alignment: .trailing)
                                    Text(l.text.isEmpty ? " " : l.text).textSelection(.enabled).fixedSize(horizontal: true, vertical: false)
                                }
                                .font(.system(size: 11.5, design: .monospaced))
                                .padding(.vertical, 1.5).padding(.trailing, 8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(l.bad ? dangerRed.opacity(0.22) : Color.clear)
                            }
                        }
                    }
                    .frame(minHeight: 260, maxHeight: 420)
                    .background(RoundedRectangle(cornerRadius: 8).fill(Color.primary.opacity(0.05)))
                }
            } else {
                ProgressView().frame(maxWidth: .infinity, minHeight: 260)
            }
            HStack {
                Text("Viewing is safe: RepoGuard only reads the text and never runs it.").font(.caption).foregroundColor(.secondary)
                Spacer()
                if content?.onDisk == true {
                    Button("Show in Finder") { model.reveal(finding) }
                        .help("Files starting with a dot are hidden in Finder. Press ⌘⇧. in Finder to show them.")
                }
                Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 760)
        .onAppear { DispatchQueue.global().async { let c = loadFindingContent(finding); DispatchQueue.main.async { content = c } } }
    }
}


// MARK: dashboard charts

struct TrendChart: View {
    let stats: [DayStat]
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Last 14 days").font(.headline)
                Spacer()
                Text("\(stats.filter { $0.kind == "Found" }.reduce(0) { $0 + $1.count }) found · \(stats.filter { $0.kind == "Removed" }.reduce(0) { $0 + $1.count }) removed")
                    .font(.callout).foregroundColor(.secondary)
            }
            Chart(stats) { s in
                BarMark(x: .value("Day", s.day, unit: .day), y: .value("Count", s.count))
                    .foregroundStyle(by: .value("Kind", s.kind))
                    .position(by: .value("Kind", s.kind))
                    .cornerRadius(3)
            }
            .chartForegroundStyleScale(["Found": dangerRed, "Removed": safeGreen])
            .chartXAxis { AxisMarks(values: .stride(by: .day, count: 3)) { _ in AxisValueLabel(format: .dateTime.day().month(.abbreviated)); AxisGridLine() } }
            .chartLegend(position: .bottom, alignment: .leading)
            .frame(height: 170)
        }
    }
}

struct ProjectChart: View {
    let findings: [Finding]
    let open: () -> Void
    private var rows: [(String, Int)] {
        Dictionary(grouping: findings, by: \.repoName).map { ($0.key, $0.value.count) }.sorted { $0.1 > $1.1 }.prefix(6).map { $0 }
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("Threats by project", action: open)
            if rows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.seal.fill").font(.system(size: 34)).foregroundColor(safeGreen)
                    Text("Every project is clean").foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, minHeight: 170)
            } else {
                Chart(rows, id: \.0) { r in
                    BarMark(x: .value("Threats", r.1), y: .value("Project", r.0), height: .fixed(14))
                        .foregroundStyle(LinearGradient(colors: [dangerRed.opacity(0.65), dangerRed], startPoint: .leading, endPoint: .trailing))
                        .cornerRadius(4)
                        .annotation(position: .trailing) { Text("\(r.1)").font(.caption.bold()).foregroundColor(.secondary) }
                }
                .chartXAxis(.hidden)
                .chartYAxis { AxisMarks(position: .leading) { _ in AxisValueLabel().font(.callout) } }
                .frame(height: 170)
            }
        }
    }
}

@available(macOS 14, *)
struct TypeChart: View {
    let findings: [Finding]
    private var rows: [(String, Int)] {
        Dictionary(grouping: findings, by: \.label).map { ($0.key, $0.value.count) }.sorted { $0.1 > $1.1 }
    }
    private let palette: [Color] = [dangerRed, cautionOrange, .purple, .pink, .blue, .teal, .indigo, .brown]
    var body: some View {
        HStack(alignment: .center, spacing: 22) {
            Chart(Array(rows.enumerated()), id: \.element.0) { i, r in
                SectorMark(angle: .value("Count", r.1), innerRadius: .ratio(0.62), angularInset: 1.5)
                    .foregroundStyle(palette[i % palette.count])
                    .cornerRadius(4)
            }
            .chartBackground { _ in
                VStack(spacing: 0) {
                    Text("\(findings.count)").font(.system(size: 24, weight: .bold))
                    Text("threats").font(.caption).foregroundColor(.secondary)
                }
            }
            .frame(width: 160, height: 160)
            VStack(alignment: .leading, spacing: 7) {
                Text("What was found").font(.headline)
                ForEach(Array(rows.enumerated()), id: \.element.0) { i, r in
                    HStack(spacing: 8) {
                        Circle().fill(palette[i % palette.count]).frame(width: 9, height: 9)
                        Text(r.0).lineLimit(1)
                        Spacer()
                        Text("\(r.1)").font(.callout.monospacedDigit()).foregroundColor(.secondary)
                    }
                }
            }
        }
    }
}
