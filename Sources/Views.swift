import AppKit
import SwiftUI

enum Screen: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard", threats = "Threats", repositories = "Repositories", activity = "Activity", settings = "Settings"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .threats: return "exclamationmark.triangle"
        case .repositories: return "folder"
        case .activity: return "clock.arrow.circlepath"
        case .settings: return "gearshape"
        }
    }
}

final class Navigation: ObservableObject {
    @Published var screen: Screen? = .dashboard
    @Published var confirmingFalseAlarm = false
    @Published var activityFilter = 0
}

private let safeGreen = Color(red: 0.11, green: 0.62, blue: 0.40)
private let dangerRed = Color(red: 0.84, green: 0.20, blue: 0.20)
private let cautionOrange = Color(red: 0.90, green: 0.55, blue: 0.12)

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
        .background(Color.primary.opacity(0.035))
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
            .background(RoundedRectangle(cornerRadius: 12).fill(Color(NSColor.controlBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(Color.primary.opacity(0.08)))
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
                Text(model.scanning ? "Scanning…" : "Scan Now")
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
        return model.loaded ? "You're protected" : "Starting first scan…"
    }
    private var heroDetail: String {
        if let e = model.lastError { return e }
        if !model.active.isEmpty { return "Don't open the affected project in VS Code or run npm commands in it. RepoGuard hasn't run any of this code." }
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
                                Text(model.scanning ? "Scanning…" : "Scan Now")
                            }
                        }
                        .buttonStyle(HeroButtonStyle())
                        .disabled(model.scanning)
                    }
                }
                .padding(22)
                .background(RoundedRectangle(cornerRadius: 16).fill(LinearGradient(colors: heroColors, startPoint: .topLeading, endPoint: .bottomTrailing)))

                HStack(spacing: 12) {
                    StatTile(value: model.isProtected ? "\(model.active.count)" : "Unknown", label: "Active threats", icon: "exclamationmark.triangle.fill", color: !model.isProtected ? cautionOrange : (model.active.isEmpty ? .secondary : dangerRed))
                    StatTile(value: "\(model.repos.count)", label: "Repositories", icon: "folder.fill", color: .accentColor)
                    StatTile(value: model.filesChecked.formatted(), label: "Files checked", icon: "doc.text.fill", color: .accentColor)
                    StatTile(value: model.isProtected ? relativeTime(model.lastScan) : "Failed", label: "Last scan", icon: "clock.fill", color: model.isProtected ? .accentColor : cautionOrange)
                }

                HStack(alignment: .top, spacing: 12) {
                    Card {
                        VStack(alignment: .leading, spacing: 12) {
                            SectionTitle("Repositories") { nav.screen = .repositories }
                            if model.repos.isEmpty {
                                Text(model.loaded ? "No Git repos in this folder yet." : "Looking for repos…").foregroundColor(.secondary)
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
                        Button("Mark All as False Alarm…") { nav.confirmingFalseAlarm = true }.controlSize(.large)
                    }
                }
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
        .alert("Mark \(model.active.count) findings as false alarms?", isPresented: $nav.confirmingFalseAlarm) {
            Button("Cancel", role: .cancel) {}
            Button("Mark as False Alarm", role: .destructive) { model.markAllFalseAlarm() }
        } message: {
            Text("Only do this if you're sure this code is safe. RepoGuard stops warning about these exact file versions, and warns again if they change.")
        }
    }
}

struct ThreatRow: View {
    let finding: Finding
    @ObservedObject var model: AppModel
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
                Button("Show in Finder") { model.reveal(finding) }
            }
        }
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
                if model.repos.isEmpty {
                    EmptyState(icon: "folder", color: .secondary, title: model.loaded ? "No repositories yet" : "Looking for repos…", detail: "Clone a repo into a watched folder and it appears here automatically.")
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
