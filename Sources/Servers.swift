import AppKit
import Foundation
import Security
import SwiftUI

// Servers: scan and clean Linux servers over SSH. The scan engine, cleaner and server agent are
// sent with each run and deleted afterwards; nothing is installed on the server.

enum AuthKind: String, Codable, CaseIterable, Identifiable {
    case password = "Password", key = "Key file (.pem)", ec2Connect = "AWS EC2 Instance Connect"
    var id: String { rawValue }
}

struct Server: Codable, Identifiable, Hashable {
    var id = UUID().uuidString
    var name = ""
    var host = ""
    var port = 22
    var user = "ubuntu"
    var auth: AuthKind = .key
    var keyPath = ""
    var awsProfile = ""
    var awsRegion = ""
    var instanceId = ""
    var roots = "/var/www /home /root /opt /srv"
    var useSudo = true
}

struct ServerFinding: Codable, Identifiable, Hashable {
    let id: String
    let kind: String
    let path: String
    let detail: String
    let severity: String
    let fix: String
}

struct ServerFixResult: Codable, Hashable {
    let id: String
    let ok: Bool
    let path: String?
    let result: String
}

struct ServerInfo: Codable, Hashable {
    let host: String
    let root: Bool
    let python: String
}

struct ServerReport: Codable {
    var info: ServerInfo?
    var findings: [ServerFinding] = []
    var errors: [String]? = []
    var results: [ServerFixResult]? = nil
    var backup: String? = nil
    var time: Date? = nil
    var failure: String? = nil
}

// MARK: keychain

enum Keychain {
    static let service = "RepoGuard server"
    static func set(_ value: String, for account: String) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        SecItemDelete(base as CFDictionary)
        if value.isEmpty { return }
        var add = base
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
    static func get(_ account: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    static func delete(_ account: String) { set("", for: account) }
}

// MARK: processes

struct ProcResult { let status: Int32; let out: Data; let err: Data; var errText: String { String(data: err, encoding: .utf8) ?? "" } }

func runProcess(_ path: String, _ args: [String], env: [String: String] = [:], input: Data? = nil, timeout: TimeInterval = 900) -> ProcResult {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    var e = ProcessInfo.processInfo.environment
    e["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    for (k, v) in env { e[k] = v }
    p.environment = e
    p.currentDirectoryURL = URL(fileURLWithPath: "/")
    let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    p.standardInput = inPipe
    p.standardOutput = outPipe
    p.standardError = errPipe
    do { try p.run() } catch { return ProcResult(status: -1, out: Data(), err: Data(error.localizedDescription.utf8)) }
    DispatchQueue.global().async {
        if let input = input { try? inPipe.fileHandleForWriting.write(contentsOf: input) }
        try? inPipe.fileHandleForWriting.close()
    }
    var errData = Data(), outData = Data()
    let group = DispatchGroup()
    group.enter(); DispatchQueue.global().async { errData = errPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    group.enter(); DispatchQueue.global().async { outData = outPipe.fileHandleForReading.readDataToEndOfFile(); group.leave() }
    let timer = DispatchWorkItem { if p.isRunning { p.terminate() } }
    DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
    p.waitUntilExit()
    timer.cancel()
    group.wait()
    return ProcResult(status: p.terminationStatus, out: outData, err: errData)
}

func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

func findTool(_ names: [String]) -> String? { names.first { FileManager.default.isExecutableFile(atPath: $0) } }

// MARK: AWS

struct Ec2Instance: Identifiable, Hashable {
    let id: String
    let name: String
    let publicIp: String
    let privateIp: String
    let keyName: String
    let region: String
    var address: String { publicIp.isEmpty ? privateIp : publicIp }
}

enum AWS {
    static var cli: String? { findTool(["/opt/homebrew/bin/aws", "/usr/local/bin/aws", "/usr/bin/aws"]) }

    static func profiles() -> [(name: String, region: String)] {
        var regions: [String: String] = [:]
        var names: [String] = []
        func parse(_ file: String, prefixed: Bool) {
            guard let text = try? String(contentsOfFile: "\(home)/.aws/\(file)", encoding: .utf8) else { return }
            var current: String?
            for raw in text.split(separator: "\n") {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix("[") && line.hasSuffix("]") {
                    var n = String(line.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                    if prefixed && n.hasPrefix("profile ") { n = String(n.dropFirst(8)) }
                    if n.hasPrefix("sso-session ") { current = nil; continue }
                    current = n
                    if !names.contains(n) { names.append(n) }
                } else if let c = current, line.hasPrefix("region") {
                    regions[c] = line.split(separator: "=").last.map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
                }
            }
        }
        parse("config", prefixed: true)
        parse("credentials", prefixed: false)
        return names.map { ($0, regions[$0] ?? "") }
    }

    static func run(_ args: [String], profile: String, region: String) -> Result<Any, Error> {
        guard let cli = cli else { return .failure(err("The AWS CLI isn't installed. Install it with: brew install awscli")) }
        var a = args + ["--output", "json", "--profile", profile]
        if !region.isEmpty { a += ["--region", region] }
        let r = runProcess(cli, a, timeout: 60)
        if r.status != 0 { return .failure(err(r.errText.trimmingCharacters(in: .whitespacesAndNewlines))) }
        do { return .success(try JSONSerialization.jsonObject(with: r.out.isEmpty ? Data("{}".utf8) : r.out)) } catch { return .failure(error) }
    }

    static func regions(profile: String, fallback: String) -> [String] {
        if case .success(let j) = run(["ec2", "describe-regions"], profile: profile, region: fallback.isEmpty ? "us-east-1" : fallback),
           let list = (j as? [String: Any])?["Regions"] as? [[String: Any]] {
            return list.compactMap { $0["RegionName"] as? String }.sorted()
        }
        return fallback.isEmpty ? [] : [fallback]
    }

    static func instances(profile: String, region: String) -> Result<[Ec2Instance], Error> {
        switch run(["ec2", "describe-instances", "--filters", "Name=instance-state-name,Values=running"], profile: profile, region: region) {
        case .failure(let e): return .failure(e)
        case .success(let j):
            var out: [Ec2Instance] = []
            for res in ((j as? [String: Any])?["Reservations"] as? [[String: Any]]) ?? [] {
                for i in (res["Instances"] as? [[String: Any]]) ?? [] {
                    let tags = (i["Tags"] as? [[String: Any]]) ?? []
                    let name = tags.first { ($0["Key"] as? String) == "Name" }?["Value"] as? String ?? ""
                    out.append(Ec2Instance(id: i["InstanceId"] as? String ?? "", name: name,
                                           publicIp: i["PublicIpAddress"] as? String ?? "", privateIp: i["PrivateIpAddress"] as? String ?? "",
                                           keyName: i["KeyName"] as? String ?? "", region: region))
                }
            }
            return .success(out)
        }
    }

    /// A .pem for this key pair in the usual places, if the user has it.
    static func keyFile(for keyName: String) -> String? {
        guard !keyName.isEmpty else { return nil }
        let dirs = ["\(home)/.ssh", "\(home)/Downloads", "\(home)/Desktop", "\(home)/Documents", "\(home)/.ssh/keys"]
        for d in dirs { for ext in [".pem", "", ".key"] where FileManager.default.fileExists(atPath: "\(d)/\(keyName)\(ext)") { return "\(d)/\(keyName)\(ext)" } }
        return nil
    }
}

func err(_ s: String) -> NSError { NSError(domain: "RepoGuard", code: 10, userInfo: [NSLocalizedDescriptionKey: s]) }

// MARK: store

final class ServerStore: ObservableObject {
    @Published var servers: [Server] = []
    @Published var reports: [String: ServerReport] = [:]
    @Published var busy: [String: String] = [:]

    private let serversFile = "\(supportDir)/servers.json"
    private let reportsFile = "\(supportDir)/server-reports.json"

    init() {
        if let d = FileManager.default.contents(atPath: serversFile), let s = try? JSONDecoder().decode([Server].self, from: d) { servers = s }
        if let d = FileManager.default.contents(atPath: reportsFile), let r = try? JSONDecoder().decode([String: ServerReport].self, from: d) { reports = r }
    }

    private func save() {
        try? FileManager.default.createDirectory(atPath: supportDir, withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(servers) { FileManager.default.createFile(atPath: serversFile, contents: d, attributes: [.posixPermissions: 0o600]) }
        if let d = try? JSONEncoder().encode(reports) { FileManager.default.createFile(atPath: reportsFile, contents: d, attributes: [.posixPermissions: 0o600]) }
    }

    func upsert(_ s: Server, password: String?, sudoPassword: String?) {
        if let i = servers.firstIndex(where: { $0.id == s.id }) { servers[i] = s } else { servers.append(s) }
        if let p = password { Keychain.set(p, for: "\(s.id).ssh") }
        if let p = sudoPassword { Keychain.set(p, for: "\(s.id).sudo") }
        save()
    }

    func remove(_ s: Server) {
        servers.removeAll { $0.id == s.id }
        reports[s.id] = nil
        Keychain.delete("\(s.id).ssh")
        Keychain.delete("\(s.id).sudo")
        save()
    }

    var totalThreats: Int { reports.values.reduce(0) { $0 + $1.findings.filter { $0.severity == "block" }.count } }

    func scan(_ s: Server) { perform(s, label: "Scanning…", args: ["scan"]) }

    func clean(_ s: Server, ids: [String]) {
        guard !ids.isEmpty else { return }
        perform(s, label: "Removing…", args: ["clean", "--ids"] + ids)
    }

    private func perform(_ s: Server, label: String, args: [String]) {
        busy[s.id] = label
        let roots = s.roots.split(whereSeparator: { $0 == " " || $0 == "," || $0 == "\n" }).map(String.init)
        DispatchQueue.global().async {
            var report = ServerReport()
            switch self.runAgent(s, args: args + ["--roots"] + roots) {
            case .success(let r): report = r
            case .failure(let e): report = self.reports[s.id] ?? ServerReport(); report.failure = e.localizedDescription
            }
            report.time = Date()
            DispatchQueue.main.async {
                self.reports[s.id] = report
                self.busy[s.id] = nil
                self.save()
                self.log(s, report)
            }
        }
    }

    private func log(_ s: Server, _ r: ServerReport) {
        var lines: [String] = []
        let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let now = fmt.string(from: Date())
        if let f = r.failure { lines.append("\(now) SERVER ERROR \(s.name): \(f)") }
        for x in r.results ?? [] { lines.append("\(now) SERVER \(x.ok ? "CLEANED" : "MANUAL") \(s.name) \(x.path ?? x.id): \(x.result)") }
        if r.failure == nil && r.results == nil { lines.append("\(now) SERVER SCAN \(s.name): \(r.findings.filter { $0.severity == "block" }.count) threats, \(r.findings.filter { $0.severity != "block" }.count) to review") }
        guard let h = FileHandle(forWritingAtPath: logFile) else { return }
        h.seekToEndOfFile(); h.write(Data((lines.joined(separator: "\n") + "\n").utf8)); h.closeFile()
    }

    // The bundle is sent on stdin, unpacked into a private temp folder and deleted when done.
    private static let bootstrap = """
    import sys,json,os,tempfile,shutil,runpy
    b=json.loads(sys.stdin.read())
    d=tempfile.mkdtemp(prefix="repoguard-")
    try:
        for k,v in b["files"].items():
            with open(os.path.join(d,k),"w") as fh: fh.write(v)
        sys.argv=[os.path.join(d,"server_agent.py")]+b["args"]
        runpy.run_path(sys.argv[0],run_name="__main__")
    finally:
        shutil.rmtree(d,ignore_errors=True)
    """

    private func bundle(args: [String]) throws -> Data {
        var files: [String: String] = [:]
        for (name, ext) in [("engine", "py"), ("cleaner", "py"), ("server_agent", "py"), ("rules", "json")] {
            guard let p = Bundle.main.path(forResource: name, ofType: ext) else { throw err("RepoGuard is missing \(name).\(ext). Reinstall it.") }
            files["\(name).\(ext)"] = try String(contentsOfFile: p, encoding: .utf8)
        }
        return try JSONSerialization.data(withJSONObject: ["files": files, "args": args])
    }

    private func askpassPath() -> String {
        let p = "\(supportDir)/askpass.sh"
        let script = "#!/bin/sh\nprintf '%s\\n' \"$REPOGUARD_SSH_PASSWORD\"\n"
        FileManager.default.createFile(atPath: p, contents: Data(script.utf8), attributes: [.posixPermissions: 0o700])
        return p
    }

    /// A key pair RepoGuard pushes to an instance with EC2 Instance Connect (valid for 60 seconds per push).
    private func ec2TempKey() -> String? {
        let k = "\(supportDir)/ec2-connect-key"
        if !FileManager.default.fileExists(atPath: k) {
            let r = runProcess("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "repoguard", "-f", k])
            if r.status != 0 { return nil }
        }
        return k
    }

    func runAgentForTest(_ s: Server, args: [String]) -> Result<ServerReport, Error> { runAgent(s, args: args) }

    private func runAgent(_ s: Server, args: [String]) -> Result<ServerReport, Error> {
        var sshArgs = ["-p", String(s.port), "-T",
                       "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=\(supportDir)/known_hosts",
                       "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=20", "-o", "ServerAliveCountMax=6",
                       "-o", "LogLevel=ERROR"]
        var env: [String: String] = [:]
        switch s.auth {
        case .key:
            let key = (s.keyPath as NSString).expandingTildeInPath
            guard FileManager.default.fileExists(atPath: key) else { return .failure(err("Key file not found: \(s.keyPath)")) }
            sshArgs += ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        case .password:
            guard let pw = Keychain.get("\(s.id).ssh") else { return .failure(err("No password saved for this server. Edit it and enter the password.")) }
            env = ["SSH_ASKPASS": askpassPath(), "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": ":0", "REPOGUARD_SSH_PASSWORD": pw]
            sshArgs += ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
        case .ec2Connect:
            guard let key = ec2TempKey() else { return .failure(err("Couldn't create a temporary SSH key.")) }
            let r = AWS.run(["ec2-instance-connect", "send-ssh-public-key", "--instance-id", s.instanceId, "--instance-os-user", s.user,
                             "--ssh-public-key", "file://\(key).pub"], profile: s.awsProfile, region: s.awsRegion)
            if case .failure(let e) = r { return .failure(err("EC2 Instance Connect failed: \(e.localizedDescription)")) }
            sshArgs += ["-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        }
        let input: Data
        do { input = try bundle(args: args) } catch { return .failure(error) }
        var stdin = Data()
        var remote = "python3 -I -c \(shellQuote(Self.bootstrap))"
        if s.useSudo && s.user != "root" {
            if let sp = Keychain.get("\(s.id).sudo") ?? (s.auth == .password ? Keychain.get("\(s.id).ssh") : nil) {
                remote = "sudo -S -p '' \(remote)"
                stdin.append(Data((sp + "\n").utf8))
            } else {
                remote = "sudo -n \(remote) || { echo 'RG_NO_SUDO' >&2; exit 3; }"
            }
        }
        stdin.append(input)
        sshArgs += ["\(s.user)@\(s.host)", remote]
        let r = runProcess("/usr/bin/ssh", sshArgs, env: env, input: stdin, timeout: 1800)
        let text = r.errText
        if r.status == 255 { return .failure(err("Couldn't connect: \(text.trimmingCharacters(in: .whitespacesAndNewlines).suffix(300))")) }
        if text.contains("RG_NO_SUDO") || text.contains("a password is required") {
            return .failure(err("This user needs a sudo password. Edit the server and add it, or turn off \"Use sudo\" for a limited scan."))
        }
        if text.contains("python3: command not found") || text.contains("python3: not found") {
            return .failure(err("Python 3 isn't installed on the server."))
        }
        guard let line = String(data: r.out, encoding: .utf8)?.split(separator: "\n").last(where: { $0.hasPrefix("{") }),
              let report = try? JSONDecoder().decode(ServerReport.self, from: Data(line.utf8)) else {
            return .failure(err("The server scan failed: \(text.trimmingCharacters(in: .whitespacesAndNewlines).suffix(400))"))
        }
        return .success(report)
    }
}

let serverStore = ServerStore()

// MARK: views

private let sRed = Color(red: 0.84, green: 0.20, blue: 0.20)
private let sOrange = Color(red: 0.90, green: 0.55, blue: 0.12)
private let sGreen = Color(red: 0.11, green: 0.62, blue: 0.40)

struct ServersView: View {
    @ObservedObject var store = serverStore
    @State private var editing: Server?
    @State private var importing = false
    @State private var confirmClean: Server?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PageHeader(title: "Servers", subtitle: store.servers.isEmpty ? "Scan your VPS and EC2 servers for the same malware." : "\(store.servers.count) \(store.servers.count == 1 ? "server" : "servers") · \(store.totalThreats) threats") {
                    HStack(spacing: 8) {
                        Button("Import from AWS…") { importing = true }.controlSize(.large)
                        Button("Add Server…") { editing = Server() }.controlSize(.large).buttonStyle(.borderedProminent)
                    }
                }
                if store.servers.isEmpty {
                    EmptyState(icon: "server.rack", color: .secondary, title: "No servers yet",
                               detail: "Add a server with its SSH password or .pem key, or import your EC2 instances from your AWS profiles. RepoGuard checks web folders, startup entries and running programs, and nothing is installed on the server.")
                }
                ForEach(store.servers) { s in
                    ServerCard(server: s, store: store, edit: { editing = s }, clean: { confirmClean = s })
                }
            }
            .padding(24)
        }
        .sheet(item: $editing) { s in ServerEditor(server: s, store: store) }
        .sheet(isPresented: $importing) { AWSImportView(store: store) }
        .alert(item: $confirmClean) { s in
            let n = store.reports[s.id]?.findings.filter { $0.severity == "block" }.count ?? 0
            return Alert(title: Text("Remove \(n) threats on \(s.name)?"),
                         message: Text("Injected code is cut out of files and git history isn't touched. Bad startup entries are removed, bad services are stopped and disabled, and bad programs are stopped. Everything changed is backed up on the server in /var/backups/repoguard first."),
                         primaryButton: .destructive(Text("Remove Threats")) {
                             store.clean(s, ids: store.reports[s.id]?.findings.filter { $0.severity == "block" }.map(\.id) ?? [])
                         },
                         secondaryButton: .cancel())
        }
    }
}

struct ServerCard: View {
    let server: Server
    @ObservedObject var store: ServerStore
    let edit: () -> Void
    let clean: () -> Void
    @State private var open: Bool

    init(server: Server, store: ServerStore, edit: @escaping () -> Void, clean: @escaping () -> Void) {
        self.server = server; self.store = store; self.edit = edit; self.clean = clean
        let saved = UserDefaults.standard.object(forKey: "serverOpen.\(server.id)") as? Bool
        let hasThreats = store.reports[server.id]?.findings.contains { $0.severity == "block" } ?? false
        _open = State(initialValue: saved ?? hasThreats)
    }

    private var report: ServerReport? { store.reports[server.id] }
    private var threats: [ServerFinding] { report?.findings.filter { $0.severity == "block" } ?? [] }
    private var reviews: [ServerFinding] { report?.findings.filter { $0.severity != "block" } ?? [] }
    private var tint: Color { report?.failure != nil ? sOrange : (threats.isEmpty ? (report == nil ? .secondary : sGreen) : sRed) }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 0) {
                header
                if open {
                    VStack(alignment: .leading, spacing: 12) {
                        Divider().padding(.top, 12)
                        HStack(spacing: 18) {
                            Fact(title: "Address", value: "\(server.user)@\(server.host):\(server.port)")
                            Fact(title: "Sign-in", value: server.auth.rawValue)
                            Fact(title: "Folders", value: server.roots)
                        }
                        HStack(spacing: 8) {
                            if let b = store.busy[server.id] {
                                ProgressView().controlSize(.small); Text(b).foregroundColor(.secondary)
                            } else {
                                Button { store.scan(server) } label: { Label("Scan", systemImage: "arrow.clockwise") }
                                if !threats.isEmpty {
                                    Button(action: clean) { Label("Remove Threats…", systemImage: "trash") }.buttonStyle(.borderedProminent).tint(sRed)
                                }
                                Spacer()
                                Button(action: edit) { Label("Edit", systemImage: "pencil") }
                                Button(role: .destructive) { store.remove(server) } label: { Label("Delete", systemImage: "minus.circle") }
                            }
                        }
                        if let f = report?.failure {
                            Label(f, systemImage: "exclamationmark.triangle.fill").foregroundColor(sOrange).font(.callout)
                        }
                        if let results = report?.results, !results.isEmpty {
                            VStack(alignment: .leading, spacing: 3) {
                                Text("Last clean").font(.subheadline.bold())
                                ForEach(results, id: \.id) { r in
                                    Label("\(r.path ?? r.id): \(r.result)", systemImage: r.ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                                        .foregroundColor(r.ok ? sGreen : sOrange).font(.callout).lineLimit(2)
                                }
                                if let b = report?.backup { Text("Backups on the server: \(b)").font(.caption).foregroundColor(.secondary) }
                            }
                        }
                        if !threats.isEmpty || !reviews.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                ForEach(threats) { f in FindingRow(f: f, color: sRed, fix: nil) }
                                ForEach(reviews) { f in
                                    FindingRow(f: f, color: sOrange, fix: f.kind == "sshkeys" ? nil : { store.clean(server, ids: [f.id]) })
                                }
                            }
                        } else if report?.time != nil && report?.failure == nil {
                            Label("Nothing found on this server.", systemImage: "checkmark.seal.fill").foregroundColor(sGreen)
                        }
                        if let errs = report?.errors, !errs.isEmpty {
                            Text("Couldn't check everything: \(errs.prefix(3).joined(separator: "; "))").font(.caption).foregroundColor(.secondary).lineLimit(2)
                        }
                    }
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
        }
        .clipped()
    }

    private var header: some View {
        Button {
            withAnimation(.snappy(duration: 0.28)) { open.toggle() }
            UserDefaults.standard.set(open, forKey: "serverOpen.\(server.id)")
        } label: {
            HStack(spacing: 12) {
                Image(systemName: "chevron.right").font(.system(size: 12, weight: .bold)).foregroundColor(.secondary)
                    .rotationEffect(.degrees(open ? 90 : 0))
                ZStack {
                    Circle().fill(tint.opacity(0.16)).frame(width: 36, height: 36)
                    Image(systemName: "server.rack").foregroundColor(tint)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(server.name.isEmpty ? server.host : server.name).font(.headline)
                    Text(status).font(.callout).foregroundColor(.secondary).lineLimit(1)
                }
                Spacer()
                if store.busy[server.id] != nil { ProgressView().controlSize(.small) }
                Pill(text: pillText, color: tint)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var pillText: String {
        if report?.failure != nil { return "Can't connect" }
        if report == nil { return "Not scanned" }
        if !threats.isEmpty { return "\(threats.count) threat\(threats.count == 1 ? "" : "s")" }
        return reviews.isEmpty ? "Clean" : "\(reviews.count) to review"
    }

    private var status: String {
        guard let r = report, let t = r.time else { return "\(server.user)@\(server.host) · not scanned yet" }
        let who = r.info.map { "\($0.host)\($0.root ? "" : " · limited scan, no root")" } ?? server.host
        return "Scanned \(relativeTime(t)) · \(who)"
    }
}

struct Fact: View {
    let title: String
    let value: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundColor(.secondary)
            Text(value).font(.callout).lineLimit(1).truncationMode(.middle)
        }
    }
}

struct Pill: View {
    let text: String
    let color: Color
    var body: some View {
        Text(text).font(.caption.bold()).foregroundColor(color)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background(Capsule().fill(color.opacity(0.15)))
    }
}

struct FindingRow: View {
    let f: ServerFinding
    let color: Color
    let fix: (() -> Void)?
    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: icon).foregroundColor(color).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(f.detail).lineLimit(3)
                Text(f.path).font(.system(.caption, design: .monospaced)).foregroundColor(.secondary).lineLimit(1).truncationMode(.middle)
                Text("Fix: \(f.fix)").font(.caption).foregroundColor(.secondary)
            }
            Spacer()
            if let fix = fix { Button("Fix", action: fix).controlSize(.small) }
        }
    }
    private var icon: String {
        switch f.kind {
        case "process": return "cpu"
        case "service": return "gearshape.2.fill"
        case "autostart", "preload", "pm2", "launchd", "shell", "cron": return "bolt.fill"
        case "login": return "person.crop.circle.badge.exclamationmark"
        case "sshkeys": return "key.fill"
        case "tempfile": return "trash.fill"
        default: return "doc.text.fill"
        }
    }
}

struct ServerEditor: View {
    @State var server: Server
    @ObservedObject var store: ServerStore
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var sudoPassword = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(Color.accentColor.opacity(0.15)).frame(width: 40, height: 40)
                    Image(systemName: "server.rack").foregroundColor(.accentColor)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(isNew ? "Add Server" : "Edit Server").font(.title2.bold())
                    Text("Nothing is installed on the server. Each scan sends the scanner, runs it, and deletes it.")
                        .font(.callout).foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 6)

            Form {
                Section("Server") {
                    TextField("Name", text: $server.name, prompt: Text("ChainSol production"))
                    TextField("Host or IP", text: $server.host, prompt: Text("203.0.113.10"))
                    TextField("User", text: $server.user, prompt: Text("root"))
                    TextField("Port", value: $server.port, format: .number.grouping(.never))
                }
                Section {
                    Picker("Sign in with", selection: $server.auth) {
                        ForEach(AuthKind.allCases) { Text($0.rawValue).tag($0) }
                    }
                    switch server.auth {
                    case .password:
                        SecureField("Password", text: $password, prompt: Text(hasSavedPassword ? "Saved, type to change" : "Server password"))
                    case .key:
                        HStack {
                            TextField("Key file", text: $server.keyPath, prompt: Text("~/.ssh/my-key.pem"))
                            Button("Choose…") {
                                let p = NSOpenPanel(); p.canChooseFiles = true; p.canChooseDirectories = false; p.showsHiddenFiles = true
                                p.directoryURL = URL(fileURLWithPath: "\(home)/.ssh")
                                if p.runModal() == .OK, let u = p.url { server.keyPath = u.path }
                            }
                        }
                    case .ec2Connect:
                        TextField("AWS profile", text: $server.awsProfile, prompt: Text("default"))
                        TextField("Region", text: $server.awsRegion, prompt: Text("eu-north-1"))
                        TextField("Instance ID", text: $server.instanceId, prompt: Text("i-0123456789abcdef0"))
                    }
                } header: {
                    Text("Sign in")
                } footer: {
                    Text("Passwords are kept in your Mac's Keychain.").font(.caption).foregroundColor(.secondary)
                }
                Section {
                    Toggle("Use sudo", isOn: $server.useSudo)
                    if server.useSudo && server.user != "root" {
                        SecureField("sudo password", text: $sudoPassword, prompt: Text("Leave empty if sudo needs no password"))
                    }
                    TextField("Folders", text: $server.roots, prompt: Text("/var/www /home /root /opt /srv"))
                } header: {
                    Text("Scan")
                } footer: {
                    Text("sudo lets RepoGuard check and fix system startup entries and other users' files. Separate folders with spaces.")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).controlSize(.large)
                Button(isNew ? "Add and Scan" : "Save and Scan") {
                    if server.name.isEmpty { server.name = server.host }
                    store.upsert(server, password: password.isEmpty ? nil : password, sudoPassword: sudoPassword.isEmpty ? nil : sudoPassword)
                    store.scan(server)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(server.host.isEmpty || server.user.isEmpty || (server.auth == .ec2Connect && server.instanceId.isEmpty))
            }
            .padding(.horizontal, 22).padding(.bottom, 20).padding(.top, 4)
        }
        .frame(width: 620, height: 770)
    }

    private var isNew: Bool { !store.servers.contains { $0.id == server.id } }
    private var hasSavedPassword: Bool { Keychain.get("\(server.id).ssh") != nil }
}

struct AWSImportView: View {
    @ObservedObject var store: ServerStore
    @Environment(\.dismiss) private var dismiss
    @State private var profiles: [(name: String, region: String)] = AWS.profiles()
    @State private var profile = ""
    @State private var region = ""
    @State private var allRegions = false
    @State private var user = "ubuntu"
    @State private var instances: [Ec2Instance] = []
    @State private var picked: Set<String> = []
    @State private var loading = false
    @State private var message: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import EC2 Instances").font(.title2.bold())
            if AWS.cli == nil {
                Text("The AWS CLI isn't installed. Install it with `brew install awscli`, then run `aws configure` or `aws sso login`.").foregroundColor(sOrange)
            } else if profiles.isEmpty {
                Text("No AWS profiles found in ~/.aws. Run `aws configure` first.").foregroundColor(sOrange)
            } else {
                Form {
                    Picker("Profile", selection: $profile) { ForEach(profiles, id: \.name) { Text($0.name).tag($0.name) } }
                        .onChange(of: profile) { p in region = profiles.first { $0.name == p }?.region ?? "" }
                    TextField("Region", text: $region, prompt: Text("ap-south-1"))
                    Toggle("Search every region", isOn: $allRegions)
                    TextField("Server user", text: $user, prompt: Text("ubuntu or ec2-user"))
                }
                HStack {
                    Button(loading ? "Loading…" : "Find Running Instances", action: load).disabled(loading || profile.isEmpty)
                    if loading { ProgressView().controlSize(.small) }
                    if let m = message { Text(m).foregroundColor(.secondary).lineLimit(2) }
                }
                if !instances.isEmpty {
                    List(instances) { i in
                        Toggle(isOn: Binding(get: { picked.contains(i.id) }, set: { on in if on { picked.insert(i.id) } else { picked.remove(i.id) } })) {
                            VStack(alignment: .leading, spacing: 1) {
                                Text(i.name.isEmpty ? i.id : "\(i.name) (\(i.id))")
                                Text("\(i.address) · \(i.region) · " + (AWS.keyFile(for: i.keyName) != nil ? "key \(i.keyName).pem found" : "no .pem found: EC2 Instance Connect"))
                                    .font(.caption).foregroundColor(.secondary)
                            }
                        }
                    }.frame(height: 220)
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Import and Scan \(picked.count)") { importPicked() }.keyboardShortcut(.defaultAction).disabled(picked.isEmpty)
            }
        }
        .padding(22)
        .frame(width: 620)
        .onAppear { if profile.isEmpty, let f = profiles.first { profile = f.name; region = f.region } }
    }

    private func load() {
        loading = true; message = nil; instances = []
        let p = profile, r = region, all = allRegions
        DispatchQueue.global().async {
            let regions = all ? AWS.regions(profile: p, fallback: r) : [r]
            var found: [Ec2Instance] = [], errors: [String] = []
            for reg in regions {
                switch AWS.instances(profile: p, region: reg) {
                case .success(let list): found += list
                case .failure(let e): errors.append("\(reg.isEmpty ? "default region" : reg): \(e.localizedDescription)")
                }
            }
            DispatchQueue.main.async {
                loading = false
                instances = found
                picked = Set(found.map(\.id))
                message = found.isEmpty ? (errors.first ?? "No running instances found.") : "\(found.count) running" + (errors.isEmpty ? "" : " · \(errors.count) regions failed")
            }
        }
    }

    private func importPicked() {
        for i in instances where picked.contains(i.id) {
            var s = store.servers.first { $0.instanceId == i.id } ?? Server()
            s.name = i.name.isEmpty ? i.id : i.name
            s.host = i.address
            s.user = user
            s.instanceId = i.id
            s.awsProfile = profile
            s.awsRegion = i.region
            if let k = AWS.keyFile(for: i.keyName) { s.auth = .key; s.keyPath = k } else { s.auth = .ec2Connect }
            store.upsert(s, password: nil, sudoPassword: nil)
            store.scan(s)
        }
        dismiss()
    }
}
