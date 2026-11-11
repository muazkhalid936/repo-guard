"""RepoGuard Mac scan: things that start automatically, running programs, and risky folders.

  mac_agent.py scan  --backup DIR
  mac_agent.py clean --backup DIR --ids ID [ID ...]

scan looks at:
  * launchd agents and daemons (~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons):
    what each one runs, who signed it, and whether it hides in a temp/cache folder or pretends to be Apple
  * login items, your crontab, and shell startup files (.zshrc, .zprofile, /etc/zshrc ...)
  * VS Code / Cursor user settings and tasks that run code when a folder opens
  * running processes: crypto-miners, known malware commands, programs and scripts started from
    temp or cache folders, unsigned programs using a lot of CPU
  * scripts dropped in /tmp, /var/tmp, /Users/Shared and ~/Library/Caches

Every launchd item is also listed in "inventory" (with who signed it), so any of them can be turned off.

clean re-checks each id and fixes only those. Everything it removes is copied into the backup folder
first. Items that need administrator rights are returned with needs_admin=true when not run as root.
Prints JSON.
"""
import argparse, datetime, getpass, hashlib, importlib.util, json, os, plistlib, pwd, re, signal, stat, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    spec = importlib.util.spec_from_file_location("rg_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


engine = _load("engine")
cleaner = _load("cleaner")
RULES = engine.Rules(os.path.join(HERE, "rules.json"))
cleaner.RULES = RULES

IS_ROOT = os.geteuid() == 0
# When run as root through the admin prompt, look at the person's own home, not root's.
USER = os.environ.get("REPOGUARD_USER") or (os.environ.get("SUDO_USER") if IS_ROOT else None) or getpass.getuser()
try:
    PW = pwd.getpwnam(USER)
    HOME, UID = PW.pw_dir, PW.pw_uid
except KeyError:
    HOME, UID = os.path.expanduser("~"), os.getuid()
TESTING = bool(os.environ.get("REPOGUARD_TEST_HOME"))
if TESTING:  # tests point the scan at a fake home and skip the parts that read the real Mac
    HOME = os.environ["REPOGUARD_TEST_HOME"]

BAD_CMD = re.compile(
    r"(?:curl|wget)[^|;&]*\|\s*(?:ba|z|da)?sh\b"
    r"|base64\s+(?:-d|-D|--decode)[^|]*\|\s*(?:ba|z)?sh"
    r"|\bnode\s+\S*(?:/|\b)init\b"
    r"|\.orc\b|fa-brand-400|fa-solid-400\.woff2"
    r"|/tmp/\.|/var/tmp/\."
    r"|xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|stratum\+tcp|nicehash|cryptonight"
    r"|ethplorer|eth_getTransactionByHash"
    r"|jsonkeeper\.com|npoint\.io"
    r"|iconservices\.store/CatalogData", re.I)
ODD_CMD = re.compile(r"\b(?:nohup|setsid)\b.*\s(?:/tmp|/var/tmp|/private/tmp)/|python3?\s+-c\s+['\"].*(?:urllib|socket)|\bnc\s+-e\b|/bin/sh\s+-i"
                     r"|osascript\s+-e\s+.*do shell script|DYLD_INSERT_LIBRARIES", re.I)
MINERS = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|nicehash|nbminer|t-rex|phoenixminer|lolminer|gminer|\bkthreaddk\b", re.I)
REMOTE_TOOLS = re.compile(r"anydesk|teamviewer|hoptodesk|rustdesk|screenconnect|connectwise|splashtop|logmein|remotepc|ammyy|supremo|dwservice|meshagent|ultraviewer", re.I)
INTERPRETERS = re.compile(r"(?:^|/)(?:python[0-9.]*|node|nodejs|osascript|perl[0-9.]*|ruby|bash|zsh|sh|dash|php|deno|bun)$", re.I)


def running_script(exe, cmd):
    """The script an interpreter process is running, if any."""
    args = cmd.split()
    if INTERPRETERS.search(exe) or (args and INTERPRETERS.search(args[0])):
        return script_of(["python"] + args[1:]) if args else None
    return None

# Places programs shouldn't start from. Paths are compared after resolving /private.
TEMP_LOC = re.compile(r"^(?:/private)?/(?:tmp|var/tmp|var/folders)/")
CACHE_LOC = re.compile(r"^(?:/Users/[^/]+/Library/Caches/|/Library/Caches/|/Users/Shared/|.*/rg-fakehome/Library/Caches/)")
HIDDEN_DIR = re.compile(r"^/Users/[^/]+/(?:\.[^/]+/|Library/Application Support/\.[^/]+/|Library/\.[^/]+/)")
# Hidden folders that developer tools normally run from (package managers, version managers, editors).
TOOL_DIRS = re.compile(r"^/Users/[^/]+/\.(?:npm|nvm|cache|local|bun|deno|cargo|rustup|pyenv|rbenv|volta|vscode|vscode-insiders|cursor|windsurf"
                       r"|docker|orbstack|gradle|m2|yarn|pnpm-store|config|claude|codex|sdkman|asdf|fnm|rye|poetry|conda|miniconda3|android"
                       r"|expo|rd|colima|lima|kube|gem|swiftpm|dotnet|opam|ghcup|elan|juliaup|wasmtime|foundry|cursor-server|pub-cache"
                       r"|flutter|dart-tool|bundle|jenv|goenv|nodenv|n|tfenv|mint|codeium|copilot|antigravity|gemini|ollama|lmstudio|continue)/")


def finding(kind, path, detail, severity, fix, **extra):
    raw = f"{kind}|{path}|{extra.get('line', '')}|{extra.get('pid', '')}|{extra.get('cmd', '')}|{extra.get('label', '')}"
    fid = hashlib.sha1(raw.encode()).hexdigest()[:16]
    return dict(id=fid, kind=kind, path=path, detail=detail, severity=severity, fix=fix, **extra)


def read(path, limit=2_000_000):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def run(args, input=None, timeout=20):
    try:
        r = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return r.returncode, r.stdout.decode("utf8", "replace"), r.stderr.decode("utf8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


_signers = {}


def signer(path):
    """'Apple', 'Developer ID: Name (TEAM)', 'App Store', 'ad-hoc', 'unsigned' or 'missing'."""
    if not path:
        return "missing"
    if path in _signers:
        return _signers[path]
    if not os.path.exists(path):
        _signers[path] = "missing"
        return "missing"
    target = path
    m = re.match(r"(.*?\.app)/Contents/MacOS/", path)
    if m:
        target = m.group(1)
    rc, out, err = run(["/usr/bin/codesign", "-dv", "--verbose=2", target])
    text = out + err
    if "not signed at all" in text:
        who = "unsigned"
    elif "Signature=adhoc" in text:
        who = "ad-hoc"
    else:
        auth = re.findall(r"Authority=(.+)", text)
        first = auth[0].strip() if auth else ""
        if first.startswith("Developer ID Application:"):
            who = "Developer ID: " + first.split(":", 1)[1].strip()
        elif first.startswith("Apple Mac OS Application Signing"):
            who = "App Store"
        elif first.startswith("Software Signing"):
            who = "Apple"
        elif first:
            who = first
        elif "Operation not permitted" in text or "Permission denied" in text or not text.strip():
            who = "needs admin to check"
        else:
            who = "unknown"
    # Homebrew builds are ad-hoc signed by design on Apple Silicon.
    if who in ("ad-hoc", "unsigned") and norm(path).startswith(("/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/Homebrew/")):
        who = "Homebrew"
    if who == "ad-hoc" and "/RepoGuard.app/" in path:
        who = "RepoGuard"
    _signers[path] = who
    return who


def trusted(who):
    return who in ("Apple", "App Store", "Homebrew", "needs admin to check") or who.startswith("Developer ID")


def norm(p):
    return os.path.realpath(p) if p else p


def risky_place(p):
    p = norm(p) or ""
    if TEMP_LOC.match(p):
        return "a temp folder"
    if CACHE_LOC.match(p):
        return "a cache or shared folder"
    if HIDDEN_DIR.match(p) and not TOOL_DIRS.match(p):
        return "a hidden folder"
    return None


def script_of(args):
    """For `python3 /x/y.py ...` style commands, the script that actually runs."""
    if not args or not INTERPRETERS.search(args[0]):
        return None
    skip_next = False
    for a in args[1:]:
        if skip_next:
            skip_next = False
            continue
        if a in ("-c", "-e", "--eval"):
            return None
        if a in ("-m", "-W", "-X", "--require", "-r"):
            skip_next = True
            continue
        if a.startswith("-"):
            continue
        return os.path.expanduser(a)
    return None


# ---------------------------------------------------------------- launchd

LAUNCH_DIRS = [(os.path.join(HOME, "Library/LaunchAgents"), "user agent", False)] + ([] if TESTING else [
               ("/Library/LaunchAgents", "agent for every user", True),
               ("/Library/LaunchDaemons", "system daemon", True)])


def scan_launchd(out, inventory, errors):
    for d, where, needs_root in LAUNCH_DIRS:
        try:
            names = sorted(os.listdir(d))
        except OSError:
            continue
        for n in names:
            if not n.endswith(".plist"):
                continue
            p = os.path.join(d, n)
            try:
                with open(p, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:
                out.append(finding("launchd", p, f"{n}: can't be read as a launchd file", "review",
                                   "turn it off (the file is moved to the backup)", label=n[:-6], root=needs_root))
                continue
            label = str(pl.get("Label") or n[:-6])
            args = [str(a) for a in (pl.get("ProgramArguments") or [])]
            prog = str(pl.get("Program") or (args[0] if args else ""))
            if pl.get("Program") and args:
                args = [prog] + args[1:]
            elif not args:
                args = [prog]
            prog = os.path.expanduser(prog)
            script = script_of(args)
            target = script or prog
            who = signer(prog) if not script else signer(script) if os.path.exists(script) and not script.endswith((".py", ".js", ".sh", ".rb", ".pl")) else ("script" if script and os.path.exists(script) else "missing")
            cmd = " ".join(args)
            item = dict(id=finding("launchd", p, "", "", "", label=label)["id"], label=label, plist=p, program=target,
                        command=cmd[:400], signer=who, where=where, root=needs_root,
                        runs_at_load=bool(pl.get("RunAtLoad")), keep_alive=bool(pl.get("KeepAlive")),
                        disabled=bool(pl.get("Disabled")), changed=datetime.datetime.fromtimestamp(os.lstat(p).st_mtime).strftime("%Y-%m-%d"))
            inventory.append(item)
            why, sev = None, "block"
            place = risky_place(target)
            if label.startswith("com.apple.") or n.startswith("com.apple."):
                why = "pretends to be part of macOS (Apple never puts its own items here)"
            elif BAD_CMD.search(cmd) or MINERS.search(cmd):
                why = "runs a known malware command"
            elif place and not trusted(who):
                why = f"runs a program from {place}"
            elif script and place:
                why = f"runs a script from {place}"
            elif ODD_CMD.search(cmd):
                why, sev = "runs an unusual shell command", "review"
            elif REMOTE_TOOLS.search(cmd + " " + label):
                why, sev = "remote-control software that starts automatically. Keep it only if you use it", "review"
            elif not prog:
                why, sev = "is empty; a leftover from software that was uninstalled", "review"
            elif who == "missing":
                why, sev = "points at a program that no longer exists", "review"
            elif who in ("unsigned", "ad-hoc") and not script and not prog.startswith(("/opt/homebrew/", "/usr/local/")):
                why, sev = "starts an unsigned program", "review"
            if why:
                fix = "turn it off and move the file to the backup" + ("; also quarantine the program" if place else "")
                runs = f" Runs: {cmd[:220]}" if cmd.strip() else ""
                out.append(finding("launchd", p, f"{label}: {why}.{runs}", sev, fix,
                                   label=label, root=needs_root, item=item["id"]))


# ---------------------------------------------------------------- login items, cron, shell files

def scan_login_items(out, inventory, errors):
    if TESTING:
        return
    rc, o, e = run(["/usr/bin/osascript", "-e",
                    'tell application "System Events" to get {name, path} of every login item'], timeout=15)
    if rc:
        errors.append("Couldn't read login items (allow RepoGuard to control System Events in Privacy & Security > Automation).")
        return
    parts = [x.strip() for x in o.strip().split(", ")]
    half = len(parts) // 2
    for name, path in zip(parts[:half], parts[half:]):
        who = signer(path)
        item = dict(id=finding("login", path, "", "", "", label=name)["id"], label=name, plist="", program=path, command=path,
                    signer=who, where="login item", root=False, runs_at_load=True, keep_alive=False, disabled=False, changed="")
        inventory.append(item)
        place = risky_place(path)
        if place or REMOTE_TOOLS.search(name + path) or who in ("unsigned", "ad-hoc"):
            why = f"opens from {place}" if place else ("remote-control software" if REMOTE_TOOLS.search(name + path) else "unsigned app")
            out.append(finding("login", path, f"Login item {name}: {why}", "block" if place else "review",
                               "remove it from login items", label=name, item=item["id"]))


SHELL_FILES = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile", ".bash_login"]
ETC_SHELL = ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/bashrc"]
RUN_FROM_RISKY = re.compile(r"(?:python3?|node|osascript|bash|sh|perl|ruby)\s+['\"]?(?:~|\$HOME|/Users/[^/\s]+)?/?\S*(?:Library/Caches/|/tmp/|/Users/Shared/)", re.I)


def check_lines(path, text, out, kind, root):
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if BAD_CMD.search(s) or RUN_FROM_RISKY.search(s) or re.search(r"\bDYLD_INSERT_LIBRARIES\s*=", s):
            out.append(finding(kind, path, f"line {i}: {s[:220]}", "block", "remove this line", line=s, root=root))
        elif ODD_CMD.search(s):
            out.append(finding(kind, path, f"line {i}: {s[:220]}", "review", "remove this line", line=s, root=root))


def scan_shell_and_cron(out, errors):
    for n in SHELL_FILES:
        p = os.path.join(HOME, n)
        data = read(p)
        if data is not None:
            check_lines(p, data.decode("utf8", "replace"), out, "shell", False)
    for p in ([] if TESTING else ETC_SHELL):
        data = read(p)
        if data is not None:
            check_lines(p, data.decode("utf8", "replace"), out, "shell", True)
    args = ["/usr/bin/crontab", "-l"] if not IS_ROOT else ["/usr/bin/crontab", "-u", USER, "-l"]
    rc, o, e = run(args) if not TESTING else (1, "", "")
    if rc == 0 and o.strip():
        before = len(out)
        check_lines("crontab", o, out, "cron", False)
        if len(out) == before:
            jobs = [l for l in o.splitlines() if l.strip() and not l.strip().startswith("#")]
            if jobs:
                out.append(finding("cron", "crontab", f"{len(jobs)} scheduled job(s): {jobs[0][:160]}", "review",
                                   "review by hand (crontab -e)"))


# ---------------------------------------------------------------- editors

EDITOR_DIRS = ["Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"]


def scan_editors(out):
    for ed in EDITOR_DIRS:
        for n in ("settings.json", "tasks.json"):
            p = os.path.join(HOME, "Library/Application Support", ed, "User", n)
            data = read(p)
            if data is None:
                continue
            content_ids = {r["id"] for r in RULES.content_rules}
            hits = [h for h in RULES.check(".vscode/" + n, data) if h[0] in content_ids]  # the file existing isn't a problem
            if hits:
                sev = "block" if any(h[1] == "block" and h[0] != "autorun" for h in hits) else "review"
                out.append(finding("file", p, f"{ed} {n}: " + ", ".join(sorted({h[2] for h in hits})), sev,
                                   "cut out the setting", rules=[list(h) for h in hits], rel=".vscode/" + n))


# ---------------------------------------------------------------- risky folders

def scan_risky_folders(out):
    tops = [("/private/tmp", 4), ("/private/var/tmp", 4), ("/Users/Shared", 3), (os.path.join(HOME, "Library/Caches"), 3)]
    if TESTING:
        tops = [(os.path.join(HOME, "Library/Caches"), 3)]
    for top, depth in tops:
        base = top.count(os.sep)
        for cur, dirs, names in os.walk(top, followlinks=False):
            if cur.count(os.sep) - base >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "Homebrew", "pip", "go-build", "com.apple.python")
                       and not d.startswith("repoguard-") and not engine.QUARANTINE.search(d)]
            for n in names:
                p = os.path.join(cur, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > 3_000_000 or st.st_size < 40:
                    continue
                head = read(p, 4096) or b""
                is_script = n.endswith((".js", ".mjs", ".cjs", ".sh", ".py", ".command", ".orc", ".scpt")) or head.startswith(b"#!")
                data_file = n.lower().endswith((".json", ".jsonl", ".txt", ".md", ".log", ".html", ".htm", ".csv", ".map", ".xml", ".plist", ".yml", ".yaml"))
                if not is_script and not data_file and b"\0" not in head[:1024] and re.search(rb"require\(|import |eval\(|exec\(|child_process|subprocess", head):
                    is_script = True  # script content without an extension, like the fake CatalogData file
                if not is_script:
                    continue
                data = read(p, RULES.max)
                hits = [h for h in RULES.check(p, data) if h[1] == "block"]
                text = (data or b"").decode("utf8", "replace")
                if hits or BAD_CMD.search(text):
                    what = ", ".join(sorted({h[2] for h in hits})) or "known malware command"
                    out.append(finding("tempfile", p, f"script in {risky_place(p) or 'a temp folder'}: {what}", "block", "delete the file (backed up)"))


# ---------------------------------------------------------------- processes

def processes():
    rc, a, _ = run(["/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,%cpu=,args="])
    rc2, c, _ = run(["/bin/ps", "-axww", "-o", "pid=,comm="])
    exe = {}
    for line in c.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)$", line)
        if m:
            exe[int(m.group(1))] = m.group(2).strip()
    procs = []
    for line in a.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+(.*)$", line)
        if m:
            pid = int(m.group(1))
            procs.append(dict(pid=pid, ppid=int(m.group(2)), uid=int(m.group(3)), cpu=float(m.group(4)), cmd=m.group(5), exe=exe.get(pid, "")))
    return procs


def scan_processes(out):
    me = {os.getpid(), os.getppid()}
    for pr in processes():
        if pr["pid"] in me or pr["pid"] < 2:
            continue
        cmd, exe = pr["cmd"], pr["exe"]
        if "repoguard" in cmd.lower() and "/RepoGuard.app/" in cmd:
            continue
        why, sev = None, "block"
        args = cmd.split()
        script = running_script(exe, cmd)
        place = risky_place(exe) if exe.startswith("/") else None
        splace = risky_place(script) if script else None
        if MINERS.search(cmd) or MINERS.search(exe):
            why = "known crypto-miner"
        elif BAD_CMD.search(cmd):
            why = "runs a known malware command"
        elif splace:
            why = f"runs a script from {splace}"
        elif place:
            who = signer(exe)
            if not trusted(who):
                why = f"unsigned program running from {place}"
                if place == "a temp folder" and not os.path.basename(exe).startswith("."):
                    sev = "review"  # build tools (go run, swift) run unsigned binaries from temp folders too
        elif REMOTE_TOOLS.search(exe):
            why, sev = "remote-control software is running. Keep it only if you use it", "review"
        elif pr["cpu"] >= 90 and exe.startswith("/") and not exe.startswith(("/System/", "/usr/", "/bin/", "/sbin/", "/Applications/Xcode")):
            who = signer(exe)
            if not trusted(who):
                why, sev = f"unsigned program using {pr['cpu']:.0f}% CPU (miners look like this)", "review"
        if why:
            try:
                user = pwd.getpwuid(pr["uid"]).pw_name
            except KeyError:
                user = str(pr["uid"])
            out.append(finding("process", exe or args[0], f"PID {pr['pid']} ({user}): {why}: {cmd[:220]}", sev,
                               "stop the process" + (" and quarantine its program" if place or splace else ""),
                               pid=pr["pid"], cmd=cmd[:500], root=pr["uid"] != UID and pr["uid"] == 0))


# ---------------------------------------------------------------- clean

class Fixer:
    def __init__(self, backup):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.backup_dir = os.path.join(backup, "mac-" + stamp)
        cleaner.BACKUP = self.backup_dir
        cleaner.TMPDIR = os.path.join(backup, ".tmp")
        os.makedirs(cleaner.TMPDIR, exist_ok=True)
        cleaner.NODE = cleaner.find_node()

    def backup(self, path):
        data = read(path, 80_000_000)
        if data is not None:
            dst = cleaner.backup(path, data, "")
            if IS_ROOT:
                try:
                    os.chown(dst, UID, -1)
                except OSError:
                    pass
            return dst

    def quarantine(self, path):
        if not path or not os.path.lexists(path):
            return "already gone"
        if os.path.isdir(path):
            return "is a folder; left in place"
        self.backup(path)
        os.unlink(path)
        return "moved to backup"

    def remove_line(self, path, line):
        if path == "crontab":
            args = ["/usr/bin/crontab", "-l"] if not IS_ROOT else ["/usr/bin/crontab", "-u", USER, "-l"]
            rc, o, e = run(args)
            lines = o.split("\n")
            keep = [l for l in lines if l.strip() != line]
            if len(keep) == len(lines):
                return "already gone"
            os.makedirs(self.backup_dir, exist_ok=True)
            with open(os.path.join(self.backup_dir, "crontab.quarantined"), "w") as fh:
                fh.write(o)
            put = ["/usr/bin/crontab", "-"] if not IS_ROOT else ["/usr/bin/crontab", "-u", USER, "-"]
            rc, _, e = run(put, input="\n".join(keep).encode())
            if rc:
                raise RuntimeError(e.strip()[-200:])
            return "removed the cron job"
        data = read(path)
        if data is None:
            raise RuntimeError("can't read the file")
        lines = data.decode("utf8", "replace").split("\n")
        keep = [l for l in lines if l.strip() != line]
        if len(keep) == len(lines):
            return "already gone"
        self.backup(path)
        st = os.stat(path)
        tmp = path + ".rg-tmp"
        with open(tmp, "w") as fh:
            fh.write("\n".join(keep))
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        if IS_ROOT:
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
        return "removed the line"

    def launchd_off(self, plist, label, root, program=None):
        if not os.path.exists(plist):
            return "already gone"
        if "/LaunchDaemons/" in plist:
            domain = "system"
        elif plist.startswith(HOME):
            domain = f"gui/{UID}"
        else:
            domain = f"gui/{UID}"
        run(["/bin/launchctl", "bootout", f"{domain}/{label}"])
        run(["/bin/launchctl", "bootout", domain, plist])
        msg = "turned off; plist " + self.quarantine(plist)
        if program and risky_place(program) and os.path.isfile(program):
            msg += "; program " + self.quarantine(program)
        return msg

    def fix(self, f, inv):
        if f.get("root") and not IS_ROOT:
            raise NeedsAdmin()
        k = f["kind"]
        if k == "launchd":
            item = inv.get(f.get("item") or f["id"], {})
            return self.launchd_off(f["path"], f.get("label") or item.get("label", ""), f.get("root"), item.get("program"))
        if k == "login":
            name = f.get("label", "")
            rc, o, e = run(["/usr/bin/osascript", "-e", f'tell application "System Events" to delete login item "{name}"'])
            if rc:
                raise RuntimeError(e.strip()[-200:] or "couldn't remove the login item")
            return "removed from login items"
        if k in ("shell", "cron"):
            return self.remove_line(f["path"], f["line"])
        if k == "tempfile":
            return self.quarantine(f["path"])
        if k == "file":
            data = read(f["path"], RULES.max + 1)
            if data is None:
                return "already gone"
            hits = RULES.check(f.get("rel") or f["path"], data)
            if not hits:
                return "already clean"
            new, notes = cleaner.clean_text(f.get("rel") or f["path"], data, hits)
            self.backup(f["path"])
            if new is None:
                os.unlink(f["path"])
                return "deleted: " + "; ".join(notes)
            with open(f["path"], "wb") as fh:
                fh.write(new)
            return "cleaned: " + "; ".join(notes)
        if k == "process":
            pid = int(f["pid"])
            now = next((p for p in processes() if p["pid"] == pid), None)
            if not now:
                return "already stopped"
            if now["cmd"][:500] != f["cmd"]:
                return "PID now belongs to another program; left alone"
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(1.0)
                if any(p["pid"] == pid for p in processes()):
                    os.kill(pid, signal.SIGKILL)
            except PermissionError:
                raise NeedsAdmin()
            extra = ""
            exe = now["exe"]
            if exe and risky_place(exe) and os.path.isfile(exe):
                extra = "; program " + self.quarantine(exe)
            script = running_script(exe, now["cmd"])
            if script and risky_place(script) and os.path.isfile(script):
                extra += "; script " + self.quarantine(script)
            return "stopped" + extra
        raise RuntimeError("review this one by hand")


class NeedsAdmin(Exception):
    pass


def scan():
    out, inventory, errors = [], [], []
    for step in (lambda: scan_launchd(out, inventory, errors), lambda: scan_login_items(out, inventory, errors),
                 lambda: scan_shell_and_cron(out, errors), lambda: scan_editors(out),
                 lambda: scan_risky_folders(out), lambda: scan_processes(out)):
        try:
            step()
        except Exception as e:  # one broken check shouldn't hide the others
            errors.append(f"{type(e).__name__}: {e}")
    return out, inventory, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["scan", "clean"])
    ap.add_argument("--backup", default=os.path.join(HOME, "Library/Application Support/RepoGuard/quarantine"))
    ap.add_argument("--ids", nargs="*", default=[])
    a = ap.parse_args()
    info = {"host": os.uname().nodename, "root": IS_ROOT, "python": sys.version.split()[0]}
    findings, inventory, errors = scan()
    if a.mode == "scan":
        print(json.dumps({"info": info, "findings": findings, "inventory": inventory, "errors": errors[:50]}))
        return
    fx = Fixer(a.backup)
    by_id = {f["id"]: f for f in findings}
    inv = {i["id"]: i for i in inventory}
    # Any startup item can be turned off from the list, not just flagged ones.
    for i in inventory:
        if i["id"] not in by_id:
            kind = "login" if i["where"] == "login item" else "launchd"
            by_id[i["id"]] = dict(id=i["id"], kind=kind, path=i["plist"] or i["program"], label=i["label"], root=i["root"], item=i["id"])
    results = []
    for fid in a.ids:
        f = by_id.get(fid)
        if not f:
            results.append({"id": fid, "ok": True, "result": "no longer found"})
            continue
        try:
            results.append({"id": fid, "ok": True, "path": f["path"], "result": fx.fix(f, inv)})
        except NeedsAdmin:
            results.append({"id": fid, "ok": False, "path": f["path"], "result": "needs your administrator password", "needs_admin": True})
        except cleaner.Manual as e:
            results.append({"id": fid, "ok": False, "path": f["path"], "result": f"left unchanged: {e}"})
        except Exception as e:
            results.append({"id": fid, "ok": False, "path": f["path"], "result": f"failed: {e}"})
    import shutil
    shutil.rmtree(cleaner.TMPDIR, ignore_errors=True)
    after, inventory, errors = scan()
    print(json.dumps({"info": info, "results": results, "backup": fx.backup_dir, "findings": after, "inventory": inventory, "errors": errors[:50]}))


if __name__ == "__main__":
    main()
