"""RepoGuard server agent. Runs on a Linux server (Python 3.7+), sent over SSH by the Mac app.

  server_agent.py scan  --roots DIR [DIR ...]
  server_agent.py clean --roots DIR [DIR ...] --ids ID [ID ...]

scan looks at:
  * files under the roots (web/app folders) with the same rules as the Mac scanner;
    git folders are skipped, git history is never read or changed
  * temp folders (/tmp, /var/tmp, /dev/shm) for scripts and binaries dropped there
  * things that start automatically: cron, systemd units, rc.local, shell startup files,
    /etc/profile.d, /etc/ld.so.preload, pm2 process lists
  * running processes started from temp folders, from deleted files, or matching known malware
  * SSH authorized_keys changed recently (shown for review, never removed automatically)

clean fixes only the findings whose ids it is given, after re-checking each one. Every file
it changes is copied to /var/backups/repoguard/<time>/ (read-only, .quarantined suffix).
Prints JSON.
"""
import argparse, datetime, hashlib, importlib.util, json, os, pwd, re, shutil, signal, stat, subprocess, sys, time

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
TEMP_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]
SKIP_DIRS = set(RULES.skip_dirs) | {".git", "proc", "sys", ".npm", ".nvm", ".cache", ".cargo", ".rustup", "go"}
RECENT = time.time() - 30 * 86400

# Strong signs: these are cleaned by the one-click button.
BAD_CMD = re.compile(
    r"(?:curl|wget)[^|;&]*\|\s*(?:ba|z|da)?sh\b"          # download piped into a shell
    r"|base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh"       # decoded script into a shell
    r"|\bnode\s+\S*(?:/|\b)init\b"                        # the worm's loader
    r"|\.orc\b|fa-brand-400|fa-solid-400\.woff2"          # its payload names
    r"|/dev/shm/|/tmp/\.|/var/tmp/\."                     # hidden files in temp folders
    r"|xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|stratum\+tcp"
    r"|ethplore[r]|eth_getTransa[c]tionByHash"
    r"|jsonkeeper\.com|npoint\.io", re.I)
# Weaker signs: shown for review.
ODD_CMD = re.compile(r"\b(?:nohup|setsid)\b.*\s(?:/tmp|/var/tmp)/|python3?\s+-c\s+['\"].*(?:urllib|socket)|\bnc\s+-e\b|/bin/sh\s+-i", re.I)
MINERS = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|\bkthreaddk\b", re.I)


def finding(kind, path, detail, severity, fix, **extra):
    raw = f"{kind}|{path}|{extra.get('line', '')}|{extra.get('pid', '')}|{extra.get('cmd', '')}"
    fid = hashlib.sha1(raw.encode()).hexdigest()[:16]
    return dict(id=fid, kind=kind, path=path, detail=detail, severity=severity, fix=fix, **extra)


def read(path, limit=2_000_000):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


# ---------------------------------------------------------------- files

def scan_files(roots, out, errors):
    seen = set()
    for top in roots:
        if not os.path.isdir(top):
            continue
        for cur, dirs, names in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and os.path.join(cur, d) != HERE and not engine.QUARANTINE.search(d)
                       and not os.path.join(cur, d).startswith(("/proc", "/sys", "/var/backups/repoguard"))]
            for n in names:
                p = os.path.join(cur, n)
                if p in seen:
                    continue
                seen.add(p)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                data = read(p, RULES.max + 1) if st.st_size <= RULES.max else None
                hits = [h for h in RULES.check(p, data) if h[1] == "block"]
                if hits and not cleaner.VENDORED.search(p):
                    out.append(finding("file", p, ", ".join(sorted({h[2] for h in hits})), "block",
                                       "cut out the injected code (delete if the whole file is malware)",
                                       rules=[list(h) for h in hits]))


def scan_temp(out):
    for top in TEMP_DIRS:
        if not os.path.isdir(top):
            continue
        for cur, dirs, names in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith(("systemd-private", "snap-private")) and os.path.join(cur, d) != HERE]
            for n in names:
                p = os.path.join(cur, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > 20_000_000:
                    continue
                head = read(p, 8000) or b""
                is_elf = head.startswith(b"\x7fELF")
                is_script = n.endswith((".js", ".sh", ".py", ".pl")) or head.startswith(b"#!")
                data = read(p, RULES.max) if is_script else None
                hits = [h for h in RULES.check(p, data) if h[1] == "block"] if data is not None else []
                text = (data or b"").decode("utf8", "replace")
                if hits or BAD_CMD.search(text):
                    out.append(finding("tempfile", p, "malware script in a temp folder", "block", "delete the file"))
                elif is_elf and (st.st_mode & 0o111):
                    out.append(finding("tempfile", p, "program file in a temp folder", "review", "delete the file"))


# ---------------------------------------------------------------- autostart

def home_dirs():
    homes = set()
    for pw in pwd.getpwall():
        if pw.pw_dir and os.path.isdir(pw.pw_dir) and pw.pw_dir not in ("/", "/nonexistent"):
            homes.add(pw.pw_dir)
    return sorted(homes)


def line_files():
    """Files where each line can start something: cron tables, rc and shell startup files."""
    files = ["/etc/crontab", "/etc/rc.local", "/etc/profile", "/etc/bash.bashrc", "/etc/environment"]
    for d in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
              "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/profile.d"]:
        if os.path.isdir(d):
            files += [os.path.join(d, n) for n in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, n))]
    for h in home_dirs():
        files += [os.path.join(h, n) for n in (".bashrc", ".bash_profile", ".profile", ".zshrc", ".bash_login", ".bash_logout")]
    return [f for f in files if os.path.isfile(f)]


def scan_autostart(out, errors):
    for f in line_files():
        data = read(f)
        if data is None:
            errors.append(f"can't read {f} (needs root)")
            continue
        for i, line in enumerate(data.decode("utf8", "replace").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if BAD_CMD.search(s):
                out.append(finding("autostart", f, f"line {i}: {s[:200]}", "block", "remove this line", line=s))
            elif ODD_CMD.search(s):
                out.append(finding("autostart", f, f"line {i}: {s[:200]}", "review", "remove this line", line=s))
    # rootkit-style preload
    pre = read("/etc/ld.so.preload")
    if pre and pre.strip():
        for s in pre.decode("utf8", "replace").split():
            out.append(finding("preload", "/etc/ld.so.preload", f"library loaded into every program: {s}", "block",
                               "remove the entry and quarantine the library", line=s))
    # systemd units
    unit_dirs = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"]
    unit_dirs += [os.path.join(h, ".config/systemd/user") for h in home_dirs()]
    for d in unit_dirs:
        if not os.path.isdir(d):
            continue
        for cur, dirs, names in os.walk(d):
            for n in names:
                if not n.endswith((".service", ".timer")):
                    continue
                p = os.path.join(cur, n)
                if os.path.islink(p):
                    continue
                text = (read(p) or b"").decode("utf8", "replace")
                execs = " ".join(l.split("=", 1)[1] for l in text.splitlines() if l.strip().startswith(("ExecStart", "ExecStartPre", "ExecStartPost")) and "=" in l)
                if BAD_CMD.search(execs) or re.search(r"(?:^|\s)(?:/tmp|/var/tmp|/dev/shm)/", execs):
                    out.append(finding("service", p, f"{n} runs: {execs[:200]}", "block", "stop, disable and quarantine the service", unit=n))
                elif ODD_CMD.search(execs):
                    out.append(finding("service", p, f"{n} runs: {execs[:200]}", "review", "stop, disable and quarantine the service", unit=n))
    # pm2 saved process lists
    for h in home_dirs():
        dump = os.path.join(h, ".pm2", "dump.pm2")
        data = read(dump)
        if not data:
            continue
        try:
            procs = json.loads(data)
        except ValueError:
            continue
        for p in procs:
            script = str(p.get("pm_exec_path", "")) + " " + " ".join(map(str, p.get("args", []) or []))
            if BAD_CMD.search(script) or re.search(r"(?:^|/)init$|\.orc$|^/tmp/|^/dev/shm/", str(p.get("pm_exec_path", ""))):
                out.append(finding("pm2", dump, f"pm2 app '{p.get('name')}' runs {script.strip()[:200]}", "block",
                                   "delete it from pm2 and save", name=p.get("name"), owner=os.path.basename(h)))
    # SSH keys: never removed automatically
    for h in home_dirs():
        ak = os.path.join(h, ".ssh", "authorized_keys")
        try:
            st = os.stat(ak)
        except OSError:
            continue
        if st.st_mtime > RECENT:
            n = len([l for l in (read(ak) or b"").decode("utf8", "replace").splitlines() if l.strip() and not l.startswith("#")])
            when = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            out.append(finding("sshkeys", ak, f"{n} login keys, changed {when}. Check every key is yours.", "review", "review by hand"))


# ---------------------------------------------------------------- processes

def scan_processes(out):
    me = os.getpid()
    for pid in [int(x) for x in os.listdir("/proc") if x.isdigit()]:
        if pid == me:
            continue
        try:
            cmd = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf8", "replace").strip()
        except OSError:
            continue
        if not cmd:
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        try:
            user = pwd.getpwuid(os.stat(f"/proc/{pid}").st_uid).pw_name
        except (OSError, KeyError):
            user = "?"
        why = None
        if MINERS.search(cmd) or MINERS.search(exe):
            why = "known crypto-miner"
        elif BAD_CMD.search(cmd):
            why = "runs malware"
        elif exe.endswith(" (deleted)") and re.match(r"(?:/tmp|/var/tmp|/dev/shm)/", exe):
            why = "program deleted itself from a temp folder"
        elif re.match(r"(?:/tmp|/var/tmp|/dev/shm)/", exe):
            why = "program running from a temp folder"
        elif re.search(r"\bnode\s+(?:/tmp|/var/tmp)/tmp\w+\.js\b", cmd):
            why = "node running a script dropped in /tmp (blockchain loader)"
        if why:
            out.append(finding("process", exe or cmd.split()[0], f"PID {pid} ({user}): {why}: {cmd[:200]}", "block",
                               "stop the process and quarantine its program file", pid=pid, cmd=cmd[:500]))


# ---------------------------------------------------------------- clean

class Fixer:
    def __init__(self):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        base = "/var/backups/repoguard" if IS_ROOT else os.path.expanduser("~/.repoguard-backups")
        self.backup_dir = os.path.join(base, stamp)
        cleaner.BACKUP = self.backup_dir
        cleaner.TMPDIR = os.path.join(base, ".tmp")
        os.makedirs(cleaner.TMPDIR, exist_ok=True)
        cleaner.NODE = cleaner.find_node()
        self.done, self.failed = [], []

    def backup(self, path):
        data = read(path, 50_000_000)
        if data is not None:
            return cleaner.backup(path, data, "")

    def remove_line(self, path, line):
        data = read(path)
        if data is None:
            raise RuntimeError("can't read the file (needs root?)")
        text = data.decode("utf8", "replace")
        lines = text.split("\n")
        keep = [l for l in lines if l.strip() != line]
        if len(keep) == len(lines):
            return "already gone"
        self.backup(path)
        st = os.stat(path)
        tmp = path + ".rg-tmp"
        with open(tmp, "w") as fh:
            fh.write("\n".join(keep))
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.chown(tmp, st.st_uid, st.st_gid) if IS_ROOT else None
        os.replace(tmp, path)
        if "/var/spool/cron" in path or path == "/etc/crontab" or path.startswith("/etc/cron.d"):
            subprocess.run(["sh", "-c", "command -v systemctl >/dev/null && (systemctl reload cron || systemctl reload crond) >/dev/null 2>&1; true"])
        return "removed the line"

    def quarantine_file(self, path):
        if not os.path.lexists(path):
            return "already gone"
        self.backup(path)
        os.unlink(path)
        return "deleted (backed up)"

    def fix(self, f):
        k = f["kind"]
        if k == "file":
            data = read(f["path"], RULES.max + 1)
            if data is None:
                return "already gone"
            hits = [h for h in RULES.check(f["path"], data) if h[1] == "block"]
            if not hits:
                return "already clean"
            new, notes = cleaner.clean_text(f["path"], data, hits)  # raises cleaner.Manual
            self.backup(f["path"])
            if new is None:
                os.unlink(f["path"])
                return "deleted: " + "; ".join(notes)
            st = os.stat(f["path"])
            tmp = f["path"] + ".rg-tmp"
            with open(tmp, "wb") as fh:
                fh.write(new)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            os.chown(tmp, st.st_uid, st.st_gid) if IS_ROOT else None
            os.replace(tmp, f["path"])
            return "cleaned: " + "; ".join(notes)
        if k == "tempfile":
            return self.quarantine_file(f["path"])
        if k == "autostart":
            return self.remove_line(f["path"], f["line"])
        if k == "preload":
            msg = self.remove_line(f["path"], f["line"])
            if os.path.isfile(f["line"]):
                self.quarantine_file(f["line"])
            return msg + "; library quarantined"
        if k == "service":
            unit = f["unit"]
            user_unit = "/.config/systemd/user/" in f["path"]
            if not user_unit:
                subprocess.run(["systemctl", "disable", "--now", unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            msg = self.quarantine_file(f["path"])
            if not user_unit:
                subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "service stopped, disabled and " + msg
        if k == "pm2":
            owner = f.get("owner") or ""
            cmd = f"pm2 delete {json.dumps(str(f['name']))} && pm2 save --force"
            if IS_ROOT and owner and owner != "root":
                r = subprocess.run(["su", "-", owner, "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            else:
                r = subprocess.run(["sh", "-lc", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if r.returncode:
                raise RuntimeError(r.stdout.decode("utf8", "replace")[-200:])
            return "removed from pm2"
        if k == "process":
            pid = int(f["pid"])
            try:
                now = open(f"/proc/{pid}/cmdline", "rb").read().replace(b"\0", b" ").decode("utf8", "replace").strip()
            except OSError:
                return "already stopped"
            if now[:500] != f["cmd"]:
                return "PID now belongs to another program; left alone"
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = ""
            os.kill(pid, signal.SIGKILL)
            extra = ""
            if exe and not exe.endswith(" (deleted)") and re.match(r"(?:/tmp|/var/tmp|/dev/shm)/", exe):
                extra = "; program file " + self.quarantine_file(exe)
            return "stopped" + extra
        raise RuntimeError("review this one by hand")


# ---------------------------------------------------------------- main

def scan(roots):
    out, errors = [], []
    scan_files(roots, out, errors)
    scan_temp(out)
    scan_autostart(out, errors)
    scan_processes(out)
    return out, errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["scan", "clean"])
    ap.add_argument("--roots", nargs="*", default=[])
    ap.add_argument("--ids", nargs="*", default=[])
    a = ap.parse_args()
    info = {"host": os.uname().nodename, "root": IS_ROOT, "python": sys.version.split()[0]}
    findings, errors = scan(a.roots)
    if a.mode == "scan":
        print(json.dumps({"info": info, "findings": findings, "errors": errors[:50]}))
        return
    fx = Fixer()
    by_id = {f["id"]: f for f in findings}
    results = []
    for fid in a.ids:
        f = by_id.get(fid)
        if not f:
            results.append({"id": fid, "ok": True, "result": "no longer found"})
            continue
        try:
            results.append({"id": fid, "ok": True, "path": f["path"], "result": fx.fix(f)})
        except cleaner.Manual as e:
            results.append({"id": fid, "ok": False, "path": f["path"], "result": f"left unchanged: {e}"})
        except Exception as e:  # report and continue with the rest
            results.append({"id": fid, "ok": False, "path": f["path"], "result": f"failed: {e}"})
    shutil.rmtree(cleaner.TMPDIR, ignore_errors=True)
    after, errors = scan(a.roots)
    print(json.dumps({"info": info, "results": results, "backup": fx.backup_dir, "findings": after, "errors": errors[:50]}))


if __name__ == "__main__":
    main()
