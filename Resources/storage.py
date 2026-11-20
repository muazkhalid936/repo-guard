"""RepoGuard Cleanup: find space a developer can get back, clean it, and archive old projects to GitHub.

  storage.py analyze --watch DIR [--watch DIR] --state STATE.json [--stale-days 60]
  storage.py clean   --items ITEMS.json
  storage.py archive --project DIR --state STATE.json [--no-notes] [--no-push] [--create-repo]
                     [--remove trash|delete|keep] [--accept-ignored]

Every mode prints one JSON object per line: {"type": "progress"|"step"|"result", ...}, so the app can show
live progress. Nothing is deleted by analyze. clean only deletes paths that pass the same safety checks
again. archive refuses projects with malware findings, saves .env files to Apple Notes, commits unsaved
work to a new branch, pushes every branch without force, checks GitHub really has every commit, and only
then removes the folder.
"""
import argparse, datetime, glob, hashlib, html, json, os, re, shutil, subprocess, sys, time

HOME = os.path.expanduser("~")
DAY = 86400
# Apps start with a minimal PATH (/usr/bin:/bin...), so tools from Homebrew and Docker wouldn't be found.
os.environ["PATH"] = ":".join([os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"), "/opt/homebrew/bin", "/usr/local/bin",
                               "/Applications/Docker.app/Contents/Resources/bin"])

# Folders that are always safe to delete: tools download or rebuild them on demand.
CACHES = [
    # (id, category, title, path, detail, selected by default)
    ("xcode-derived", "Xcode", "Xcode DerivedData", "~/Library/Developer/Xcode/DerivedData", "Build products and indexes. Xcode rebuilds them.", True),
    ("xcode-devicesupport", "Xcode", "iOS device support files", "~/Library/Developer/Xcode/iOS DeviceSupport", "Symbols copied from phones you plugged in. Copied again next time.", True),
    ("xcode-sim-caches", "Xcode", "Simulator caches", "~/Library/Developer/CoreSimulator/Caches", "Rebuilt automatically.", True),
    ("xcode-archives", "Xcode", "Xcode archives", "~/Library/Developer/Xcode/Archives", "Old app builds you exported. Keep them if you need to symbolicate old crash reports.", False),
    ("npm", "Package caches", "npm cache", "~/.npm/_cacache", "Downloaded packages. npm downloads them again when needed.", True),
    ("yarn", "Package caches", "Yarn cache", "~/Library/Caches/Yarn", "Downloaded packages.", True),
    ("pnpm", "Package caches", "pnpm store", "~/Library/pnpm/store", "Shared package store. Projects re-link packages on the next install.", True),
    ("bun", "Package caches", "Bun cache", "~/.bun/install/cache", "Downloaded packages.", True),
    ("pip", "Package caches", "pip cache", "~/Library/Caches/pip", "Downloaded Python packages.", True),
    ("uv", "Package caches", "uv cache", "~/.cache/uv", "Python packages and tools. Tools started with uvx re-download on next start; close running ones first.", False),
    ("brew", "Package caches", "Homebrew downloads", "~/Library/Caches/Homebrew", "Installer downloads, not installed apps.", True),
    ("cocoapods", "Package caches", "CocoaPods cache", "~/Library/Caches/CocoaPods", "Downloaded pods.", True),
    ("gradle", "Package caches", "Gradle caches", "~/.gradle/caches", "Android/Java dependencies and build cache. The next build is slower.", False),
    ("go-build", "Package caches", "Go build cache", "~/Library/Caches/go-build", "Compiled Go packages.", True),
    ("cargo", "Package caches", "Cargo registry cache", "~/.cargo/registry/cache", "Downloaded Rust crates.", True),
    ("logs", "System", "User logs", "~/Library/Logs", "Old app logs and crash reports. RepoGuard's own log is kept.", True),
]
# Editor caches: safe to delete while the editor is closed. (id, title, path, app bundle name, detail, default)
AS = "~/Library/Application Support/"
EDITOR_CACHES = [
    ("cursor-cached", "Cursor cached data", AS + "Cursor/CachedData", "Cursor", "Compiled code caches. Rebuilt when Cursor starts.", True),
    ("cursor-vsix", "Cursor extension downloads", AS + "Cursor/CachedExtensionVSIXs", "Cursor", "Installer copies of extensions you already have.", True),
    ("cursor-logs", "Cursor logs", AS + "Cursor/logs", "Cursor", "Old log files.", True),
    ("cursor-snapshots", "Cursor agent checkpoints", AS + "Cursor/snapshots", "Cursor", "Copies Cursor keeps so you can undo agent edits. Old checkpoints can't be restored after this.", False),
    ("code-cached", "VS Code cached data", AS + "Code/CachedData", "Visual Studio Code", "Compiled code caches. Rebuilt when VS Code starts.", True),
    ("code-vsix", "VS Code extension downloads", AS + "Code/CachedExtensionVSIXs", "Visual Studio Code", "Installer copies of extensions you already have.", True),
    ("code-logs", "VS Code logs", AS + "Code/logs", "Visual Studio Code", "Old log files.", True),
    ("antigravity-cached", "Antigravity cached data", AS + "Antigravity/CachedData", "Antigravity", "Compiled code caches.", True),
    ("trae-cached", "Trae cached data", AS + "Trae/CachedData", "Trae", "Compiled code caches.", True),
    ("windsurf-cached", "Windsurf cached data", AS + "Windsurf/CachedData", "Windsurf", "Compiled code caches.", True),
]
# Single files that are only backups. (id, title, path, app, detail)
BACKUP_FILES = [
    ("cursor-db-backup", "Cursor chat database backup", AS + "Cursor/User/globalStorage/state.vscdb.backup", "Cursor",
     "A spare copy of Cursor's chat history database. The real one (state.vscdb) is kept."),
    ("code-db-backup", "VS Code state backup", AS + "Code/User/globalStorage/state.vscdb.backup", "Visual Studio Code", "A spare copy of VS Code's state database."),
]
DEPENDENCY_DIRS = {"node_modules", "Pods", ".venv", "venv"}

# Names of folders inside projects that can be rebuilt. Only deleted when git ignores them (or node_modules).
REBUILDABLE = {"node_modules", ".next", ".nuxt", ".turbo", ".expo", ".parcel-cache", ".svelte-kit", ".angular", "dist", "build",
               "out", "target", "Pods", ".gradle", "DerivedData", "coverage", "__pycache__", ".pytest_cache", ".venv", "venv", ".dart_tool"}
JUNK_IGNORED = REBUILDABLE | {".DS_Store", ".cache", ".idea", ".vscode", "tmp", ".eslintcache", "npm-debug.log", "yarn-error.log", "next-env.d.ts"}
ENV_NAME = re.compile(r"^\.env(?:\.[\w.-]+)?$")
ENV_EXAMPLE = re.compile(r"\.(?:example|sample|template|dist|defaults?)$", re.I)
PROJECT_MARKERS = ("package.json", "pubspec.yaml", "Podfile", "build.gradle", "settings.gradle", "Cargo.toml", "go.mod",
                   "pyproject.toml", "requirements.txt", "composer.json", "Gemfile", "Package.swift")


def emit(**kw):
    sys.stdout.write(json.dumps(kw) + "\n")
    sys.stdout.flush()


def run(args, cwd=None, timeout=120, input=None):
    try:
        # GIT_OPTIONAL_LOCKS=0: `git status` must not rewrite .git/index, or every project looks just used.
        env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
        r = subprocess.run(args, cwd=cwd, input=input, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return r.returncode, r.stdout.decode("utf8", "replace"), r.stderr.decode("utf8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)


def git(repo, *args, timeout=300):
    # Hooks and fsmonitor off: a repo's own config must never run code here (the worm used this).
    return run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
                "-c", "credential.interactive=never", *args], cwd=repo, timeout=timeout)


def du(path):
    if not os.path.lexists(path):
        return 0
    rc, out, _ = run(["/usr/bin/du", "-sk", path], timeout=600)
    try:
        return int(out.split()[0]) * 1024
    except (IndexError, ValueError):
        return 0


def item_id(*parts):
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:14]


# ---------------------------------------------------------------- analyze

def simulator_items():
    rc, out, _ = run(["xcrun", "simctl", "list", "devices", "-j"], timeout=30)
    if rc:
        return []
    try:
        devs = json.loads(out)["devices"]
    except (ValueError, KeyError):
        return []
    items = []
    base = os.path.join(HOME, "Library/Developer/CoreSimulator/Devices")
    for runtime, lst in devs.items():
        for d in lst:
            path = os.path.join(base, d["udid"])
            if not os.path.isdir(path):
                continue
            unavailable = not d.get("isAvailable", True)
            name = f"{d['name']} ({runtime.split('.')[-1].replace('-', ' ', 1).replace('-', '.')})"
            items.append(dict(path=path, name=name, unavailable=unavailable, udid=d["udid"], state=d.get("state", "")))
    return items


def android_items():
    out = []
    sdk = os.path.join(HOME, "Library/Android/sdk/system-images")
    for p in sorted(glob.glob(os.path.join(sdk, "*/*/*"))):
        if os.path.isdir(p):
            out.append(p)
    avd = os.path.join(HOME, ".android/avd")
    return out, avd


def vscode_opened():
    """folder path -> last time an editor opened it (VS Code, Cursor, Windsurf keep per-folder storage)."""
    seen = {}
    for ed in ("Code", "Code - Insiders", "Cursor", "Windsurf", "VSCodium"):
        for ws in glob.glob(os.path.join(HOME, "Library/Application Support", ed, "User/workspaceStorage/*/workspace.json")):
            try:
                folder = json.load(open(ws)).get("folder", "")
            except (OSError, ValueError):
                continue
            if not folder.startswith("file://"):
                continue
            from urllib.parse import unquote
            path = os.path.realpath(unquote(folder[7:]))
            d = os.path.dirname(ws)
            try:
                t = max(os.stat(os.path.join(d, n)).st_mtime for n in os.listdir(d))
            except (OSError, ValueError):
                continue
            seen[path] = max(seen.get(path, 0), t)
    return seen


REAL_ACTION = re.compile(r"^(?:commit|checkout|merge|pull|rebase|cherry-pick|revert|am)\b")
TOOL_MESSAGE = re.compile(r"malware|repoguard|cleanup commit|restore", re.I)


def last_real_git_action(path):
    """Time of the last commit/checkout/merge someone did by hand. Resets and cleanup commits made while
    removing malware are skipped, so they don't make an old project look recently used."""
    data = b""
    try:
        with open(os.path.join(path, ".git/logs/HEAD"), "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 200_000))
            data = fh.read()
    except OSError:
        return 0
    for line in reversed(data.decode("utf8", "replace").splitlines()):
        head, _, msg = line.partition("\t")
        m = re.search(r"> (\d+) [+-]\d{4}$", head)
        if m and REAL_ACTION.match(msg) and not TOOL_MESSAGE.search(msg):
            return int(m.group(1))
    return 0


_touched = None


def cleaned_by_repoguard():
    """Files RepoGuard's malware cleaner changed (it keeps a backup of each one)."""
    global _touched
    if _touched is None:
        _touched = set()
        q = os.path.join(HOME, "Library/Application Support/RepoGuard/quarantine")
        for cur, dirs, names in os.walk(q):
            for n in names:
                if n.endswith(".quarantined"):
                    rel = os.path.relpath(os.path.join(cur, n), q)
                    parts = rel.split(os.sep, 1)
                    if len(parts) == 2:  # <stamp>/<original absolute path>[@label].quarantined
                        _touched.add("/" + re.sub(r"(?:@[^/]*)?\.quarantined$", "", parts[1]))
    return _touched


def last_activity(path, opened):
    """Newest of: an editor opening the folder, a commit or checkout, and an edited source file.
    .git/index and fetches don't count: background tools (GitHub Desktop, watchers) touch those."""
    times = [opened.get(os.path.realpath(path), 0), last_real_git_action(path)]
    touched = cleaned_by_repoguard()
    seen = 0
    for cur, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in REBUILDABLE and d != ".git" and not d.startswith(".")]
        for n in names:
            if n == ".DS_Store" or os.path.join(cur, n) in touched:
                continue
            try:
                times.append(os.lstat(os.path.join(cur, n)).st_mtime)
            except OSError:
                pass
            seen += 1
        if seen > 30000:
            break
    now = time.time()
    times = [t for t in times if t <= now + 60]
    return max(times) if times else 0


def env_files(path):
    found = []
    for cur, dirs, names in os.walk(path):
        dirs[:] = [d for d in dirs if d not in REBUILDABLE and d != ".git" and not d.startswith(".") or d in (".config",)]
        if cur.count(os.sep) - path.count(os.sep) > 4:
            dirs[:] = []
        for n in names:
            if ENV_NAME.match(n) and not ENV_EXAMPLE.search(n):
                p = os.path.join(cur, n)
                if os.path.isfile(p) and os.path.getsize(p) < 512_000:
                    found.append(p)
    return sorted(found)


def rebuildable_dirs(path, is_git):
    out = []
    for cur, dirs, names in os.walk(path):
        depth = cur.count(os.sep) - path.count(os.sep)
        keep = []
        for d in dirs:
            if d == ".git":
                continue
            full = os.path.join(cur, d)
            if d in REBUILDABLE:
                if d == "node_modules" or (is_git and git(path, "check-ignore", "-q", os.path.relpath(full, path))[0] == 0):
                    out.append(full)
                    continue
            if depth < 3 and not d.startswith("."):
                keep.append(d)
        dirs[:] = keep
    return out


def git_state(path):
    st = dict(git=os.path.isdir(os.path.join(path, ".git")), remote="", branches=0, unpushed=0, no_upstream=[], dirty=0, stashes=0,
              last_commit=0, current="")
    if not st["git"]:
        return st
    rc, out, _ = git(path, "remote", "get-url", "origin")
    if rc:
        rc, out, _ = git(path, "remote")
        name = out.split()[0] if out.split() else ""
        if name:
            rc, out, _ = git(path, "remote", "get-url", name)
    st["remote"] = out.strip() if rc == 0 else ""
    rc, out, _ = git(path, "for-each-ref", "--format=%(refname:short)|%(upstream:short)|%(upstream:track)", "refs/heads")
    for line in out.splitlines():
        b, up, track = (line.split("|") + ["", ""])[:3]
        st["branches"] += 1
        if not up:
            st["no_upstream"].append(b)
        else:
            m = re.search(r"ahead (\d+)", track)
            if m:
                st["unpushed"] += int(m.group(1))
    rc, out, _ = git(path, "status", "--porcelain", "--untracked-files=normal")
    st["dirty"] = len([l for l in out.splitlines() if l.strip()])
    rc, out, _ = git(path, "stash", "list")
    st["stashes"] = len([l for l in out.splitlines() if l.strip()])
    rc, out, _ = git(path, "log", "-1", "--format=%ct")
    st["last_commit"] = int(out.strip() or 0) if rc == 0 else 0
    rc, out, _ = git(path, "branch", "--show-current")
    st["current"] = out.strip()
    return st


def find_projects(watch, state):
    repos = set(state.get("refs", {}).keys())
    for w in watch:
        for cur, dirs, names in os.walk(w):
            depth = cur.count(os.sep) - w.count(os.sep)
            if ".git" in dirs or ".git" in names:
                repos.add(cur)
                dirs[:] = []
                continue
            if depth >= 1 and any(m in names for m in PROJECT_MARKERS):
                repos.add(cur)
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in REBUILDABLE and not d.startswith(".")] if depth < 3 else []
    # Drop folders inside other projects (monorepo packages).
    out = sorted(repos)
    return [p for p in out if os.path.isdir(p) and not any(p != q and p.startswith(q + "/") for q in out)]


def analyze(a):
    state = load_state(a.state)
    infected = {f["root"] for f in state.get("findings", {}).values()}
    now = time.time()
    items = []
    total_steps = len(CACHES) + 4
    step = 0

    def progress(title):
        nonlocal step
        step += 1
        emit(type="progress", title=title, pct=min(99, int(step * 100 / max(1, total_steps))))

    for cid, cat, title, path, detail, default in CACHES:
        progress(f"Measuring {title}")
        p = os.path.expanduser(path)
        size = du(p)
        if cid == "logs":
            size -= du(os.path.join(p, "RepoGuard.log"))
        if size > 1_000_000:
            items.append(dict(id=cid, category=cat, title=title, path=p, size=size, detail=detail, selected=default, kind="contents"))

    progress("Checking editors")
    for cid, title, path, app, detail, default in EDITOR_CACHES:
        p = os.path.expanduser(path)
        size = du(p)
        if size > 50_000_000:
            items.append(dict(id=cid, category="Editors", title=title, path=p, size=size, detail=detail + f" Quit {app} first.",
                              selected=default, kind="editor", app=app))
    for cid, title, path, app, detail in BACKUP_FILES:
        p = os.path.expanduser(path)
        size = du(p)
        if size > 50_000_000:
            items.append(dict(id=cid, category="Editors", title=title, path=p, size=size, detail=detail + f" Quit {app} first.",
                              selected=False, kind="backupfile", app=app))

    progress("Checking simulator runtimes")
    rc, out, _ = run(["xcrun", "simctl", "runtime", "list", "-j"], timeout=60)
    if rc == 0:
        try:
            runtimes = json.loads(out)
        except ValueError:
            runtimes = {}
        for rid, r in runtimes.items():
            size = int(r.get("sizeBytes") or 0)
            if size < 500_000_000 or not r.get("deletable"):
                continue
            last = r.get("lastUsedAt") or ""
            items.append(dict(id=item_id("runtime", rid), category="Simulators", title=f"iOS {r.get('version', '?')} simulator runtime",
                              path=r.get("path", ""), size=size, udid=rid,
                              detail=f"The iOS system the simulators run. Last used {last[:10] or 'never'}. Download it again from Xcode > Settings > Components.",
                              selected=False, kind="runtime"))

    progress("Checking simulators")
    sims = simulator_items()
    total_steps += len(sims) // 4
    for s in sims:
        size = du(s["path"])
        if size < 50_000_000:
            continue
        items.append(dict(id=item_id("sim", s["udid"]), category="Simulators",
                          title=s["name"] + (" (unavailable)" if s["unavailable"] else ""), path=s["path"], size=size,
                          detail=("Xcode doesn't have this simulator's iOS version right now (it can come back after Xcode downloads it). Deleting removes its apps and data."
                                  if s["unavailable"] else "Apps and data inside this simulator. Deleting removes them for good."),
                          # Never pre-selected: simulators hold the person's apps and data, and after an Xcode reinstall
                          # every simulator reads as unavailable, which used to tick all of them.
                          selected=False, kind="simulator", udid=s["udid"]))

    progress("Checking Android SDK")
    images, avd = android_items()
    for p in images:
        size = du(p)
        if size > 200_000_000:
            name = " ".join(p.split("/")[-3:])
            items.append(dict(id=item_id("android", p), category="Android", title=f"Emulator image {name}", path=p, size=size,
                              detail="Android Studio downloads it again if an emulator needs it.", selected=False, kind="path"))
    if os.path.isdir(avd):
        for p in sorted(glob.glob(os.path.join(avd, "*.avd"))):
            size = du(p)
            if size > 200_000_000:
                items.append(dict(id=item_id("avd", p), category="Android", title=f"Emulator {os.path.basename(p)[:-4]}", path=p, size=size,
                                  detail="Emulator disk with its apps and data. Recreate it in Android Studio if needed.", selected=False, kind="avd"))

    progress("Checking Docker")
    rc, out, _ = run(["docker", "system", "df", "--format", "{{json .}}"], timeout=30)
    if rc == 0:
        def amount(s):
            m = re.match(r"([\d.]+)\s*([kMGT]?B)", s or "")
            return int(float(m.group(1)) * {"B": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(2)]) if m else 0
        rec = {}
        for line in out.splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            rec[d.get("Type")] = (amount(d.get("Reclaimable")), amount(d.get("Size")))
        bc = rec.get("Build Cache", (0, 0))[0]
        if bc > 100_000_000:
            items.append(dict(id="docker-build", category="Docker", title="Docker build cache", path="", size=bc,
                              detail="Layers kept to speed up `docker build`. The next build of each image is slower.", selected=True, kind="docker", what="builder"))
        img = min(*rec.get("Images", (0, 0)))
        if img > 100_000_000:
            items.append(dict(id="docker-images", category="Docker", title="Docker images no container uses", path="", size=img,
                              detail="Pulled or built images without a container. They're downloaded or built again when needed. Volumes (databases) are kept.",
                              selected=False, kind="docker", what="images"))
        stopped = rec.get("Containers", (0, 0))[0]
        if stopped > 50_000_000:
            items.append(dict(id="docker-containers", category="Docker", title="Stopped Docker containers", path="", size=stopped,
                              detail="Containers that aren't running.", selected=False, kind="docker", what="containers"))

    progress("Looking at your projects")
    opened = vscode_opened()
    projects = []
    plist = find_projects(a.watch, state)
    total_steps += len(plist)
    for p in plist:
        progress(f"Measuring {os.path.basename(p)}")
        last = last_activity(p, opened)
        idle = int((now - last) / DAY) if last else 9999
        g = git_state(p)
        rebuild = rebuildable_dirs(p, g["git"])
        rebuild_size = sum(du(d) for d in rebuild)
        size = du(p)
        envs = env_files(p)
        proj = dict(path=p, name=os.path.basename(p), parent=os.path.basename(os.path.dirname(p)), size=size, rebuild_size=rebuild_size,
                    idle_days=idle, last_opened=datetime.datetime.fromtimestamp(last).strftime("%Y-%m-%d") if last else "",
                    envs=[os.path.relpath(e, p) for e in envs], infected=p in infected, **g)
        projects.append(proj)
        if idle < a.stale_days:
            build = [d for d in rebuild if os.path.basename(d) not in DEPENDENCY_DIRS]
            bsize = sum(du(d) for d in build)
            if bsize > 300_000_000:
                items.append(dict(id=item_id("build", p), category="Build output", title=f"{proj['parent']}/{proj['name']}",
                                  path=p, size=bsize, paths=build,
                                  detail="Build folders git ignores: " + ", ".join(sorted({os.path.relpath(d, p) for d in build}))[:160] + ". The next build takes longer.",
                                  selected=False, kind="rebuild"))
        if rebuild_size > 20_000_000 and idle >= a.stale_days:
            items.append(dict(id=item_id("rebuild", p), category="Old projects", title=f"{proj['parent']}/{proj['name']}: node_modules and build folders",
                              path=p, size=rebuild_size, paths=rebuild,
                              detail=f"Not opened in {idle} days. `npm install` or a build brings these back.", selected=True, kind="rebuild"))
    projects.sort(key=lambda x: (-(x["idle_days"] >= a.stale_days), -x["size"]))

    progress("Checking Downloads")
    dl = os.path.join(HOME, "Downloads")
    try:
        for n in os.listdir(dl):
            p = os.path.join(dl, n)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            age = (now - max(st.st_atime, st.st_mtime)) / DAY
            size = st.st_size if os.path.isfile(p) else (du(p) if age > 60 else 0)
            if size > 100_000_000 and age > 60:
                items.append(dict(id=item_id("dl", p), category="Downloads", title=n, path=p, size=size,
                                  detail=f"Not opened in {int(age)} days. Moved to the Trash.", selected=False, kind="trash"))
    except OSError:
        pass

    du_total = shutil.disk_usage("/")
    emit(type="result", items=items, projects=projects, disk=dict(total=du_total.total, free=du_total.free),
         stale_days=a.stale_days, time=datetime.datetime.now().isoformat(timespec="seconds"))


def load_state(path):
    try:
        return json.load(open(path))
    except (OSError, ValueError, TypeError):
        return {}


# ---------------------------------------------------------------- clean

def safe_target(item):
    """Re-checks an item before deleting, so a tampered items file can't point anywhere else."""
    p = os.path.realpath(item.get("path", "")) if item.get("path") else ""
    k = item["kind"]
    if k == "contents":
        allowed = {os.path.realpath(os.path.expanduser(c[3])) for c in CACHES}
        return p in allowed
    if k == "simulator":
        return p.startswith(os.path.join(HOME, "Library/Developer/CoreSimulator/Devices/")) and p.count("/") == HOME.count("/") + 4
    if k == "path":
        return p.startswith(os.path.join(HOME, "Library/Android/sdk/system-images/"))
    if k == "avd":
        return p.startswith(os.path.join(HOME, ".android/avd/")) and p.endswith(".avd")
    if k == "trash":
        return os.path.dirname(p) == os.path.join(HOME, "Downloads")
    if k == "rebuild":
        return all(os.path.realpath(x).startswith(p + "/") and os.path.basename(x) in REBUILDABLE for x in item.get("paths", []))
    if k == "docker":
        return True
    if k == "editor":
        return p in {os.path.realpath(os.path.expanduser(c[2])) for c in EDITOR_CACHES}
    if k == "backupfile":
        return p in {os.path.realpath(os.path.expanduser(c[2])) for c in BACKUP_FILES}
    if k == "runtime":
        return bool(re.fullmatch(r"[0-9A-F-]{36}", item.get("udid", "")))
    return False


def app_running(app):
    rc, out, _ = run(["/usr/bin/pgrep", "-f", f"/{app}.app/Contents/MacOS/"], timeout=10)
    return rc == 0 and out.strip() != ""


def remove_tree(p):
    if os.path.islink(p) or os.path.isfile(p):
        os.unlink(p)
    elif os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)


def to_trash(p):
    trash = os.path.join(HOME, ".Trash")
    dst = os.path.join(trash, os.path.basename(p))
    if os.path.lexists(dst):
        base, ext = os.path.splitext(os.path.basename(p))
        dst = os.path.join(trash, f"{base} {datetime.datetime.now().strftime('%H.%M.%S')}{ext}")
    try:
        os.rename(p, dst)
    except OSError:
        shutil.move(p, dst)
    return dst


def clean(a):
    items = json.load(open(a.items))
    before = shutil.disk_usage("/").free
    results = []
    for i, it in enumerate(items, 1):
        emit(type="progress", title=f"Cleaning {it['title']}", pct=int((i - 1) * 100 / max(1, len(items))), current=it["id"])
        if not safe_target(it):
            results.append(dict(id=it["id"], ok=False, result="skipped: not a location RepoGuard cleans"))
            continue
        try:
            k = it["kind"]
            if k == "contents":
                for n in os.listdir(it["path"]):
                    if it["id"] == "logs" and n == "RepoGuard.log":
                        continue
                    remove_tree(os.path.join(it["path"], n))
            elif k == "simulator":
                rc, _, err = run(["xcrun", "simctl", "delete", it["udid"]], timeout=300)
                if rc:
                    raise RuntimeError(err.strip()[-200:])
            elif k in ("editor", "backupfile"):
                if app_running(it.get("app", "")):
                    raise RuntimeError(f"quit {it.get('app')} first")
                if k == "editor":
                    for n in os.listdir(it["path"]):
                        remove_tree(os.path.join(it["path"], n))
                else:
                    os.unlink(it["path"])
            elif k == "runtime":
                rc, _, err = run(["xcrun", "simctl", "runtime", "delete", it["udid"]], timeout=600)
                if rc:
                    raise RuntimeError(err.strip()[-200:])
            elif k in ("path", "avd"):
                remove_tree(it["path"])
            elif k == "trash":
                to_trash(it["path"])
            elif k == "rebuild":
                for x in it["paths"]:
                    remove_tree(x)
            elif k == "docker":
                cmd = {"builder": ["docker", "builder", "prune", "-a", "-f"], "images": ["docker", "image", "prune", "-a", "-f"],
                       "containers": ["docker", "container", "prune", "-f"]}.get(it.get("what"), ["docker", "system", "prune", "-f"])
                rc, _, err = run(cmd, timeout=1800)
                if rc:
                    raise RuntimeError(err.strip()[-200:] or "is Docker running?")
            results.append(dict(id=it["id"], ok=True, result="cleaned", size=it.get("size", 0)))
        except Exception as e:
            results.append(dict(id=it["id"], ok=False, result=f"failed: {e}"))
    after = shutil.disk_usage("/").free
    emit(type="result", results=results, freed=max(0, after - before), estimated=sum(r.get("size", 0) for r in results if r["ok"]))


# ---------------------------------------------------------------- archive

class Stop(Exception):
    pass


def step(n, of, title, status, detail=""):
    emit(type="step", n=n, of=of, title=title, status=status, detail=detail)


def notes_save(project, envs):
    """One note per project in a Notes folder called "RepoGuard .env backups". Returns the note name."""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    name = f"{os.path.basename(os.path.dirname(project))}/{os.path.basename(project)} .env ({stamp})"
    body = f"<h1>{html.escape(name)}</h1><p>{html.escape(project)}</p>"
    for e in envs:
        text = open(e, encoding="utf8", errors="replace").read()
        body += f"<h2>{html.escape(os.path.relpath(e, project))}</h2><pre>{html.escape(text)}</pre>"
    script = '''on run argv
  set folderName to "RepoGuard .env backups"
  tell application "Notes"
    if not (exists folder folderName) then make new folder with properties {name:folderName}
    make new note at folder folderName with properties {name:(item 1 of argv), body:(item 2 of argv)}
    return count of (notes of folder folderName whose name is (item 1 of argv))
  end tell
end run'''
    rc, out, err = run(["/usr/bin/osascript", "-e", script, name, body], timeout=60)
    if rc or out.strip() in ("", "0"):
        if "-1743" in err or "Not authorized" in err:
            raise Stop("RepoGuard isn't allowed to use Notes. Allow it in System Settings > Privacy & Security > Automation, then try again.")
        raise Stop(f"Couldn't save to Notes: {err.strip()[-200:]}")
    return name


def ignored_files(repo):
    """Ignored files that aren't rebuildable junk or .env (those are saved to Notes). They would be lost."""
    rc, out, _ = git(repo, "status", "--porcelain", "--ignored=matching", "--untracked-files=all")
    lost = []
    for line in out.splitlines():
        if not line.startswith("!! "):
            continue
        rel = line[3:].strip().strip('"').rstrip("/")
        parts = rel.split("/")
        if any(p in JUNK_IGNORED for p in parts) or ENV_NAME.match(parts[-1]) or rel.endswith((".log", ".pyc", ".tsbuildinfo")):
            continue
        lost.append(rel)
    return lost


def archive(a):
    p = os.path.realpath(a.project)
    state = load_state(a.state)
    steps = ["Check for malware", "Save .env files to Notes", "Commit unsaved work", "Push to GitHub", "Check GitHub has everything", "Remove from this Mac"]
    N = len(steps)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    done = {}
    i = 0
    try:
        # 1 malware: never push a project RepoGuard flagged; that's how the worm spread.
        i = 1
        step(i, N, steps[0], "running")
        bad = [f for f in state.get("findings", {}).values() if f["root"] == p]
        if bad:
            raise Stop(f"RepoGuard found {len(bad)} threat(s) in this project. Remove the malware first, so it isn't pushed.")
        if not os.path.isdir(p):
            raise Stop("The folder no longer exists.")
        if p == HOME or p.count("/") < 4:
            raise Stop("That folder is too broad to archive.")
        step(i, N, steps[0], "done", "No threats found")

        # 2 .env to Notes
        i = 2
        envs = env_files(p)
        if a.no_notes or not envs:
            step(i, N, steps[1], "skipped", "No .env files" if not envs else "Turned off")
        else:
            step(i, N, steps[1], "running", f"{len(envs)} file(s)")
            name = notes_save(p, envs)
            done["note"] = name
            step(i, N, steps[1], "done", f"Saved {len(envs)} file(s) in Notes: {name}")

        is_git = os.path.isdir(os.path.join(p, ".git"))
        if a.no_push:
            step(3, N, steps[2], "skipped", "Pushing turned off")
            step(4, N, steps[3], "skipped", "Pushing turned off")
            step(5, N, steps[4], "skipped", "Pushing turned off")
            if a.remove != "keep" and not a.accept_ignored:
                raise Stop("Without pushing, the code would only be in the Trash. Turn on pushing, or keep the folder.")
        else:
            # 3 commit unsaved work on a new branch, never with .env files
            i = 3
            step(i, N, steps[2], "running")
            if not is_git:
                git(p, "init", "-q", "-b", "main")
                is_git = True
            exclude = os.path.join(p, ".git/info/exclude")
            os.makedirs(os.path.dirname(exclude), exist_ok=True)
            with open(exclude, "a") as fh:
                fh.write("\n# added by RepoGuard archive\n.env\n.env.*\n!.env.example\n!.env.sample\n!.env.template\nnode_modules/\n.DS_Store\n")
            rc, out, _ = git(p, "status", "--porcelain")
            tracked_env = [l for l in out.splitlines() if ENV_NAME.match(os.path.basename(l[3:].strip().strip('"'))) and not ENV_EXAMPLE.search(l)]
            if tracked_env:
                raise Stop("A .env file is tracked by git here and has changes. Commit or revert it yourself first, so secrets aren't pushed.")
            lost = ignored_files(p)
            if lost and a.remove != "keep" and not a.accept_ignored:
                raise Stop("These git-ignored files aren't on GitHub and would be lost: " + ", ".join(lost[:12]) + (" …" if len(lost) > 12 else ""))
            if out.strip():
                big = []
                rc2, files, _ = git(p, "ls-files", "--others", "--exclude-standard", "-z")
                for rel in [x for x in files.split("\0") if x]:
                    try:
                        if os.path.getsize(os.path.join(p, rel)) > 95_000_000:
                            big.append(rel)
                    except OSError:
                        pass
                if big:
                    raise Stop("Files too large for GitHub: " + ", ".join(big[:5]))
                branch = f"repoguard-archive-{stamp}"
                rc, cur, _ = git(p, "branch", "--show-current")
                git(p, "switch", "-q", "-c", branch)
                git(p, "add", "-A")
                rc, _, err = git(p, "commit", "-q", "--no-verify", "-m", "Archive unsaved work (saved by RepoGuard before removing the folder)")
                if rc and "nothing to commit" not in err:
                    raise Stop(f"Commit failed: {err.strip()[-200:]}")
                done["archive_branch"] = branch
                step(i, N, steps[2], "done", f"Saved on branch {branch}")
            else:
                step(i, N, steps[2], "done", "Nothing unsaved")

            # 4 push
            i = 4
            step(i, N, steps[3], "running")
            rc, remotes, _ = git(p, "remote")
            remote = "origin" if "origin" in remotes.split() else (remotes.split()[0] if remotes.split() else "")
            rc, heads, _ = git(p, "for-each-ref", "--format=%(refname:short)", "refs/heads")
            if not heads.strip():
                git(p, "commit", "-q", "--no-verify", "--allow-empty", "-m", "Initial commit (RepoGuard archive)")
            if not remote:
                if not a.create_repo:
                    raise Stop("This project has no GitHub remote. Turn on \"Create a private GitHub repo\".")
                name = re.sub(r"[^A-Za-z0-9._-]+", "-", os.path.basename(p)).strip("-") or "project"
                rc, out, err = run(["gh", "repo", "create", name, "--private", "--source", p, "--remote", "origin"], cwd=p, timeout=120)
                if rc and "already exists" in err:
                    name = f"{name}-{stamp}"
                    rc, out, err = run(["gh", "repo", "create", name, "--private", "--source", p, "--remote", "origin"], cwd=p, timeout=120)
                if rc:
                    raise Stop(f"Couldn't create the GitHub repo: {err.strip()[-200:]}")
                remote = "origin"
                done["created_repo"] = out.strip() or name
            rc, heads, _ = git(p, "for-each-ref", "--format=%(refname:short)", "refs/heads")
            pushed, renamed = [], []
            for b in [h for h in heads.split() if h]:
                rc, _, err = git(p, "push", "--no-verify", remote, f"refs/heads/{b}:refs/heads/{b}", timeout=600)
                if rc:
                    # The remote branch moved on: keep ours under a new name instead of forcing.
                    alt = f"{b}-local-{stamp}"
                    rc, _, err = git(p, "push", "--no-verify", remote, f"refs/heads/{b}:refs/heads/{alt}", timeout=600)
                    if rc:
                        raise Stop(f"Push of {b} failed: {err.strip()[-200:]}")
                    renamed.append(f"{b} → {alt}")
                else:
                    pushed.append(b)
            rc, stashes, _ = git(p, "stash", "list", "--format=%gd")
            for n, s in enumerate([x for x in stashes.split() if x]):
                git(p, "push", "--no-verify", remote, f"{s}:refs/heads/repoguard-stash-{stamp}-{n}", timeout=600)
            git(p, "push", "--no-verify", remote, "--tags", timeout=600)
            step(i, N, steps[3], "done", f"{len(pushed)} branch(es) pushed" + (f"; kept on new names: {', '.join(renamed)}" if renamed else ""))

            # 5 verify every local commit is on the remote
            i = 5
            step(i, N, steps[4], "running")
            rc, _, err = git(p, "fetch", "--no-tags", remote, timeout=600)
            if rc:
                raise Stop(f"Couldn't fetch to check: {err.strip()[-200:]}")
            rc, out, _ = git(p, "for-each-ref", "--format=%(objectname) %(refname:short)", "refs/heads", "refs/stash")
            missing = []
            for line in out.splitlines():
                sha, ref = line.split(" ", 1)
                rc, contains, _ = git(p, "branch", "-r", "--contains", sha)
                if not contains.strip():
                    missing.append(ref)
            if missing:
                raise Stop("GitHub doesn't have these yet, so the folder was kept: " + ", ".join(missing))
            rc, st, _ = git(p, "status", "--porcelain")
            if st.strip():
                raise Stop("There are still unsaved changes, so the folder was kept.")
            step(i, N, steps[4], "done", "Every branch and commit is on GitHub")

        # 6 remove
        i = 6
        if a.remove == "keep":
            step(i, N, steps[5], "skipped", "Kept the folder")
        else:
            step(i, N, steps[5], "running")
            size = du(p)
            if a.remove == "delete":
                shutil.rmtree(p)
                step(i, N, steps[5], "done", f"Deleted, {size} bytes freed")
            else:
                dst = to_trash(p)
                step(i, N, steps[5], "done", "Moved to the Trash. Empty the Trash to free the space.")
                done["trash"] = dst
            done["freed"] = size
        emit(type="result", ok=True, **done)
    except Stop as e:
        step(i, N, steps[i - 1], "failed", str(e))
        for j in range(i + 1, N + 1):
            step(j, N, steps[j - 1], "skipped", "")
        emit(type="result", ok=False, error=str(e), **done)


# ---------------------------------------------------------------- disk map

PROTECTED = [("Mail", "~/Library/Mail"), ("Messages", "~/Library/Messages"), ("Photos library", "~/Pictures/Photos Library.photoslibrary"),
             ("iPhone and iPad backups", "~/Library/Application Support/MobileSync"), ("Safari", "~/Library/Safari"), ("Trash", "~/.Trash")]
MIN_NODE = 100 * 1024 * 1024


def du_tree(path, depth):
    """{path, size, children} from one `du -d depth` pass. Sizes are real disk use, so sparse files
    (Docker's disk, Xcode caches) count for what they actually take."""
    rc, out, _ = run(["/usr/bin/du", "-kx", "-d", str(depth), path], timeout=3600)
    sizes = {}
    for line in out.splitlines():
        k, _, p = line.partition("\t")
        try:
            sizes[p] = int(k) * 1024
        except ValueError:
            pass
    nodes = {p: {"path": p, "name": os.path.basename(p) or p, "size": s, "children": []} for p, s in sizes.items() if s >= MIN_NODE or p == path}
    for p in sorted(nodes, key=len, reverse=True):
        parent = os.path.dirname(p)
        if p != path and parent in nodes:
            nodes[parent]["children"].append(nodes[p])
    for n in nodes.values():
        n["children"].sort(key=lambda x: -x["size"])
    return nodes.get(path, {"path": path, "name": os.path.basename(path), "size": sizes.get(path, 0), "children": []})


def apfs_volumes():
    rc, out, _ = run(["/bin/sh", "-c", "diskutil apfs list -plist | plutil -convert json -o - -"], timeout=60)
    try:
        data = json.loads(out)
    except ValueError:
        return None, []
    main, extra = None, []
    for c in data.get("Containers", []):
        vols = [dict(name=v.get("Name", ""), role=(v.get("Roles") or [""])[0], used=int(v.get("CapacityInUse") or 0)) for v in c.get("Volumes", [])]
        if any(v["role"] == "Data" for v in vols):
            main = dict(total=int(c.get("CapacityCeiling") or 0), free=int(c.get("CapacityFree") or 0), volumes=vols)
        elif any("Simulator" in v["name"] for v in vols):
            extra += [v for v in vols if v["used"] > 0]
    return main, extra


def can_read(p):
    try:
        os.listdir(p)
        return True
    except PermissionError:
        return False
    except OSError:
        return True  # doesn't exist: nothing hidden there


def diskmap(a):
    t0 = time.time()
    container, sim_volumes = apfs_volumes()
    tops = [n for n in sorted(os.listdir(HOME)) if not os.path.islink(os.path.join(HOME, n))]
    others = [("/Applications", 1), ("/opt/homebrew", 1), ("/Library", 2), ("/usr/local", 1), ("/private/var", 1), ("/Users/Shared", 1)]
    total = len(tops) + len(others) + 3
    done = 0

    def tick(title):
        nonlocal done
        done += 1
        emit(type="progress", title=title, pct=min(99, int(done * 100 / total)))

    home = {"path": HOME, "name": "Home folder", "size": 0, "children": []}
    for n in tops:
        tick(f"Measuring ~/{n}")
        p = os.path.join(HOME, n)
        node = du_tree(p, 4 if n in ("Library", "Desktop", "Documents", "Downloads") else 3)
        home["size"] += node["size"]
        if node["size"] >= MIN_NODE:
            home["children"].append(node)
    home["children"].sort(key=lambda x: -x["size"])
    roots = [home]
    for p, d in others:
        tick(f"Measuring {p}")
        if os.path.isdir(p):
            node = du_tree(p, d)
            node["name"] = {"/private/var": "System data (/private/var)", "/Library": "/Library (all users)"}.get(p, p)
            if node["size"] >= MIN_NODE:
                roots.append(node)

    tick("Checking protected folders")
    blocked = [dict(name=name, path=os.path.expanduser(p)) for name, p in PROTECTED if not can_read(os.path.expanduser(p))]

    tick("Finding large files")
    large = []
    rc, out, _ = run(["mdfind", "-onlyin", HOME, "kMDItemFSSize > 1000000000"], timeout=60)
    for f in out.splitlines():
        try:
            st = os.lstat(f)
        except OSError:
            continue
        if not os.path.isfile(f):
            continue
        real = st.st_blocks * 512
        if real >= 500_000_000:
            large.append(dict(path=f, size=real, apparent=st.st_size, modified=datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d")))
    large.sort(key=lambda x: -x["size"])

    tick("Explaining what uses space")
    insights = make_insights(home, roots, blocked, container)
    measured = sum(r["size"] for r in roots)
    emit(type="result", container=container, sim_volumes=sim_volumes, roots=roots, blocked=blocked, large=large[:40],
         insights=insights, measured=measured, seconds=int(time.time() - t0), time=datetime.datetime.now().isoformat(timespec="seconds"))


def find_node(node, path):
    if node["path"] == path:
        return node
    for c in node["children"]:
        if path == c["path"] or path.startswith(c["path"] + "/"):
            return find_node(c, path)
    return None


def size_at(roots, path):
    for r in roots:
        if path == r["path"] or path.startswith(r["path"] + "/"):
            n = find_node(r, path)
            if n:
                return n["size"]
    return du(path) if os.path.exists(path) else 0


def make_insights(home, roots, blocked, container):
    out = []

    def add(title, size, detail, action="", path=""):
        if size >= 500_000_000:
            out.append(dict(title=title, size=size, detail=detail, action=action, path=path))

    H = HOME
    docker = os.path.join(H, "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw")
    add("Docker's virtual disk", size_at(roots, os.path.join(H, "Library/Containers/com.docker.docker")),
        "Everything inside Docker (images, containers, volumes, build cache) lives in one disk file. Clean its build cache and unused images under "
        "Safe to clean > Docker while Docker is running; Docker hands the space back to macOS over the next minutes.", "category:Docker", docker)
    add("Desktop", size_at(roots, os.path.join(H, "Desktop")),
        "Mostly your projects. Their build output and node_modules are listed under Safe to clean; open Explore to see the rest.", "explore", os.path.join(H, "Desktop"))
    add("iOS simulators", size_at(roots, os.path.join(H, "Library/Developer/CoreSimulator")),
        "Each simulator keeps its own apps and data. Delete the ones you don't use under Safe to clean > Simulators.", "category:Simulators")
    add("Android SDK and emulators", size_at(roots, os.path.join(H, "Library/Android")) + size_at(roots, os.path.join(H, ".android")),
        "Emulator system images and emulator disks. Remove versions you don't test on in Android Studio > SDK Manager.", "category:Android")
    cursor = os.path.join(H, "Library/Application Support/Cursor")
    db = os.path.join(cursor, "User/globalStorage/state.vscdb")
    try:
        dbs = os.lstat(db).st_blocks * 512
    except OSError:
        dbs = 0
    add("Cursor chat history", dbs,
        "Cursor stores every chat in one database. RepoGuard won't delete it. To shrink it, delete old chats inside Cursor; its backup copy and checkpoints are under Safe to clean > Editors.",
        "reveal", db)
    icloud = size_at(roots, os.path.join(H, "Library/Mobile Documents"))
    add("iCloud Drive files kept on this Mac", icloud,
        "Includes app backups such as WhatsApp's. Turn on System Settings > Apple Account > iCloud > Optimize Mac Storage to keep only recent files here.", "reveal",
        os.path.join(H, "Library/Mobile Documents"))
    hidden = sum(c["size"] for c in home["children"] if c["name"].startswith("."))
    add("Hidden tool folders in your home", hidden,
        "Folders like .cache, .gradle, .npm, .vscode and .local hold tool downloads and caches. Open Explore > Home folder to see each one.", "explore", H)
    apps = size_at(roots, "/Applications")
    add("Applications", apps, "Installed apps. Remove ones you don't use by dragging them to the Trash.", "explore", "/Applications")
    if container:
        sysv = sum(v["used"] for v in container["volumes"] if v["role"] in ("System", "Preboot", "Recovery", "Update"))
        add("macOS itself", sysv, "The read-only system, startup files and Recovery. This can't be cleaned.", "")
        vm = sum(v["used"] for v in container["volumes"] if v["role"] == "VM")
        add("Swap and sleep image", vm, "Memory macOS moved to disk. It shrinks after a restart, especially if you close heavy apps first.", "")
        data = sum(v["used"] for v in container["volumes"] if v["role"] == "Data")
        measured = sum(r["size"] for r in roots)
        unknown = max(0, data - measured)
        if blocked:
            add("Space RepoGuard can't see yet", unknown,
                "Protected folders (" + ", ".join(b["name"] for b in blocked) + ") and system files need Full Disk Access to measure. "
                "Give RepoGuard Full Disk Access in System Settings, then analyze again.", "fda")
        else:
            add("Other system data", unknown, "Space used outside your folders: system caches, Time Machine snapshots and files only root can read.", "")
    out.sort(key=lambda x: -x["size"])
    return out


def children(a):
    node = du_tree(a.path, 1)
    emit(type="result", node=node)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["analyze", "clean", "archive", "diskmap", "children"])
    ap.add_argument("--path")
    ap.add_argument("--watch", action="append", default=[])
    ap.add_argument("--state", default="")
    ap.add_argument("--stale-days", type=int, default=30)
    ap.add_argument("--items")
    ap.add_argument("--project")
    ap.add_argument("--no-notes", action="store_true")
    ap.add_argument("--no-push", action="store_true")
    ap.add_argument("--create-repo", action="store_true")
    ap.add_argument("--remove", choices=["trash", "delete", "keep"], default="trash")
    ap.add_argument("--accept-ignored", action="store_true")
    a = ap.parse_args()
    {"analyze": analyze, "clean": clean, "archive": archive, "diskmap": diskmap, "children": children}[a.mode](a)


if __name__ == "__main__":
    main()
