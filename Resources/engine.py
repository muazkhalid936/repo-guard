"""RepoGuard scan engine.

Reads files and git objects as data. It never runs, imports or checks out anything it scans.
Run with `python3 -I` so nothing is loaded from the scanned folder.

  engine.py full  --watch DIR --state FILE --rules FILE --log FILE
  engine.py event --watch DIR --state FILE --rules FILE --log FILE --paths-file FILE
  engine.py ignore-active --state FILE
"""
import argparse, datetime, hashlib, json, os, re, stat, subprocess, sys

GIT = "/usr/bin/git"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_TERMINAL_PROMPT="0", LC_ALL="C")
# Plumbing commands only, with program-running settings neutralised.
GIT_BASE = [GIT, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.sshCommand=/usr/bin/false", "-c", "core.pager=cat"]


class Rules:
    def __init__(self, path):
        r = json.load(open(path))
        self.max = r["max_file_bytes"]
        self.skip_dirs = set(r["skip_dirs"])
        self.skip_content = re.compile(r["skip_content"])
        self.vendored = re.compile(r["vendored"])
        self.code = re.compile(r["code_files"])
        self.media = re.compile(r["media_files"], re.I)
        self.path_rules = [dict(x, rx=re.compile(x["pattern"])) for x in r["path_rules"]]
        self.content_rules = [dict(x, rx=re.compile(x["pattern"].encode(), re.M)) for x in r["content_rules"]]
        self.fake = dict(r["fake_media"], rx=re.compile(r["fake_media"]["pattern"].encode()))
        self.config_rules = [dict(x, rx=re.compile(x["pattern"].encode(), re.M | re.I)) for x in r["git_config_rules"]]

    def check(self, path, data):
        """Return [(rule_id, severity, label)] for one file version. data=None means name-only."""
        hits = []
        for rule in self.path_rules:
            if rule["rx"].search(path):
                hits.append((rule["id"], rule["severity"], rule["label"]))
        if data is None or self.skip_content.search(path) or b"\0" in data[:8000]:
            return hits
        if self.media.search(path):
            if self.fake["rx"].search(data[:8000]):
                hits.append(("fake_media", self.fake["severity"], self.fake["label"]))
            return hits
        base = os.path.basename(path)
        vendored = bool(self.vendored.search(path))
        for rule in self.content_rules:
            scope = rule["scope"]
            if scope == "gitignore" and base != ".gitignore":
                continue
            if scope == "package_json" and (base != "package.json" or vendored):
                continue
            if scope == "code" and (vendored or not self.code.search(path)):
                continue
            need = rule.get("min_count", 1)
            matched = len(rule["rx"].findall(data)) >= need if need > 1 else bool(rule["rx"].search(data))
            if matched:
                hits.append((rule["id"], rule["severity"], rule["label"]))
        return hits


def git(repo, *args, data=None):
    p = subprocess.run(GIT_BASE + ["-C", repo, *args], input=data, capture_output=True, env=GIT_ENV, cwd="/")
    return p.returncode, p.stdout


def read_blobs(repo, shas, limit):
    """Yield (sha, bytes or None). Oversized blobs come back as None so names are still checked."""
    shas = list(dict.fromkeys(shas))
    for i in range(0, len(shas), 200):
        part = shas[i:i + 200]
        rc, out = git(repo, "cat-file", "--batch-check", data="\n".join(part).encode())
        small = []
        for line in out.decode("utf8", "replace").splitlines():
            f = line.split()
            if len(f) == 3 and f[1] == "blob":
                if int(f[2]) <= limit:
                    small.append(f[0])
                else:
                    yield f[0], None
        if not small:
            continue
        rc, out = git(repo, "cat-file", "--batch", data="\n".join(small).encode())
        pos = 0
        while pos < len(out):
            nl = out.index(b"\n", pos)
            head = out[pos:nl].split()
            size = int(head[2])
            yield head[0].decode(), out[nl + 1:nl + 1 + size]
            pos = nl + 2 + size


class Scanner:
    def __init__(self, a):
        self.rules = Rules(a.rules)
        self.watch = os.path.realpath(a.watch)
        self.state_path = a.state
        self.log_path = a.log
        try:
            self.state = json.load(open(a.state))
        except (OSError, ValueError):
            self.state = {}
        self.state.setdefault("refs", {})
        self.state.setdefault("findings", {})
        self.state.setdefault("ignored", [])
        self.before = set(self.state["findings"])
        self.reviews = []
        self.files = 0
        self.repos = set()

    def log(self, msg):
        if not self.log_path:
            return
        with open(self.log_path, "a") as fh:
            fh.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")

    def add(self, root, path, rule, severity, label, where, sig):
        if severity != "block":
            self.reviews.append({"root": root, "path": path, "label": label, "where": where})
            self.log(f"REVIEW {root} {path}: {label} [{where}]")
            return
        key = f"{root}|{path}|{rule}|{sig}"
        if key in self.state["ignored"]:
            return
        self.state["findings"][key] = {"key": key, "root": root, "path": path, "rule": rule, "label": label, "where": where,
                                       "time": datetime.datetime.now().isoformat(timespec="seconds")}

    def clear(self, root, test):
        for k, f in list(self.state["findings"].items()):
            if f["root"] == root and test(f):
                del self.state["findings"][k]

    # ---- files on disk
    def scan_file(self, root, abspath):
        rel = os.path.relpath(abspath, root)
        self.clear(root, lambda f: f["where"] == "folder" and f["path"] == rel)
        try:
            st = os.lstat(abspath)
        except OSError:
            return  # deleted: its finding was just cleared
        if not stat.S_ISREG(st.st_mode):
            return
        data = None
        if st.st_size <= self.rules.max:
            try:
                with open(abspath, "rb") as fh:
                    data = fh.read()
            except OSError:
                return
        self.files += 1
        sig = hashlib.sha1(data).hexdigest() if data is not None else str(st.st_size)
        for rule, sev, label in self.rules.check(rel, data):
            self.add(root, rel, rule, sev, label, "folder", sig)

    def walk(self, root, top, repos_out=None):
        for cur, dirs, names in os.walk(top, followlinks=False):
            if repos_out is not None and ".git" in dirs + names:
                repos_out.append(cur)
            dirs[:] = [d for d in dirs if d != ".git" and d not in self.rules.skip_dirs]
            owner = self.root_of(os.path.join(cur, "x"))
            for n in names:
                if n != ".git":
                    self.scan_file(owner, os.path.join(cur, n))

    def root_of(self, path):
        """Nearest ancestor holding .git, otherwise the top-level folder inside the watch dir."""
        cur = os.path.dirname(path)
        top = None
        while cur.startswith(self.watch) and cur != self.watch:
            if os.path.lexists(os.path.join(cur, ".git")):
                return cur
            top = cur
            cur = os.path.dirname(cur)
        return top or self.watch

    # ---- git refs
    def scan_config(self, repo):
        self.clear(repo, lambda f: f["where"] == "git-config")
        gd = os.path.join(repo, ".git")
        if not os.path.isdir(gd):
            return
        try:
            data = open(os.path.join(gd, "config"), "rb").read()
        except OSError:
            data = b""
        sig = hashlib.sha1(data).hexdigest()
        for rule in self.rules.config_rules:
            if rule["rx"].search(data):
                self.add(repo, ".git/config", rule["id"], rule["severity"], rule["label"], "git-config", sig)
        hooks = os.path.join(gd, "hooks")
        if os.path.isdir(hooks):
            for n in sorted(os.listdir(hooks)):
                p = os.path.join(hooks, n)
                if not n.endswith(".sample") and os.path.isfile(p) and os.access(p, os.X_OK):
                    self.add(repo, f".git/hooks/{n}", "repo_hook", "review", "Executable Git hook inside this repo", "git-config", n)

    def scan_tree(self, repo, name, sha, where, skip=None):
        rc, out = git(repo, "ls-tree", "-r", "-z", sha)
        if rc:
            return set()
        items = []
        for row in out.split(b"\0"):
            if not row:
                continue
            meta, path = row.split(b"\t", 1)
            f = meta.split()
            if f[1] == b"blob":
                items.append((f[2].decode(), path.decode("utf8", "replace")))
        self.scan_items(repo, items, where)
        return {s for s, _ in items}

    def scan_items(self, repo, items, where):
        by_sha = {}
        for s, p in items:
            by_sha.setdefault(s, []).append(p)
        for sha, data in read_blobs(repo, list(by_sha), self.rules.max):
            for p in by_sha[sha]:
                self.files += 1
                for rule, sev, label in self.rules.check(p, data):
                    self.add(repo, p, rule, sev, label, where, sha)

    def scan_refs(self, repo, force=False):
        self.repos.add(repo)
        rc, out = git(repo, "for-each-ref", "--format=%(refname) %(objectname) %(objecttype)")
        if rc:
            return
        now = {}
        for line in out.decode("utf8", "replace").splitlines():
            ref, sha, typ = line.rsplit(" ", 2)
            if typ == "commit" and not ref.endswith("/HEAD") and not ref.startswith("refs/pull/"):
                now[ref] = sha
        known = self.state["refs"].setdefault(repo, {})
        for ref in [r for r in known if r not in now]:
            self.clear(repo, lambda f: f["where"] in (f"branch:{ref}", f"incoming:{ref}"))
            del known[ref]
        seen_trees = {}
        for ref, sha in now.items():
            old = known.get(ref)
            short = ref.replace("refs/heads/", "").replace("refs/remotes/", "").replace("refs/tags/", "tag ")
            if old == sha and not force:
                continue
            if old != sha:
                self.clear(repo, lambda f: f["where"] == f"incoming:{ref}")
            self.clear(repo, lambda f: f["where"] == f"branch:{ref}")
            tree = seen_trees.get(sha)
            current = tree if tree is not None else self.scan_tree(repo, short, sha, f"branch:{ref}")
            if tree is None:
                seen_trees[sha] = current
            else:
                self.scan_tree(repo, short, sha, f"branch:{ref}")
            if old and old != sha:
                rc, ancestor = git(repo, "merge-base", "--is-ancestor", old, sha)
                if rc == 1 and ref.startswith("refs/remotes/"):
                    self.add(repo, short, "force_push", "review", "Branch history was rewritten (force-push)", f"branch:{ref}", sha)
                self.scan_range(repo, ref, old, sha, current)
            known[ref] = sha

    def scan_range(self, repo, ref, old, new, current):
        """Check versions added and removed again between two points, and rewritten commits.

        Commits already reachable from another known ref were reported when that ref moved,
        so pulling a branch doesn't repeat a warning that fetching already raised.
        """
        seen = sorted(set(self.state["refs"].get(repo, {}).values()) | {old})
        rc, out = git(repo, "rev-list", "--ignore-missing", "--objects", new, "--not", *seen)
        if rc:
            return
        items = []
        for line in out.decode("utf8", "replace").splitlines():
            f = line.split(" ", 1)
            if len(f) == 2 and f[0] not in current:
                items.append((f[0], f[1]))
        self.scan_items(repo, items, f"incoming:{ref}")
        rc, out = git(repo, "log", "--ignore-missing", "--format=%h%x09%ai%x09%ci%x09%ae%x09%ce", new, "--not", *seen)
        for line in out.decode("utf8", "replace").splitlines():
            f = line.split("\t")
            if len(f) == 5 and f[3] == f[4] and f[1].split()[-1] != f[2].split()[-1]:
                self.add(repo, f[0], "tz_mismatch", "review", "Commit timezone mismatch, as seen in rewritten malware commits", f"incoming:{ref}", f[0])

    # ---- entry points
    def require_access(self):
        """An unreadable folder must fail loudly, not look like a clean scan."""
        try:
            os.listdir(self.watch)
        except FileNotFoundError:
            pass
        except OSError as e:
            sys.exit(f"No permission to read {self.watch}: {e}")

    def full(self):
        self.require_access()
        repos = []
        if os.path.isdir(self.watch):
            self.walk(self.watch, self.watch, repos)
        for repo in repos:
            self.scan_config(repo)
            self.scan_refs(repo, force=True)
        known = set(repos)
        for gone in [r for r in self.state["refs"] if r not in known]:
            del self.state["refs"][gone]
        # Clear findings from folders that no longer exist.
        for k, f in list(self.state["findings"].items()):
            if not os.path.exists(f["root"]):
                del self.state["findings"][k]

    def event(self, paths):
        self.require_access()
        ref_dirty, config_dirty = set(), set()
        files, folders = set(), set()
        for p in paths:
            p = p.rstrip("/")
            if not p.startswith(self.watch):
                continue
            rel = os.path.relpath(p, self.watch)
            parts = rel.split(os.sep)
            if any(x in self.rules.skip_dirs for x in parts):
                continue
            if ".git" in parts:
                i = parts.index(".git")
                repo = os.path.join(self.watch, *parts[:i])
                inner = parts[i + 1:]
                if not inner or inner[0] in ("HEAD", "ORIG_HEAD", "FETCH_HEAD", "packed-refs", "refs"):
                    ref_dirty.add(repo)
                if not inner or inner[0] in ("config", "hooks"):
                    config_dirty.add(repo)
                continue
            if os.path.isdir(p) and not os.path.islink(p):
                folders.add(p)
            else:
                files.add(p)
        for folder in folders:
            repos = []
            self.walk(self.root_of(os.path.join(folder, "x")), folder, repos)
            for r in repos:
                ref_dirty.add(r)
                config_dirty.add(r)
        for f in files:
            root = self.root_of(f)
            self.scan_file(root, f)
            self.repos.add(root)
        for r in config_dirty:
            self.scan_config(r)
        for r in ref_dirty:
            self.scan_refs(r)

    def finish(self):
        active = list(self.state["findings"].values())
        new = [f for k, f in self.state["findings"].items() if k not in self.before]
        for f in new:
            self.log(f"THREAT {f['root']} {f['path']}: {f['label']} [{f['where']}]")
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.state, fh)
        os.replace(tmp, self.state_path)
        self.log(f"scan done: files={self.files} repos={len(self.repos)} new={len(new)} active={len(active)}")
        print(json.dumps({"new": new, "active": active, "reviews": self.reviews, "files": self.files, "repos": len(self.repos)}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["full", "event", "ignore-active"])
    ap.add_argument("--watch", default="")
    ap.add_argument("--state", required=True)
    ap.add_argument("--rules", default="")
    ap.add_argument("--log", default="")
    ap.add_argument("--paths-file")
    a = ap.parse_args()
    if a.mode == "ignore-active":
        s = json.load(open(a.state))
        s["ignored"] = sorted(set(s.get("ignored", [])) | set(s.get("findings", {})))
        s["findings"] = {}
        json.dump(s, open(a.state, "w"))
        print(json.dumps({"new": [], "active": [], "reviews": [], "files": 0, "repos": 0}))
        return
    sc = Scanner(a)
    if a.mode == "full":
        sc.full()
    else:
        sc.event(json.load(open(a.paths_file)))
    sc.finish()


if __name__ == "__main__":
    main()
