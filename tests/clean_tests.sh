#!/bin/zsh
# Tests for the malware cleaner, using fake repos with harmless copies of the malware's patterns.
# Usage: tests/clean_tests.sh SCRATCH_DIR
ROOT=${0:A:h:h}; T=${1:?scratch dir required}/rgclean; rm -rf "$T"; mkdir -p "$T"
RES="$ROOT/Resources"; W="$T/watch"; mkdir -p "$W"; ST="$T/state.json"; BK="$T/backup"; pass=0; fail=0
export SCAN_NO_NOTIFY=1 REPOGUARD_ALLOW_FETCH=1  # the fake infected repos below must not trip the global git hooks
eng() { /usr/bin/python3 -I "$RES/engine.py" full --watch "$W" --state "$ST" --rules "$RES/rules.json" --log "$T/log"; }
cln() { /usr/bin/python3 -I "$RES/cleaner.py" --state "$ST" --rules "$RES/rules.json" --backup "$BK" --log "$T/log" "$@"; }
count() { /usr/bin/python3 -I -c 'import json,sys;d=json.load(sys.stdin);print(len(d[sys.argv[1]]))' "$1"; }
ok() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1: expected [$3], got [$2]"; fi; }
cfg() { git -C "$1" config user.name t; git -C "$1" config user.email t@t; }
PAD=$(printf ' %.0s' {1..150})
LOADER="var z = '-67""52-3';"

# clean origin with two commits on main and a second branch
git init -q --bare --initial-branch=main "$T/o.git"; git clone -q "$T/o.git" "$T/dev" 2>/dev/null; cfg "$T/dev"
cd "$T/dev"
print -r -- "export default { plugins: {} };" > postcss.config.mjs
print -r -- '{"name":"x","scripts":{"dev":"next dev","build":"next build"}}' > package.json
print -r -- "node_modules" > .gitignore
print -r -- "export const a = 1;" > a.js
git add -A; git commit -qm c1
print -r -- "export const b = 2;" > b.js; git add -A; git commit -qm c2
git push -q origin main
git checkout -q -b old-branch; print -r -- "x" > old.txt; git add -A; git commit -qm old; git push -q origin old-branch; git checkout -q main
cd /

git clone -q "$T/o.git" "$W/app" 2>/dev/null; cfg "$W/app"; cd "$W/app"
git fetch -q origin old-branch:refs/remotes/origin/old-branch

infect() {  # adds the worm's files to the current working tree
  print -r -- "export default { plugins: {} };$PAD$LOADER" > postcss.config.mjs
  print -r -- '{"name":"x","scripts":{"dev":"node in''it && next dev","build":"next build"}}' > package.json
  printf 'node_modules\nconfig.bat\ntemp_auto_push.bat\n' > .gitignore
  mkdir -p .vscode public/fonts
  print -r -- '{"version":"2.0.0","tasks":[{"label":"eslint-check","type":"shell","command":"node ./public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folder''Open"}}]}' > .vscode/tasks.json
  printf '{\n  "task.allowAutomatic''Tasks": "on"\n}\n' > .vscode/settings.json
  print -r -- "x$PAD$LOADER" > init
  print -r -- "function x(){}" > public/fonts/fa-brand-400.orc
  print -r -- "@echo off" > config.bat
}

# 1. local main = a fake copy of c2 with malware (parent c1), like the worm makes
git reset -q --hard HEAD~1; print -r -- "export const b = 2;" > b.js; infect; git add -A; git commit -qm c2
# 2. local branch with real unpushed work + malware
git checkout -q -b feature; print -r -- "my work" > feature.txt; git add -A; git commit -qm "my work"; git checkout -q main
# 3. infected cached copy of a GitHub branch
git checkout -q -b tmp origin/old-branch; infect; git add -A; git commit -qm old; git update-ref refs/remotes/origin/old-branch HEAD; git checkout -q main; git branch -q -D tmp
# 3b. a branch infected on GitHub itself (worm-style settings.json with an embedded folderOpen task)
git checkout -q -b gh-infected origin/main; mkdir -p .vscode
printf '{\n  "editor.tabSize": 2,\n  "task.allowAutomatic''Tasks": true,\n  "terminal.integrated.hideOnStartup": "always",\n  "tasks": {\n    "label": "lint on open",\n    "command": "npm run lint",\n    "runOn": "folder''Open"\n  }\n}\n' > .vscode/settings.json
print -r -- "x$PAD$LOADER" > init; git add -A; git commit -qm "fix: bundle id mismatch"; git push -q origin gh-infected; git checkout -q main
GH_BEFORE=$(git -C "$T/o.git" rev-parse gh-infected)
# 4. infected tag
git tag evidence feature
# 5. working tree files: python loader inside a real file, plus a fake font
printf 'import os\n\nDEFAULT_TIMEOUT = 20\n\ntry:\n    import urllib.request as _ur\n    _addr = "0x3b1574417524c11a7403''c4b232CAcBb320CceBC6"\n    _u = "https://api.ethplo''rer.io/x"\nexcept Exception:\n    pass\n\ndef real():\n    return os.getcwd()\n' > conftest.py
print -r -- 'function(){ var a=require("x") }' > public/fonts/logo.woff2
# 7. a plain folder (not git) where the worm's code sits next to real content
L="$W/loose"; mkdir -p "$L/.vscode"
print -r -- "export default { plugins: {} };$PAD$LOADER" > $L/postcss.config.mjs
print -r -- '{"name":"x","scripts":{"dev":"node in''it && next dev","build":"next build"}}' > $L/package.json
printf 'node_modules\nconfig.bat\ntemp_auto_push.bat\n' > $L/.gitignore
print -r -- '{"version":"2.0.0","tasks":[{"label":"build","type":"shell","command":"npm run build"},{"label":"eslint-check","type":"shell","command":"node ./public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folder''Open"}}]}' > $L/.vscode/tasks.json
printf '{\n  "editor.tabSize": 2,\n  "task.allowAutomatic''Tasks": "on"\n}\n' > $L/.vscode/settings.json
# 6. a vendored false alarm that must not be touched
mkdir -p .venv-x/lib/site-packages/pkg; print -r -- "a = 1$PAD$LOADER" > .venv-x/lib/site-packages/pkg/m.py
cd /

BEFORE=$(eng | count active)
[ "$BEFORE" -gt 10 ] && ok "fake infection is detected ($BEFORE findings)" yes yes || ok "fake infection is detected" "$BEFORE" ">10"
FEATURE_BEFORE=$(git -C "$W/app" rev-parse feature)

# Preview: shows every change, changes nothing
snap() { (cd "$W" && find . -type f -not -path '*/.git/*' -exec shasum {} + | sort; git -C "$W/app" for-each-ref; git -C "$T/o.git" for-each-ref) | shasum; }
SNAP=$(snap)
P=$(/usr/bin/python3 -I "$RES/cleaner.py" --state "$ST" --rules "$RES/rules.json" --preview); print -r -- "$P" > "$T/preview.json"
pj() { /usr/bin/python3 -I -c "import json,sys;d=json.load(open(sys.argv[2]));print(eval(sys.argv[1]))" "$1" "$T/preview.json"; }
ok "preview changes nothing" "$(snap)" "$SNAP"
ok "preview: postcss cut shown, real code kept" "$(pj "[(i['action'], i['kept']) for i in d['items'] if i['path']=='postcss.config.mjs' and i['repo'].endswith('loose')]")" "[('clean', ['export default { plugins: {} };'])]"
ok "preview: hidden code is made visible" "$(pj "any('150 blank characters' in l for i in d['items'] if i['path']=='postcss.config.mjs' for l in i['removed'])")" True
ok "preview: init will be deleted" "$(pj "sorted({i['action'] for i in d['items'] if i['path']=='init'})")" "['delete']"
ok "preview: one entry per file version, listing every place" "$(pj "len([i for i in d['items'] if i['path']=='init' and 'files on disk' in i['where'] and 'branch main' in i['where']])")" 1
ok "preview: branch with real work gets a cleanup commit" "$(pj "[r['plan'] for r in d['refs'] if r['ref']=='branch feature']")" "['commit']"
ok "preview: GitHub copies listed" "$(pj "sorted(r['ref'] for r in d['refs'] if r['kind']=='github')")" "['GitHub copy origin/gh-infected', 'GitHub copy origin/old-branch']"
FP=$(pj "d['fingerprint']")
cln --fix-github --expect 0000000000000000 >/dev/null; ok "approval for other threats is refused" "$?" 3
ok "refused run changes nothing" "$(snap)" "$SNAP"

S=$(cln --fix-github --expect "$FP"); print -r -- "$S"; cp "$BK/last-clean.json" "$T/first.json"
A="$W/app"
ok "postcss: hidden code cut, real code kept" "$(cat $L/postcss.config.mjs)" "export default { plugins: {} };"
ok "package.json: node init removed, scripts kept" "$(cat $L/package.json)" '{"name":"x","scripts":{"dev":"next dev","build":"next build"}}'
ok ".gitignore: worm markers removed, real entry kept" "$(cat $L/.gitignore)" "node_modules"
ok "tasks.json: auto-run task removed, real task kept" "$(/usr/bin/python3 -I -c 'import json,sys;print([t["label"] for t in json.load(open(sys.argv[1]))["tasks"]])' $L/.vscode/tasks.json)" "['build']"
ok "settings.json: auto tasks off, other setting kept" "$(grep -c allowAutomaticTasks $L/.vscode/settings.json; grep -c tabSize $L/.vscode/settings.json)" "0
1"
ok "checked-out main: files now match GitHub" "$(git -C $A status --porcelain --untracked-files=no | wc -l | tr -d ' ')" 0
ok "checked-out main: worm's tasks.json gone" "$([ -e $A/.vscode/tasks.json ] && echo present || echo gone)" gone
ok "init loader deleted" "$([ -e $A/init ] && echo present || echo gone)" gone
ok ".orc payload deleted" "$([ -e $A/public/fonts/fa-brand-400.orc ] && echo present || echo gone)" gone
ok "fake font deleted" "$([ -e $A/public/fonts/logo.woff2 ] && echo present || echo gone)" gone
ok "config.bat dropper deleted" "$([ -e $A/config.bat ] && echo present || echo gone)" gone
ok "conftest.py: loader block removed, real code kept" "$(cat $A/conftest.py)" "import os

def real():
    return os.getcwd()"
ok "vendored library file left alone" "$(grep -c 6752 $A/.venv-x/lib/site-packages/pkg/m.py)" 1
ok "local main moved to the clean GitHub commit" "$(git -C $A rev-parse main)" "$(git -C $T/o.git rev-parse main)"
ok "feature branch keeps its work" "$(git -C $A show feature:feature.txt)" "my work"
ok "feature branch got a cleanup commit on top" "$(git -C $A rev-parse feature^)" "$FEATURE_BEFORE"
ok "feature branch tree is clean" "$(git -C $A ls-tree -r --name-only feature | grep -cE '(^|/)init$|\.orc$')" 0
ok "infected origin/old-branch replaced by clean re-fetch" "$(git -C $A rev-parse origin/old-branch)" "$(git -C $T/o.git rev-parse old-branch)"
ok "GitHub branch fixed with a commit on top (no force-push)" "$(git -C $T/o.git rev-parse gh-infected^)" "$GH_BEFORE"
ok "GitHub branch tree is clean" "$(git -C $T/o.git ls-tree -r --name-only gh-infected | grep -cE '(^|/)init$')" 0
ok "settings.json on GitHub: worm keys gone, real setting kept" "$(git -C $T/o.git show gh-infected:.vscode/settings.json | tr -d ' \n')" '{"editor.tabSize":2}'
ok "local branch follows the fixed GitHub branch" "$(git -C $A rev-parse gh-infected)" "$(git -C $T/o.git rev-parse gh-infected)"
ok "tag kept without --permanent" "$(git -C $A tag -l evidence)" evidence
ok "backups are read-only" "$(find $BK -name '*.quarantined' -perm -u+w | wc -l | tr -d ' ')" 0
ok "every changed working file has a backup" "$(find $BK -name "*.quarantined" | wc -l | tr -d " ")" 7

AFTER=$(eng | /usr/bin/python3 -I -c 'import json,sys;d=json.load(sys.stdin);print(sorted({f["where"] for f in d["active"]}))')
ok "only the tag and the vendored file remain flagged" "$AFTER" "['branch:refs/tags/evidence', 'folder']"

cln --permanent >/dev/null
ok "tag deleted with --permanent" "$(git -C $A tag -l evidence)" ""
eng >/dev/null
ok "after permanent clean only the vendored false alarm remains (1 rule)" "$(eng | count active)" 1

# false alarms that must stay quiet
F="$T/fa"; mkdir -p "$F/proj/scripts" "$F/incident-quarantine-1/x"
print -r -- 'grep -rn "runOn.*folderOpen" .vscode && echo "found auto-run task"' > "$F/proj/scripts/malware-scan.sh"
print -r -- '{"tasks":[{"runOptions":{"runOn":"folder''Open"}}]}' > "$F/incident-quarantine-1/x/tasks.json.payload"
print -r -- "x$PAD$LOADER" > "$F/incident-quarantine-1/x/init"
mkdir -p "$F/proj/.vscode"; print -r -- '{"tasks":[{"runOptions":{"runOn":"folder''Open"}}]}' > "$F/proj/.vscode/tasks.json"
FA=$(/usr/bin/python3 -I "$RES/engine.py" full --watch "$F" --state "$T/fa.json" --rules "$RES/rules.json" | /usr/bin/python3 -I -c 'import json,sys;print(sorted({f["path"] for f in json.load(sys.stdin)["active"]}))')
ok "scanner script and quarantine folder ignored, real tasks.json still caught" "$FA" "['.vscode/tasks.json']"
echo "=== $pass passed, $fail failed"
