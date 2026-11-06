#!/bin/zsh
# End-to-end tests using fake repos with harmless copies of the malware's patterns.
# Usage: tests/run_tests.sh SCRATCH_DIR
ROOT=${0:A:h:h}; T=${1:?scratch dir required}/rgtest; mkdir -p "$T"
export SCAN_NO_NOTIFY=1
RES="$ROOT/Resources"; W="$T/watch"; mkdir -p "$W"; ST="$T/state.json"; LOG="$T/log"; pass=0; fail=0
D="/Applications/GitHub Desktop.app/Contents/Resources/app/git/bin/git"
eng() { /usr/bin/python3 -I "$RES/engine.py" "$1" --watch "$W" --state "$ST" --rules "$RES/rules.json" --log "$LOG" "${@:2}"; }
ev() { print -l -- "$@" | /usr/bin/python3 -I -c 'import json,sys;print(json.dumps(sys.stdin.read().splitlines()))' > "$T/p.json"; eng event --paths-file "$T/p.json"; }
count() { /usr/bin/python3 -I -c 'import json,sys;d=json.load(sys.stdin);print(len(d[sys.argv[1]]))' "$1"; }
ok() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1: expected $3, got $2"; fi; }
cfg() { git -C "$1" config user.name t; git -C "$1" config user.email t@t; }
bad_postcss() { /usr/bin/python3 -I -c "open('$1','w').write('export default {};'+' '*150+\"var z = '-6752-3';\n\")"; }

git init -q --bare --initial-branch=main "$T/o.git"; git clone -q "$T/o.git" "$T/dev" 2>/dev/null; cfg "$T/dev"
echo 'export default {};' > "$T/dev/postcss.config.mjs"; git -C "$T/dev" add -A; git -C "$T/dev" commit -qm clean; git -C "$T/dev" push -q origin main
git clone -q "$T/o.git" "$W/app" 2>/dev/null; cfg "$W/app"
ok "first full scan of a clean repo" "$(eng full | count active)" 0

mkdir -p "$T/dev/.vscode"; print '{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}' > "$T/dev/.vscode/tasks.json"; bad_postcss "$T/dev/postcss.config.mjs"; git -C "$T/dev" add -A; git -C "$T/dev" commit -qm infected; git -C "$T/dev" push -q origin main
BEFORE=$(git -C "$W/app" rev-parse HEAD); git -C "$W/app" fetch -q
R=$(ev "$W/app/.git/refs/remotes/origin/main" "$W/app/.git/FETCH_HEAD")
[ "$(print -r -- "$R" | count new)" -gt 0 ] && ok "fetch alone warns BEFORE any merge" yes yes || ok "fetch alone warns BEFORE any merge" no yes
ok "fetch left the user's files untouched" "$(git -C "$W/app" rev-parse HEAD)" "$BEFORE"

git -C "$T/dev" rm -rq .vscode; echo 'export default {};' > "$T/dev/postcss.config.mjs"; git -C "$T/dev" add -A; git -C "$T/dev" commit -qm cleaned; git -C "$T/dev" push -q origin main; git -C "$W/app" fetch -q
R=$(ev "$W/app/.git/refs/remotes/origin/main")
ok "clean follow-up commit clears the branch warning" "$(print -r -- "$R" | count active)" 0
git -C "$W/app" merge -q --ff-only origin/main

mkdir -p "$T/keep"; bad_postcss "$W/app/tailwind.config.js"
R=$(ev "$W/app/tailwind.config.js")
[ "$(print -r -- "$R" | count new)" -gt 0 ] && ok "uncommitted infected file is flagged" yes yes || ok "uncommitted infected file is flagged" no yes
echo 'module.exports = {};' > "$W/app/tailwind.config.js"
ok "fixing the file clears the warning" "$(ev "$W/app/tailwind.config.js" | count active)" 0

mkdir -p "$W/from-zip/public/fonts"; print 'function x(){}' > "$W/from-zip/public/fonts/fa-brand-400.orc"
print 'function(){ var a=require("x") }' > "$W/from-zip/public/fonts/logo.woff2"
R=$(ev "$W/from-zip")
[ "$(print -r -- "$R" | count new)" -ge 2 ] && ok "unzipped non-git folder: fake font and .orc flagged" yes yes || ok "unzipped non-git folder: fake font and .orc flagged" no yes
rm -r "$W/from-zip"; ok "deleting the folder clears its warnings" "$(eng full | count active)" 0

# A repo from a ZIP can carry a hostile .git/config. These traps leave evidence if anything runs them.
TRAP="$T/trap.sh"; print "#!/bin/sh\ntouch '$T/TRAP_RAN'" > "$TRAP"; chmod +x "$TRAP"
git init -q "$W/evil" 2>/dev/null; cfg "$W/evil"; echo x > "$W/evil/a.txt"; git -C "$W/evil" add -A; git -C "$W/evil" commit -qm a
git -C "$W/evil" config core.fsmonitor "$TRAP"; git -C "$W/evil" config core.sshCommand "$TRAP"; git -C "$W/evil" config core.pager "$TRAP"; git -C "$W/evil" config core.hooksPath "$T"
print "#!/bin/sh\ntouch '$T/TRAP_RAN'" > "$W/evil/.git/hooks/post-checkout"; chmod +x "$W/evil/.git/hooks/post-checkout"
[ "$(eng full | count active)" -ge 1 ] && ok "malicious .git/config setting is flagged" yes yes || ok "malicious .git/config setting is flagged" no yes
ok "the trap really fires under plain git (control)" "$(git -C "$W/evil" status >/dev/null 2>&1; [ -e "$T/TRAP_RAN" ] && echo fired || echo silent)" fired
rm -f "$T/TRAP_RAN"; ev "$W/evil/.git/config" "$W/evil/.git/HEAD" "$W/evil/a.txt" >/dev/null; eng full >/dev/null
ok "the scanner did not run any trap" "$([ -e "$T/TRAP_RAN" ] && echo ran || echo no)" no
rm -rf "$W/evil"; eng full >/dev/null

mkdir -p "$T/locked"; chmod 000 "$T/locked"
/usr/bin/python3 -I "$RES/engine.py" full --watch "$T/locked" --state "$T/ls.json" --rules "$RES/rules.json" >/dev/null 2>&1; RC=$?
chmod 755 "$T/locked"; [ "$RC" != 0 ] && ok "unreadable folder fails loudly, not clean" yes yes || ok "unreadable folder fails loudly, not clean" no yes

mkdir -p "$W/app/node_modules/pkg"; bad_postcss "$W/app/node_modules/pkg/index.js"
ok "node_modules is skipped by the folder watch" "$(ev "$W/app/node_modules/pkg/index.js" | count active)" 0
rm -rf "$W/app/node_modules"

bad_postcss "$W/app/x.js"; ev "$W/app/x.js" >/dev/null
/usr/bin/python3 -I "$RES/engine.py" ignore-active --state "$ST" >/dev/null
ok "false alarm stays silent for the same version" "$(ev "$W/app/x.js" | count active)" 0
/usr/bin/python3 -I -c "open('$W/app/x.js','a').write('export const a=1;'+' '*150+\"var z = '-6752-3';\n\")"
ok "changed version warns again (two rules match)" "$(ev "$W/app/x.js" | count active)" 2
rm "$W/app/x.js"; eng full >/dev/null

# Global hook through GitHub Desktop's bundled git.
git -C "$T/dev" checkout -q -b desk; bad_postcss "$T/dev/postcss.config.mjs"; git -C "$T/dev" add -A; git -C "$T/dev" commit -qm d2; git -C "$T/dev" push -q origin desk
git clone -q -b main "$T/o.git" "$T/dk" 2>/dev/null
if [ -x "$D" ]; then
  H=$("$D" -C "$T/dk" pull --quiet --no-rebase origin desk 2>&1)
  print -r -- "$H" | /usr/bin/grep -q 'MALWARE' && ok "GitHub Desktop's git runs the global scan hook" yes yes || ok "GitHub Desktop's git runs the global scan hook" no yes
fi

# The app itself, watching live through FSEvents.
BIN="$ROOT/build/RepoGuard.app/Contents/MacOS/RepoGuard"
if [ -x "$BIN" ]; then
  LW="$T/live"; LS="$T/livesup"; mkdir -p "$LW/proj" "$LS"; git init -q "$LW/proj"; cfg "$LW/proj"; echo ok > "$LW/proj/a.txt"; git -C "$LW/proj" add -A; git -C "$LW/proj" commit -qm a
  REPOGUARD_TEST=1 REPOGUARD_WATCH="$LW" REPOGUARD_SUPPORT="$LS" REPOGUARD_LOG="$T/livelog" "$BIN" & PID=$!
  for i in {1..20}; do [ -s "$LS/state.json" ] && break; /bin/sleep 0.5; done
  ok "app starts and baselines the folder" "$([ -s "$LS/state.json" ] && echo yes || echo no)" yes
  bad_postcss "$LW/proj/postcss.config.mjs"
  for i in {1..24}; do /usr/bin/grep -q THREAT "$T/livelog" 2>/dev/null && break; /bin/sleep 0.5; done
  ok "running app detects a new infected file by itself" "$(/usr/bin/grep -c 'THREAT' "$T/livelog" 2>/dev/null | head -1)" 2
  /usr/bin/grep -c . "$T/livelog" >/dev/null; kill $PID 2>/dev/null; wait $PID 2>/dev/null
fi
echo "=== $pass passed, $fail failed"
