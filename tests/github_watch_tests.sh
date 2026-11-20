#!/bin/zsh
# Tests for the GitHub watch against a local fake GitHub. Usage: tests/github_watch_tests.sh SCRATCH_DIR
ROOT=${0:A:h:h}; T=${1:?scratch dir required}/rgwatch; rm -rf "$T"; mkdir -p "$T/gh/acme"
RES="$ROOT/Resources"; pass=0; fail=0; PORT=18765
export SCAN_NO_NOTIFY=1 REPOGUARD_ALLOW_FETCH=1  # the fake infected repos below must not trip the global git hooks
ok() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "PASS $1"; else fail=$((fail+1)); echo "FAIL $1: expected [$3], got [$2]"; fi; }
PAD=$(printf ' %.0s' {1..150}); LOADER="var z = '-67""52-3';"
export REPOGUARD_GITHUB_API=http://127.0.0.1:$PORT REPOGUARD_GITHUB_TOKEN=test MOCK_PROTECTED=locked
B="$T/gh/acme/app.git"; git init -q --bare --initial-branch=main "$B"
W="$T/work"; git clone -q "$B" "$W" 2>/dev/null; cd "$W"; git config user.name dev; git config user.email d@d
print -r -- "export default { plugins: {} };" > postcss.config.mjs; print -r -- '{"name":"x","scripts":{"dev":"next dev"}}' > package.json
print -r -- "node_modules" > .gitignore; mkdir -p src; print -r -- "export const a = 1;" > src/a.js
git add -A; git commit -qm c1; git push -q origin main
# a branch already infected before watching starts, and a protected one
git checkout -q -b old-infected; print -r -- "x$PAD$LOADER" > init; git add -A; git commit -qm old; git push -q origin old-infected
git checkout -q main; git checkout -q -b locked; git push -q origin locked; git checkout -q main
cd /
/usr/bin/python3 -I "$ROOT/tests/mock_github.py" $PORT "$T/gh" & MOCK=$!; trap "kill $MOCK 2>/dev/null" EXIT; sleep 1
poll() { /usr/bin/python3 -I "$RES/github_watch.py" poll --rules "$RES/rules.json" --state "$T/state.json" --log "$T/log" "$@"; }
j() { /usr/bin/python3 -I -c "import json,sys;d=json.loads(sys.stdin.read());print(eval(sys.argv[1]))" "$1"; }

R=$(poll --fix); print -r -- "$R" > "$T/r1.json"
ok "first check: existing infection reported" "$(j "[f['branch'] for f in d['findings']]" <<< "$R")" "['old-infected']"
ok "first check: existing infection not auto-fixed" "$(j "len(d['fixed'])" <<< "$R")" 0
ok "first check: no popup for old infections" "$(j "len(d['new_findings'])" <<< "$R")" 0

R=$(poll --fix)
ok "no change: GitHub says not modified" "$(j "d['changed']" <<< "$R")" "[]"

# the worm pushes to main: hidden loader in a config + a VS Code auto-run task + a real change
cd "$W"; git pull -q origin main 2>/dev/null
print -r -- "export default { plugins: {} };$PAD$LOADER" > postcss.config.mjs
mkdir -p .vscode public/fonts
print -r -- '{"version":"2.0.0","tasks":[{"label":"x","command":"node ./public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folder''Open"}}]}' > .vscode/tasks.json
print -r -- "function x(){}" > public/fonts/fa-brand-400.orc
print -r -- "export const a = 2;" > src/a.js
git add -A; git commit -qm "fix: bundle id mismatch"; git push -q origin main; BAD=$(git rev-parse HEAD)
# and to the protected branch
git checkout -q locked; print -r -- "x$PAD$LOADER" > init; git add -A; git commit -qm x; git push -q origin locked; git checkout -q main
cd /

R=$(poll --fix); print -r -- "$R" > "$T/r2.json"
ok "new push detected" "$(j "sorted(f['branch'] for f in d['new_findings'])" <<< "$R")" "['locked', 'main']"
ok "main fixed right away" "$(j "[f['branch'] for f in d['fixed']]" <<< "$R")" "['main']"
ok "fix is a commit on top (no force-push)" "$(git -C $B rev-parse main^)" "$BAD"
ok "hidden loader cut, config kept" "$(git -C $B show main:postcss.config.mjs)" "export default { plugins: {} };"
ok "payload and auto-run task deleted" "$(git -C $B ls-tree -r --name-only main | grep -cE '\.orc$|tasks\.json')" 0
ok "real change kept" "$(git -C $B show main:src/a.js)" "export const a = 2;"
ok "protected branch reported, not forced" "$(j "[m.split(':')[1].strip() for m in d['manual']]" <<< "$R")" "['branch is protected on GitHub; fix it with a pull request']"
ok "old infection still only reported" "$(git -C $B ls-tree -r --name-only old-infected | grep -c '^init$')" 1

R=$(poll --fix)
ok "our own fix commit doesn't trigger again" "$(j "len(d['new_findings']) + len(d['fixed'])" <<< "$R")" 0

OLDHEAD=$(git -C $B rev-parse old-infected)
P=$(/usr/bin/python3 -I "$RES/github_watch.py" preview --rules "$RES/rules.json" --state "$T/state.json")
ok "preview changes nothing on GitHub" "$(git -C $B rev-parse old-infected)" "$OLDHEAD"
ok "preview lists both reported branches" "$(j "[b['branch'] for b in d['branches']]" <<< "$P")" "['locked', 'old-infected']"
ok "preview shows init will be deleted" "$(j "[(i['path'], i['action']) for b in d['branches'] if b['branch']=='old-infected' for i in b['items']]" <<< "$P")" "[('init', 'delete')]"
j "[b['id'] for b in d['branches'] if b['branch']=='old-infected']" <<< "$P" | /usr/bin/python3 -I -c "import ast,json,sys;print(json.dumps(ast.literal_eval(sys.stdin.read())))" > "$T/approved.json"
R=$(poll --fix-existing --approved "$T/approved.json")
ok "only the approved branch is touched" "$(j "len(d['manual'])" <<< "$R")" 0
ok "Fix all on GitHub fixes the old infection" "$(git -C $B ls-tree -r --name-only old-infected | grep -c '^init$')" 0
ok "only the protected branch is left" "$(j "[f['branch'] for f in d['findings']]" <<< "$R")" "['locked']"
ok "log records the fix" "$(grep -c 'GITHUB FIXED acme/app main' $T/log)" 1

R=$(poll)
ok "watch without auto-fix only reports" "$(j "len(d['fixed'])" <<< "$R")" 0
echo "=== $pass passed, $fail failed"
