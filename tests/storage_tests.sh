#!/bin/zsh
# Cleanup: archive to a local bare "GitHub" and the clean safety checks. Never touches real repos or Notes.
# Usage: tests/storage_tests.sh /path/to/scratch
set -u
S=${1:?scratch dir}; T=$S/rg-storage; rm -rf $T; mkdir -p $T
cd "$(dirname "$0")/.."
pass=0; fail=0
ok() { if [[ "$2" == "$3" ]]; then pass=$((pass+1)); print "ok   $1"; else fail=$((fail+1)); print "FAIL $1: got '$2' want '$3'"; fi }
g() { git -c core.hooksPath=/dev/null -c user.name=t -c user.email=t@t "$@"; }
st() { /usr/bin/python3 -I Resources/storage.py "$@"; }
res() { print -r -- "$1" | tail -1 | python3 -I -c "import json,sys;d=json.load(sys.stdin);print($2)"; }
echo '{"findings": {}}' > $T/state.json

# project with a remote, unsaved work, a .env, a local-only branch, and a branch the remote moved past
g init -q --bare $T/remote.git
g init -q -b main $T/proj && cd $T/proj
echo 'console.log(1)' > index.js; echo 'node_modules/' > .gitignore; g add -A; g commit -qm one
g remote add origin $T/remote.git; g push -q origin main
g switch -qc feature; echo f > f.txt; g add -A; g commit -qm feat; g switch -q main
g clone -q $T/remote.git $T/other && (cd $T/other && echo x > x.txt && g add -A && g commit -qm other && g push -q origin main)
echo 'local' >> index.js; echo 'SECRET=1' > .env; mkdir -p node_modules/a && echo 1 > node_modules/a/i.js
cd - >/dev/null

R=$(st archive --project $T/proj --state $T/state.json --no-notes --remove delete)
ok "archive succeeded"              "$(res "$R" "d['ok']")" True
ok "folder removed"                 "$([[ -e $T/proj ]] && echo yes || echo no)" no
ok "feature branch on remote"       "$(g --git-dir=$T/remote.git branch --list feature | wc -l | tr -d ' ')" 1
ok "moved branch pushed renamed"    "$(g --git-dir=$T/remote.git branch --list 'main-local-*' | wc -l | tr -d ' ')" 1
ok "remote main not overwritten"    "$(g --git-dir=$T/remote.git log -1 --format=%s main)" other
AB=$(g --git-dir=$T/remote.git branch --list 'repoguard-archive-*' | tr -d ' *')
ok "unsaved work on archive branch" "$(g --git-dir=$T/remote.git show $AB:index.js | tail -1)" local
ok ".env never committed"           "$(g --git-dir=$T/remote.git ls-tree -r --name-only $AB | grep -c '^\.env$')" 0
ok "node_modules never committed"   "$(g --git-dir=$T/remote.git ls-tree -r --name-only $AB | grep -c node_modules)" 0

# infected project is refused and kept
g init -q -b main $T/bad && (cd $T/bad && echo 1 > a.js && g add -A && g commit -qm a)
python3 -I -c "import json;json.dump({'findings':{'k':{'root':'$(cd $T/bad && pwd -P)','path':'a.js'}}},open('$T/state-bad.json','w'))"
R=$(st archive --project $T/bad --state $T/state-bad.json --no-notes --remove delete)
ok "infected project refused"       "$(res "$R" "d['ok']")" False
ok "infected project kept"          "$([[ -d $T/bad ]] && echo yes || echo no)" yes

# git-ignored data that isn't rebuildable stops removal
g init -q --bare $T/r2.git; g init -q -b main $T/data && cd $T/data && echo '*.sqlite' > .gitignore && echo 1 > a.js && g add -A && g commit -qm a && g remote add origin $T/r2.git && echo db > local.sqlite; cd - >/dev/null
R=$(st archive --project $T/data --state $T/state.json --no-notes --remove delete)
ok "ignored data stops removal"     "$(res "$R" "d['ok']")" False
ok "  and says which file"          "$(res "$R" "'local.sqlite' in d['error']")" True
ok "  folder kept"                  "$([[ -f $T/data/local.sqlite ]] && echo yes || echo no)" yes

# no remote and repo creation off: refused
g init -q -b main $T/norem && (cd $T/norem && echo 1 > a.js && g add -A && g commit -qm a)
R=$(st archive --project $T/norem --state $T/state.json --no-notes --remove delete)
ok "no remote without create-repo"  "$(res "$R" "d['ok']")" False
ok "  folder kept"                  "$([[ -d $T/norem ]] && echo yes || echo no)" yes

# clean: only allowed locations
mkdir -p $T/victim; echo keep > $T/victim/file
cat > $T/items.json <<J
[{"id":"x","category":"System","title":"evil","path":"$T/victim","size":1,"detail":"","selected":true,"kind":"contents"},
 {"id":"y","category":"Old projects","title":"evil2","path":"$T","size":1,"detail":"","selected":true,"kind":"rebuild","paths":["$T/victim"]}]
J
R=$(st clean --items $T/items.json)
ok "clean refuses unknown folders"  "$(res "$R" "[r['ok'] for r in d['results']]")" "[False, False]"
ok "  file untouched"               "$(cat $T/victim/file)" keep
mkdir -p $T/p2/node_modules/z && echo 1 > $T/p2/node_modules/z/a.js && echo src > $T/p2/index.js
cat > $T/items2.json <<J
[{"id":"z","category":"Old projects","title":"p2","path":"$T/p2","size":1,"detail":"","selected":true,"kind":"rebuild","paths":["$T/p2/node_modules"]}]
J
R=$(st clean --items $T/items2.json)
ok "clean removes node_modules"     "$([[ -e $T/p2/node_modules ]] && echo yes || echo no)" no
ok "  source kept"                  "$(cat $T/p2/index.js)" src
print "=== $pass passed, $fail failed"
