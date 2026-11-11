#!/bin/sh
# Builds build/RepoGuard.app. Run ./build.sh install to also copy it to ~/Applications.
set -e
cd "$(dirname "$0")"
APP=build/RepoGuard.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" build/tmp
swiftc -O -swift-version 5 -target arm64-apple-macos13 -framework AppKit -framework SwiftUI -framework Charts -framework CoreServices \
  Sources/main.swift Sources/Model.swift Sources/Views.swift Sources/Servers.swift Sources/GitHubWatch.swift -o "$APP/Contents/MacOS/RepoGuard"
if [ ! -f build/tmp/AppIcon.icns ] || [ tools/make_icon.swift -nt build/tmp/AppIcon.icns ]; then
  swiftc -swift-version 5 -framework AppKit tools/make_icon.swift -o build/tmp/make_icon
  build/tmp/make_icon build/tmp/AppIcon.iconset
  iconutil -c icns build/tmp/AppIcon.iconset -o build/tmp/AppIcon.icns
fi
cp build/tmp/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/engine.py Resources/cleaner.py Resources/server_agent.py Resources/github_watch.py Resources/rules.json "$APP/Contents/Resources/"
codesign --force --deep --sign - "$APP"
echo "built $APP"
if [ "$1" = "install" ]; then
  mkdir -p "$HOME/Applications"
  ditto "$APP" "$HOME/Applications/RepoGuard.app"
  echo "installed $HOME/Applications/RepoGuard.app"
fi
