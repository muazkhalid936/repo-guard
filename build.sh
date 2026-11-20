#!/bin/sh
# Builds build/RepoGuard.app. Run ./build.sh install to also copy it to ~/Applications.
set -e
cd "$(dirname "$0")"
APP=build/RepoGuard.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" build/tmp
swiftc -O -swift-version 5 -target arm64-apple-macos13 -framework AppKit -framework SwiftUI -framework Charts -framework CoreServices \
  Sources/main.swift Sources/Model.swift Sources/Views.swift Sources/Servers.swift Sources/GitHubWatch.swift Sources/MacScan.swift Sources/Storage.swift Sources/DiskMap.swift Sources/CleanPreview.swift -o "$APP/Contents/MacOS/RepoGuard"
if [ ! -f build/tmp/AppIcon.icns ] || [ tools/make_icon.swift -nt build/tmp/AppIcon.icns ]; then
  swiftc -swift-version 5 -framework AppKit tools/make_icon.swift -o build/tmp/make_icon
  build/tmp/make_icon build/tmp/AppIcon.iconset
  iconutil -c icns build/tmp/AppIcon.iconset -o build/tmp/AppIcon.icns
fi
cp build/tmp/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/engine.py Resources/cleaner.py Resources/server_agent.py Resources/github_watch.py Resources/mac_agent.py Resources/storage.py Resources/rules.json "$APP/Contents/Resources/"
codesign --force --deep --sign - "$APP"
echo "built $APP"
if [ "$1" = "dmg" ]; then
  # Disk image with the app and an Applications shortcut to drag it onto.
  VER=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$APP/Contents/Info.plist")
  STAGE=build/tmp/dmg; DMG=build/release/RepoGuard-$VER.dmg
  rm -rf "$STAGE" "$DMG"; mkdir -p "$STAGE" build/release
  ditto "$APP" "$STAGE/RepoGuard.app"
  ln -s /Applications "$STAGE/Applications"
  hdiutil create -quiet -volname "RepoGuard $VER" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG"
  rm -rf "$STAGE"
  echo "built $DMG"
fi
if [ "$1" = "install" ]; then
  mkdir -p "$HOME/Applications"
  ditto "$APP" "$HOME/Applications/RepoGuard.app"
  echo "installed $HOME/Applications/RepoGuard.app"
fi
