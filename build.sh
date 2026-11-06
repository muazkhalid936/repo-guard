#!/bin/sh
# Builds build/RepoGuard.app. Run ./build.sh install to also copy it to ~/Applications.
set -e
cd "$(dirname "$0")"
APP=build/RepoGuard.app
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swiftc -O -swift-version 5 -framework AppKit -framework CoreServices Sources/main.swift -o "$APP/Contents/MacOS/RepoGuard"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/engine.py Resources/rules.json "$APP/Contents/Resources/"
codesign --force --deep --sign - "$APP"
echo "built $APP"
if [ "$1" = "install" ]; then
  mkdir -p "$HOME/Applications"
  ditto "$APP" "$HOME/Applications/RepoGuard.app"
  echo "installed $HOME/Applications/RepoGuard.app"
fi
