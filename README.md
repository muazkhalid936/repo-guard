# RepoGuard

Mac app with a Dashboard, Threats, Repositories, Activity and Settings window, plus a menu bar icon that keeps running after the window closes. On first launch it asks which folders hold your repos, then watches them and warns when suspicious code arrives from any source: GitHub Desktop, VS Code, the terminal, or an unzipped folder. It reads files and git objects as data and never runs what it scans.

## Build and install

```bash
./build.sh install
open ~/Applications/RepoGuard.app
```

Requires Xcode Command Line Tools, not full Xcode. Don't put this project inside a watched folder, because `rules.json` contains malware signatures and would trigger alerts.

## What it scans

- **Fetches and pulls:** every branch tip when it changes, including new commits that added and removed something.
- **Files on disk:** changed files and new folders, committed or not. `node_modules`, build output and files over 5 MB (content only) are skipped.
- **Repo settings:** `.git/config` values that can run programs, and executable hooks.

Install scripts, force-pushes and timezone-mismatched commits are logged for review without a popup.

## Updating rules

Edit `Resources/rules.json`, run `./build.sh install`, restart the app, then choose **Scan Everything Now**.

## Tests

```bash
./build.sh && tests/run_tests.sh /path/to/scratch
```

Tests use fake repos containing harmless copies of the malware's patterns.

## Checking the design

```bash
REPOGUARD_SNAPSHOT=/path/to/output build/RepoGuard.app/Contents/MacOS/RepoGuard
```

This renders every screen to PNG using sample data, without opening a window.

## Limits

It warns after files arrive, so it can't stop them landing. It matches known techniques and can miss a new attack. It doesn't inspect inside npm packages. Malware already running on the Mac could stop it.

## Uninstall

Turn off **Start at login** in Settings, quit the app, then delete `~/Applications/RepoGuard.app`, `~/Library/Application Support/RepoGuard` and `~/Library/Logs/RepoGuard.log`.
