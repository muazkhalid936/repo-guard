# RepoGuard

Mac app with a Dashboard, Threats, Repositories, Servers, Activity and Settings window, plus a menu bar icon that keeps running after the window closes. On first launch it asks which folders hold your repos, then watches them and warns when suspicious code arrives from any source: GitHub Desktop, VS Code, the terminal, or an unzipped folder. It reads files and git objects as data and never runs what it scans.

## Build and install

```bash
./build.sh install
open ~/Applications/RepoGuard.app
```

Requires Xcode Command Line Tools, not full Xcode. Don't put this project inside a watched folder, because `rules.json` contains malware signatures and would trigger alerts.

## What it scans

- **Fetches and pulls:** every branch tip when it changes, including new commits that added and removed something.
- **Files on disk:** changed files and new folders, committed or not. `node_modules`, build output, quarantine folders and files over 5 MB (content only) are skipped.
- **Repo settings:** `.git/config` values that can run programs, and executable hooks.
- **VS Code autorun:** `.vscode/settings.json` and `tasks.json` entries that run a task when a folder opens.

Install scripts, force-pushes and timezone-mismatched commits are logged for review without a popup.

A full scan remembers files it found clean (by size, change time and inode) and git objects it already checked, so repeat scans only read what changed. Every file is read again at least once a day, and whenever the rules change. At launch the app shows the last saved results immediately, with a progress bar while the next scan runs.

## Removing malware

**Remove Malware** cuts the malicious lines out of files instead of deleting them, so the project keeps working. Every original is backed up to `~/Library/Application Support/RepoGuard/quarantine` first, and each cleaned file is syntax-checked. Git history is left alone; infected branch tips get a new cleanup commit on top.

Choosing **Fix GitHub** also pushes those cleanup commits to the infected branches on GitHub. It never force-pushes, and protected branches are listed for you to fix by hand.

## GitHub live watch

Optional, on by default, and switched off in Settings. Every few minutes it checks the repos your `gh` login can see for new pushes, using conditional requests that don't use up the API rate limit, and checks only the files that changed. With auto-fix on, a push that brings malware gets a cleanup commit through the GitHub API. Branches that were already infected before the watch started are only fixed when you choose **Fix All on GitHub**.

## Servers

Add Linux servers that sign in with a password, a `.pem` key file, or AWS EC2 Instance Connect (servers can also be imported from an AWS profile). A scan uploads a small Python checker over SSH, runs it from a temporary folder, and deletes it afterwards; nothing is installed. It checks:

- project files in the folders you choose, using the same rules as the Mac
- autostart entries: cron, rc files, shell profiles, `ld.so.preload`, systemd units, pm2, recently changed `authorized_keys`
- running processes: miners, known malware commands, and programs running from temp folders

**Remove Threats** backs up everything it changes to `/var/backups/repoguard/<time>` on the server. Passwords are kept in the macOS Keychain.

## Updating rules

Edit `Resources/rules.json`, run `./build.sh install`, restart the app, then choose **Scan Now**.

## Tests

```bash
./build.sh
tests/run_tests.sh /path/to/scratch                      # scanning
REPOGUARD_TEST=1 tests/clean_tests.sh /path/to/scratch   # removing malware, fixing branches
tests/github_watch_tests.sh /path/to/scratch             # GitHub watch, against a local mock API
```

Tests use fake repos containing harmless copies of the malware's patterns. Delete `/path/to/scratch/rgtest` before rerunning `run_tests.sh`.

## Checking the design

```bash
REPOGUARD_SNAPSHOT=/path/to/output build/RepoGuard.app/Contents/MacOS/RepoGuard
```

This renders every screen to PNG using sample data, without opening a window. Glass effects and form controls only render in a real window.

## Limits

It warns after files arrive, so it can't stop them landing. It matches known techniques and can miss a new attack. It doesn't inspect inside npm packages. Malware already running on the Mac could stop it.

## Uninstall

Turn off **Start at login** in Settings, quit the app, then delete `~/Applications/RepoGuard.app`, `~/Library/Application Support/RepoGuard` and `~/Library/Logs/RepoGuard.log`.
