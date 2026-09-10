# Set up a guest

Open **Settings → Guests** on the host. Choose the guest platform/name, copy
the curl command, and run it in the guest terminal. The command only downloads
a script. Inspect it if desired, then run the separate command shown below it.
No guest fz binary, architecture-specific build or compiler is involved.

Linux requires `curl` and Python 3.6+ (standard library only). Windows requires
`curl.exe` and PowerShell 5.1 or 7. The scripts do not install these dependencies.

```sh
curl --noproxy '*' -fsS 'http://HOST_IP:8082/bootstrap/setup?shell=sh&container=reviewer' -o friendzone-setup.sh
sh ./friendzone-setup.sh
```

```powershell
curl.exe --noproxy "*" -fsS 'http://HOST_IP:8082/bootstrap/setup?shell=powershell&container=reviewer' -o friendzone-setup.ps1
& .\friendzone-setup.ps1
```

Run the second command only after the download succeeds. Do not use curl's
redirect-following flag. Windows execution policy still applies; this feature
does not weaken or bypass it. Use a trusted host/network: initial HTTP is
trust-on-first-use, not an authenticated software distribution channel.

## What changes

The script contains a snapshot of the public CA, proxy port and fake keys from
the broker at download time. It registers the guest directly with the broker,
then writes the guest account's environment and Cline settings. Refetch before
rerunning if the CA, broker address or fake keys have changed. Downloading a
script never registers or approves a guest; the host Inbox still owns approval.

The environment contains FZ_HOST/FZ_BROKER, HTTP_PROXY/HTTPS_PROXY, CA variables
for common runtimes, and fake provider keys. NO_PROXY/no_proxy includes the
broker host, localhost, 127.0.0.1, ::1 and [::1], preserving existing exclusions.
Real credentials and OAuth refresh tokens never enter the script.

If Cline credentials are configured on the broker, the script merges the fake
key into the guest's `.cline/data/settings/providers.json`. **Close guest Cline
before running the script** because it writes this same file. The merge keeps
model choice, other providers, and last-used provider; it removes stale Cline
OAuth fields so they cannot override the fake key. Invalid provider JSON fails
before environment/profile writes. Existing provider files get a backup.

The script does not modify firewall rules or the system CA store. Runtime CA
variables provide trust for supported clients; applications that ignore them
need their own trust configuration. Network confinement remains host-enforced;
see [NETWORK-ISOLATION.md](NETWORK-ISOLATION.md).

## Linux persistence

Run as the guest user without sudo. Files are written under
`${XDG_CONFIG_HOME:-$HOME/.config}/friendzone`. Managed hooks source
`activate.sh` from `.profile`, `.bashrc`, existing `.bash_profile`/`.bash_login`,
and `${ZDOTDIR:-$HOME}/.zshenv`. Existing contents are retained; the first edit
creates `.friendzone-backup` copies. Identical hooks are not duplicated. Simple
existing source lines are upgraded in place; arbitrary compound shell code is
not rewritten. A conflicting managed hook fails instead of adding a second one.

The activation script loads `friendzone-env.sh` and exports BASH_ENV pointing
to a wrapper that preserves the original BASH_ENV. Non-interactive bash inherits
it from an activated parent. Zsh reads `.zshenv` for interactive/non-interactive
shells unless startup files are disabled. Plain non-interactive sh, cron,
systemd and other services require an explicitly activated launcher.

A child cannot alter its parent shell. Use the printed source command in the
current terminal, or start a new login shell, then restart guest Cline.

Rollback: remove only the marked hooks, restore the original BASH_ENV recorded
in `previous-bash-env`, and start a clean session. Restore profile backups only
if you have not edited those profiles since installation. CA/provider files
are separate; do not overwrite unrelated later edits.

## Windows persistence

Files live in `%APPDATA%\friendzone`. The script writes **User**, never
**Machine**, environment values and activates its PowerShell process. Its
children inherit the new environment; existing applications do not. Sign out
and back in for GUI launchers, and restart guest agents/hubs. PowerShell
profiles are not required, so non-interactive and `-NoProfile` processes still
inherit values from a fresh launcher.

Before user-environment writes, `user-environment-backup.json` records original
and applied values. Reruns retain the originals and skip unchanged writes. On
write failure, completed writes are rolled back. To undo in the guest:

```powershell
& "$env:APPDATA\friendzone\persist-environment.ps1" `
  -BackupPath "$env:APPDATA\friendzone\user-environment-backup.json" -Restore
```

Rollback preserves externally changed variables with a warning. Start a fresh
session afterward; already-inherited environment values do not disappear.

## Script endpoint

`GET /bootstrap/setup?shell=sh&container=NAME` serves a shell script;
`shell=powershell` serves PowerShell. `bash`, `zsh`, `/bin/zsh`, and `pwsh` are
accepted. Omit container to use the guest hostname at execution time.

The bootstrap listener's HTTP Host determines the broker origin; it is strictly
validated and encoded as data, never interpolated into code. An explicit
`broker=` origin is supported for alternate routing. Forwarded headers are not
trusted. Scripts are no-store and only contain the public configuration snapshot.
Management routes remain unavailable on this listener.

## Validation boundary

Tests execute script configuration against explicit temporary homes and local
fixtures. Windows environment writes are mocked in memory. The developer's
real profiles, user registry, trust store, network settings and live broker
are never used as installation test targets. Native zsh startup and real
Windows persistence still require acceptance testing in a disposable guest.