# Guest bootstrap scripts

Open **Settings → Set up a guest** in the host UI. Enter the guest-reachable
broker host and optionally the container name, then copy the Linux or Windows
command. **Execute it in the guest account, never on the broker host.** Stop
guest Cline first: setup updates its provider settings and cannot coordinate
with a running Cline writer.

The commands download a complete script before executing it. **Inspect script**
opens the same plain-text script for review. Bootstrap is trust-on-first-use:
HTTP cannot authenticate the first script, binary, or CA. Only use a trusted
host/isolated network. No firewall, machine environment, system trust store,
privilege escalation, or execution-policy bypass is performed.

## What happens

1. Detect guest OS and architecture (Linux or Windows, x86_64 or aarch64).
2. Fetch the exact build from `/bootstrap/fz?target=linux-x86_64` (for example).
   A host binary is used only if **both** platform and architecture match.
   Downloads bypass proxies and do not follow redirects.
3. Invoke `fz setup --shell sh|powershell --persist-profile` with the chosen
   broker/name. This reuses CA fetching, fake-key configuration, proxy identity,
   Cline provider merging and guest announcement. Real credentials stay hosted.
4. Save `fz` beside the guest config. The environment includes both proxy
   variable cases, FZ_HOST/FZ_BROKER, broker/loopback NO_PROXY exclusions, runtime
   CA variables, and configured fake keys. Existing NO_PROXY entries survive.
5. Approve/pin the guest in the host Inbox. Setup does not approve itself.

If the build is missing, the script stops before profile/user-environment
changes. Build it in a trusted environment, put it into the broker data
directory's `guest-bin/` as `fz-linux-x86_64`, `fz-linux-aarch64`,
`fz-windows-x86_64.exe` or `fz-windows-aarch64.exe`, and restart the broker
in a planned maintenance window (the file list is currently startup-scanned).
No compiler is installed and no external release fallback is downloaded.
Linux build labels do not guarantee libc compatibility: use a build suitable
for the guest distro. A binary that cannot run fails before setup.

## Linux persistence

Run as the guest user, without sudo. Configuration defaults to
`${XDG_CONFIG_HOME:-$HOME/.config}/friendzone`. A managed hook sources
`activate.sh` from `.profile`, `.bashrc`, existing `.bash_profile`/`.bash_login`,
and `${ZDOTDIR:-$HOME}/.zshenv`. Existing file contents are preserved and a
`.friendzone-backup` copy is made before the first edit. Reruns do not append
the same hook twice. Simple existing source lines for the same environment
file are upgraded in place (including common `$HOME`/`~/` forms); arbitrary
compound shell code is not rewritten. Changing configuration directories with an old managed
hook is rejected rather than silently adding competing hooks.

`activate.sh` loads `friendzone-env.sh` and sets BASH_ENV to a managed wrapper.
The wrapper sources the original BASH_ENV (recorded on first installation),
then Friendzone's environment. This covers non-interactive bash launched from
an activated parent. Zsh reads `.zshenv` for interactive and non-interactive
shells (unless startup files are explicitly disabled).

**Limits:** a process cannot alter its parent's environment. The installer
prints a source command; run it in the existing terminal, or start a new login
shell. Plain non-interactive `sh`, cron, systemd, SSH command runners and other
services do not universally read user profiles. Launch those through an
explicitly activated shell, or set their environment in their own launcher.
Custom startup-file early returns and explicit environment clearing can also
skip hooks. Do not use guest shell configuration as network enforcement.

Rollback: remove only the marked Friendzone hook from the affected profiles
(or restore each `.friendzone-backup` **only if you have not edited that file
since**). Restore the previous BASH_ENV recorded in `previous-bash-env`, start
a clean login/session, and remove the generated activation files when no
profile references them. Do not delete unrelated shell configuration.

## Windows persistence

Windows PowerShell 5.1 and PowerShell 7 on Windows are supported. The script
uses direct .NET HTTP, so it does not depend on the PowerShell `curl` alias or
proxy auto-detection. Normal script execution policy applies; review and allow
the saved script according to your policy rather than using a blanket bypass.

Files live in `%APPDATA%\friendzone`. `friendzone-env.ps1` activates process
environment. Persistence writes **User**, never **Machine**, environment
variables; interactive and non-interactive programs launched with a fresh
user environment receive them. Windows variable names are case-insensitive.
Existing NO_PROXY exclusions are merged. `user-environment-backup.json` records
previous values before any write; reruns preserve the original rollback values.

The installer activates its current PowerShell process; new children inherit
that environment. Existing processes do not change. **Sign out and back in**
to refresh GUI launchers reliably, and restart agents/hubs. PowerShell profiles
are not required, so `-NoProfile` programs still inherit fresh user environment.

To undo saved user environment, execute in the guest:

```powershell
& "$env:APPDATA\friendzone\persist-environment.ps1" `
  -BackupPath "$env:APPDATA\friendzone\user-environment-backup.json" -Restore
```

Rollback restores only values that still equal Friendzone's applied value;
externally changed variables are preserved with a warning. Restart/sign in to
drop inherited process variables too. CA files and Cline provider settings
are separate from environment rollback.

## Explicit script API

`GET /bootstrap/setup?shell=sh&broker=http%3A%2F%2FHOST%3A8082&container=NAME`
serves POSIX shell; `shell=powershell` serves PowerShell. `bash`, `zsh`,
`/bin/zsh`, and `pwsh` are accepted selectors. Do not use a bare `?$SHELL`:
an explicit encoded parameter is unambiguous. The required `broker` is a plain
origin, not inferred from an untrusted Host header or the UI origin. Queries
are data-quoted, unknown shells/targets are rejected, and script reads make
no permission changes. These routes live on the guest bootstrap listener;
management routes remain host-only.

## Validation safety

Tests use temporary homes, explicit profile paths, local fixture servers and
isolated child environments. Windows user-environment adapters are mocked in
memory. The full installer is not executed against the developer's real user,
registry, CA store, network settings, or live broker. Actual Windows user
registry persistence and Linux distro-specific startup behavior require a
disposable guest acceptance test before using this on a valuable account.