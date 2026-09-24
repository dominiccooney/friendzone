# Set up a guest

Open **Settings → Guests → Set up guest** on the host. Choose the guest platform/name, copy
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

Setup also installs the [Friendzone Cline plugin](ASYNC-GRAPHQL.md) for async
GraphQL submissions, reviewed Git branch publication, and session updates. The managed file is
`${CLINE_DIR:-~/.cline}/plugins/friendzone.js`; unrelated plugins are preserved.
Restart guest Cline after setup. A compatible Cline plugin host is required;
the installer does not download or upgrade Cline.

The script contains a snapshot of the public CA, proxy port and fake keys from
the broker at download time. It registers the guest directly with the broker,
then writes the guest account's environment, Windows current-user proxy (on
Windows), and Cline settings. Refetch before rerunning if the CA, broker address
or fake keys have changed. Downloading a
script never registers or approves a guest; the host Inbox still owns approval.

When setup runs, the broker identifies the VM by its observed source IP. If that
IP is already uniquely pinned to a guest, that existing guest name is canonical
and setup uses it even when an old downloaded script requested another name.
The script prints the replacement; it never creates a second identity for that
IP. Registration failures now include the exact bootstrap URL, HTTP status, and
the broker's recovery action before any guest settings are changed.

The environment contains FZ_HOST/FZ_BROKER, credential-free HTTP_PROXY/HTTPS_PROXY, CA variables
for common runtimes, and fake provider keys. NO_PROXY/no_proxy includes the
broker host, localhost, 127.0.0.1, ::1 and [::1], preserving existing exclusions.
Real credentials and OAuth refresh tokens never enter the script.

Setup does not install tracing packages. For a focused timeout reproduction,
activate this environment and use the traced-command wrapper described in
[Trace commands and Cline proxy timeouts](TRACING.md). It can run any exact
command, uses an instrumented local backend for Cline, and sends traces through
this existing bootstrap listener; no collector port is exposed to the guest.

The setup name remains the human-readable policy/log label. Runtime proxy,
async-job, and MCP identity comes from a unique explicit source-IP pin. Use
**Approve + pin IP** after setup. Host networking must prevent source spoofing,
and each guest needs a distinct address; NATed guests sharing one source address
cannot be distinguished. A wildcard/preapproved name needs an explicit Pin
before new credential-free clients can use it. Legacy Basic guest identity is
accepted during migration only when it agrees with the pinned address.

Friendzone does not override Cline's global plugin sandbox lifetime. While a
request remains pending, the plugin emits a grouped reminder every 20 minutes;
an idle Cline session processes it through no-op Friendzone hooks, providing
normal host-to-sandbox activity. Closed, failed or continuously busy sessions can
still miss delivery; results remain retrievable through their delivery window and
are never automatically replayed. Rerunning setup removes the
exact temporary 25-hour override written by Friendzone release `ebfa82b` when
previous managed metadata proves ownership. User-authored values are preserved.

If Cline credentials are configured on the broker, the script merges a worthless
facade into the guest's `.cline/data/settings/providers.json`. **Close guest Cline
before running the script** because it writes this same file. A static host key
uses the existing fake `apiKey`; broker-owned Cline OAuth instead writes a fake
`auth.accessToken` with OAuth store metadata, but no refresh token or account ID.
The merge keeps model choice, other providers, and last-used provider and removes
stale fields from the other presentation mode. Invalid provider JSON fails before
environment/profile writes. Existing provider files get a backup. Restart Cline
after setup; Cloud Hub access additionally needs proxy-aware WebSocket support in
the guest Cline build.

The script does not modify firewall rules, global/repository Git configuration,
or the Windows **LocalMachine** CA store. On Kali/Debian/Ubuntu, Linux setup uses
`sudo` to install the exact Friendzone root as
`/usr/local/share/ca-certificates/friendzone-local-ca.crt` and runs
`update-ca-certificates`. It records whether it owns that file, is idempotent,
rotates only a Friendzone-owned root, refuses to overwrite external content, and
rolls back a failed trust refresh. This covers native-root TLS clients; programs
compiled with a private WebPKI-only root set must enable native roots or accept an
explicit CA bundle. On Windows it installs the exact
Friendzone CA into the guest user's Trusted Root Certification Authorities store
(`CurrentUser\Root`), so same-user .NET/Schannel applications trust intercepted
HTTPS without disabling verification. Runtime CA variables remain configured for
clients that use explicit PEM bundles. Setup also supplies
`http.schannelUseSSLCAInfo=true` through
Git's `GIT_CONFIG_COUNT` environment interface. This makes Git for Windows'
Schannel backend honor the managed
`GIT_SSL_CAINFO` PEM without disabling verification. Setup recognizes its exact entry on rerun but
fails rather than copy or overwrite other `GIT_CONFIG_*` environment injection,
which may contain secrets. Setup sets Cargo's native `CARGO_HTTP_CAINFO` to the
same PEM, allowing its libcurl/Schannel registry and crate downloads to verify
Friendzone-issued certificates. On Windows it also sets
`CARGO_HTTP_CHECK_REVOKE=false`: Friendzone's dynamically issued leaf
certificates have no public CRL/OCSP responder, so Schannel otherwise rejects
them when revocation status cannot be determined. This disables only Cargo's
Windows revocation lookup; CA-chain, signature, expiry, and hostname verification
remain enabled. Applications running as a different Windows user or using a private trust store
still need their own trust configuration. Network confinement remains host-enforced; see
[NETWORK-ISOLATION.md](NETWORK-ISOLATION.md).

When the broker exposes a fake `GITHUB_TOKEN`, setup also writes a
Friendzone-owned `friendzone.gitconfig` and loads it through the managed
environment. It contains helper logic but no token value. The helper clears stale
credential helpers and supplies the current fake token only for exact HTTPS
`github.com`; HTTP, subdomains, lookalike hosts, `api.github.com`, and other
origins receive no Friendzone credential. Git LFS inherits the same configuration.
When no matching GitHub escrow entry exists, the managed include is a harmless
marker-only file. Existing user-global and repository Git configuration is not
edited.

## Linux persistence

Run the setup script as the guest user; do not invoke the whole script with
`sudo`. Setup invokes `sudo` only for the native CA install and trust refresh.
Kali/Debian/Ubuntu require the `ca-certificates` package and `sudo` (or a root
login). User files are written under
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
if you have not edited those profiles since installation. Native-root ownership
is recorded in `linux-system-ca.json`: remove
`/usr/local/share/ca-certificates/friendzone-local-ca.crt` and run
`update-ca-certificates` only when that state says `managed: true` and its SHA-256
still matches the installed certificate. A `managed: false` root predated
Friendzone and must be preserved. CA/provider files are separate; do not
overwrite unrelated later edits.

## Windows Build Tools and Rust

Friendzone guest setup does not require Rust. If the Windows guest does need a
Rust toolchain, the preferred sequence is to install the
[Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
prerequisite and Rust before running Friendzone setup. The Build Tools
bootstrapper uses a WinINet downloader that does not work through the Friendzone
proxy.

For a guest that is already configured, use the following only during trusted
image provisioning, while no autonomous agent or untrusted workload is running.
Host-enforced egress restrictions may still block the resulting direct
connection; do not weaken those restrictions or reconnect a guest that has
processed hostile material. Run both blocks in the same PowerShell session so
`$previousProxyEnable` remains available.

First save the current setting, disable the current-user WinINet proxy, and
notify running WinINet clients:

```powershell
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$previousProxyEnable = (Get-ItemProperty $key).ProxyEnable

Set-ItemProperty $key -Name ProxyEnable -Value 0

if (-not ('QaProxy.WinInet' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace QaProxy {
    public static class WinInet {
        [DllImport("wininet.dll", SetLastError = true)]
        public static extern bool InternetSetOption(
            IntPtr handle, int option, IntPtr buffer, int length);
    }
}
'@
}

[QaProxy.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[QaProxy.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
```

Download and run the Build Tools bootstrapper, wait for installation to finish,
and then immediately restore the exact value saved above:

```powershell
Set-ItemProperty $key -Name ProxyEnable -Value $previousProxyEnable

[QaProxy.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[QaProxy.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
```

Do not leave `ProxyEnable` set to `0`. Restart any installer or client that does
not observe either notification. This workaround changes only the current-user
Windows Internet proxy switch; it does not remove Friendzone's saved proxy
address, environment variables, CA, or host-enforced network policy.

## Windows persistence

Files live in `%APPDATA%\friendzone`. The script writes **User**, never
**Machine**, environment values and activates its PowerShell process. It also
sets the current user's Windows Internet Settings (`ProxyEnable`, `ProxyServer`,
and `ProxyOverride`) to the credential-free Friendzone proxy. This is the proxy
used by many WinINET-aware and modern .NET HTTP clients; it is not a machine-wide
WinHTTP `netsh` change and cannot force software that ignores system proxy
settings. The broker and explicit loopback forms are added to the bypass list;
existing bypass entries are preserved. Its children inherit the new environment;
existing applications do not. Sign out
and back in for GUI launchers, and restart guest agents/hubs and existing
`HttpClient` owners. PowerShell
profiles are not required, so non-interactive and `-NoProfile` processes still
inherit values from a fresh launcher.

Before writes, `user-environment-backup.json`, `system-proxy-backup.json`, and
`certificate-trust-state.json` record original/applied settings and exact
Friendzone-owned certificate bytes. Reruns retain originals, skip unchanged
writes, and rotate only a root previously installed by Friendzone. A matching
root that predated setup is used but never claimed. Environment, proxy, and CA
updates form one transaction. To undo in the guest:

```powershell
& "$env:APPDATA\friendzone\persist-environment.ps1" `
  -BackupPath "$env:APPDATA\friendzone\user-environment-backup.json" -Restore
```

Rollback removes only the exact current-user root recorded as installed by
Friendzone and restores environment/proxy values that still equal Friendzone's
applied values. Pre-existing roots and externally changed values are preserved.
Start a fresh session/restart applications afterward;
already-inherited environment values and cached proxy decisions do not disappear.

The trust change is current-user only and requires no elevation. It is not a
machine-wide `LocalMachine\Root` installation. Applications may cache trust and
proxy state, so restart them after setup or rollback.

## First Windows guest acceptance

Do this in the **new Windows guest**, not the broker host. Keep the hypervisor
console and a clean snapshot available. These checks do not replace the
host-enforced network isolation in [NETWORK-ISOLATION.md](NETWORK-ISOLATION.md).

1. Friendzone dynamically issues HTTPS leaf certificates as a MITM proxy, but
   those certificates have no public CRL/OCSP revocation responder. In a
   non-elevated PowerShell in the guest, run:

   ```powershell
   inetcpl.cpl
   ```

   In **Internet Properties**, open **Advanced → Security**, uncheck **Check for
   server certificate revocation**, select **Apply**, and close the dialog.
   Restart clients that were already running. This disables revocation checks
   for affected clients in the guest user's Windows Internet settings; CA-chain,
   expiry, and hostname verification remain enabled. Do not make this change on
   the broker host. Without it, WinGet downloads through Friendzone can fail
   with `InternetOpenUrl() failed` and `0x80072f19 : unknown error` while, for
   example, running `winget install --id Git.Git -e --source winget`. The code is
   WinINet error `12057` (`ERROR_INTERNET_SEC_CERT_REV_FAILED`).
2. In a non-elevated PowerShell, confirm `curl.exe --version` and
   `cline --version`. Fetch the setup script using the **current** broker address
   shown in Settings; do not reuse an old downloaded script or assume that a
   Hyper-V Default Switch address survived a reboot.
3. Close guest Cline before running setup. Use the same guest Windows account
   that will run Cline. Execution policy still applies: do not use Bypass or
   change machine-wide policy to force installation.
4. **Approve + pin IP** for the new guest in Inbox. Check that `$env:FZ_BROKER` and
   `$env:HTTP_PROXY` point at the current host, and `$env:NO_PROXY` includes the
   host and loopback addresses. User environment values affect new launchers;
   old Cline hubs and already-running applications retain their old environment.
   Check `Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' ProxyEnable,ProxyServer,ProxyOverride`
   and confirm the user proxy points to the current Friendzone host/port. Confirm
   `Get-ChildItem Cert:\CurrentUser\Root` contains the Friendzone Local CA shown
   by the setup script's saved `friendzone-ca.pem` thumbprint.
5. Verify the installed module **without executing it**. Use
   `(Get-Content -LiteralPath "$env:USERPROFILE/.cline/plugins/friendzone.js" -Tail 1)`;
   expect `module.exports=plugin;`. Substitute `$env:CLINE_DIR` for the `.cline`
   directory if configured. If Node is installed, dynamic import of that absolute
   path via `pathToFileURL` should yield `default.name === 'friendzone'`.
6. Restart the guest Cline hub/session after activation. Confirm all six
   `friendzone_*` tools are registered before asking the agent to use them.
   Then run a small inference prompt, followed by a read-only GraphQL query and
   result retrieval. Verify the session receives the completion update.
7. Only after those pass, try a deliberate low-impact mutation with manual
   approval. Check that the submitted ID, Inbox decision and returned result
   agree. Don't use a real GitHub write as the first connectivity test.

Tests cover PowerShell installation into temporary paths with spaces/apostrophes
and Unicode, exact plugin bytes, idempotence, backups, unmanaged-file rejection,
and **mocked** user-environment/system-proxy/root-store writes. Actual Windows guest inference, proxy/CA
behavior, hub restart and steer-message delivery are acceptance checks—not claims
implied by those installer tests.

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
fixtures. Windows environment and Internet Settings writes are mocked in memory. The developer's
real profiles, user registry, trust store, network settings and live broker
are never used as installation test targets. Native zsh startup and real
Windows persistence still require acceptance testing in a disposable guest.