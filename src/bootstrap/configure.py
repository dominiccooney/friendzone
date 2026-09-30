"""Script-only Linux and macOS guest configuration; standard library, explicit test paths."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shlex
import socket
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

MARKER = "# Friendzone guest environment (managed)"
SYSTEM_CA = Path("/usr/local/share/ca-certificates/friendzone-local-ca.crt")
SYSTEM_CA_STATE = "linux-system-ca.json"
MACOS_KEYCHAIN = Path("/Library/Keychains/System.keychain")
MACOS_CA_STATE = "macos-system-ca.json"
MACOS_PROXY_STATE = "macos-system-proxy.json"
MACOS_AGENT_LABEL = "friendzone.guest-environment"


def atomic_write(path, text, mode=0o600):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".friendzone-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def certificate_der(pem):
    """Validate one bounded PEM certificate and return its DER bytes."""
    if not isinstance(pem, str) or len(pem.encode("utf-8")) > 128 * 1024:
        raise ValueError("Friendzone CA is missing or exceeds 128 KiB")
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    if pem.count(begin) != 1 or pem.count(end) != 1:
        raise ValueError("Friendzone CA must contain exactly one PEM certificate")
    before, encoded = pem.split(begin, 1)
    encoded, after = encoded.split(end, 1)
    if before.strip() or after.strip():
        raise ValueError("Friendzone CA contains data outside its PEM certificate")
    try:
        der = base64.b64decode("".join(encoded.split()), validate=True)
    except Exception as error:
        raise ValueError("Friendzone CA contains invalid PEM base64") from error
    if not der:
        raise ValueError("Friendzone CA certificate is empty")
    return der


def certificate_digest(pem):
    """Validate one bounded PEM certificate and return its DER SHA-256."""
    return hashlib.sha256(certificate_der(pem)).hexdigest()


def _command_path(name, known):
    """Resolve only fixed administrator-owned paths, never the guest's PATH."""
    for candidate in known:
        if Path(candidate).is_file():
            return candidate
    return None


def _load_ca_state(state_path, platform):
    invalid = "Invalid Friendzone " + platform + " CA ownership state; repair or remove " + str(state_path)
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ValueError(invalid) from error
    if (not isinstance(state, dict) or state.get("version") != 1 or
            not isinstance(state.get("managed"), bool) or
            not isinstance(state.get("sha256"), str) or
            len(state["sha256"]) != 64 or
            any(character not in "0123456789abcdef" for character in state["sha256"])):
        raise ValueError(invalid)
    return state


def _sudo_prefix(missing):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    sudo = _command_path("sudo", ("/usr/bin/sudo", "/bin/sudo"))
    if not sudo:
        raise ValueError(missing)
    return [sudo]


def install_linux_ca(cert, config, destination=SYSTEM_CA, run=None,
                     updater=None, installer=None, remover=None, privilege=None):
    """Install/rotate only Friendzone's owned Debian-family native trust anchor."""
    cert, config, destination = map(lambda path: Path(path).absolute(),
                                    (cert, config, destination))
    pem = cert.read_text(encoding="utf-8")
    digest = certificate_digest(pem)
    state_path = config / SYSTEM_CA_STATE
    state = _load_ca_state(state_path, "Linux") if state_path.exists() else None
    previous = destination.read_bytes() if destination.exists() else None
    previous_digest = certificate_digest(previous.decode("utf-8")) if previous is not None else None
    if state is None and previous is not None and previous_digest != digest:
        raise ValueError("Refusing to overwrite unowned system CA file " + str(destination))
    if state is not None:
        if state["managed"]:
            if previous is not None and previous_digest != state["sha256"]:
                raise ValueError("Friendzone-owned system CA was changed externally; refusing to overwrite " + str(destination))
        elif previous_digest != state["sha256"] or digest != state["sha256"]:
            raise ValueError("A pre-existing system CA occupies " + str(destination) + "; Friendzone will not replace it")
    managed = state["managed"] if state is not None else previous is None
    if previous_digest == digest:
        if state is None:
            config.mkdir(parents=True, exist_ok=True)
            atomic_write(state_path, json.dumps(
                dict(version=1, managed=False, sha256=digest), indent=2) + "\n")
        return dict(installed=False, managed=managed, sha256=digest, destination=str(destination))

    run = run or subprocess.run
    updater = updater or _command_path("update-ca-certificates", (
        "/usr/sbin/update-ca-certificates", "/usr/bin/update-ca-certificates"))
    installer = installer or _command_path("install", ("/usr/bin/install", "/bin/install"))
    remover = remover or _command_path("rm", ("/usr/bin/rm", "/bin/rm"))
    if not updater or not installer or not remover:
        raise ValueError("Linux native CA setup requires the ca-certificates package and install command")
    if privilege is None:
        privilege = _sudo_prefix("Linux native CA setup requires sudo; install sudo or run from a root login")
    privilege = list(privilege)
    config.mkdir(parents=True, exist_ok=True)
    rollback = config / ".friendzone-system-ca-rollback.crt"
    if previous is not None:
        atomic_write(rollback, previous.decode("utf-8"))
    attempted = False
    def privileged(arguments):
        return run(privilege + arguments, check=True)
    def restore():
        if previous is None:
            privileged([remover, "-f", "--", str(destination)])
        else:
            privileged([installer, "-D", "-m", "0644", "--", str(rollback), str(destination)])
        privileged([updater])
    try:
        print("Installing Friendzone CA into Linux system trust; sudo may prompt.")
        attempted = True
        privileged([installer, "-D", "-m", "0644", "--", str(cert), str(destination)])
        privileged([updater])
        atomic_write(state_path, json.dumps(dict(version=1, managed=managed, sha256=digest), indent=2) + "\n")
    except Exception as error:
        try:
            if attempted:
                restore()
        except Exception:
            raise RuntimeError("Linux CA update failed and automatic rollback also failed; inspect " + str(destination)) from error
        raise RuntimeError("Linux CA update failed and was rolled back; verify sudo and update-ca-certificates") from error
    finally:
        try:
            rollback.unlink()
        except FileNotFoundError:
            pass
    return dict(installed=True, managed=managed, sha256=digest, destination=str(destination))



def _output_text(completed):
    output = completed.stdout
    return output.decode("utf-8", "replace") if isinstance(output, bytes) else output


def _macos_fingerprint(pem):
    """Trust settings are keyed by the certificate's SHA-1."""
    return hashlib.sha1(certificate_der(pem)).hexdigest()


def _macos_trust_state(run, security, keychain):
    """Map DER SHA-256 to PEM for keychain roots; return admin-trusted SHA-1s."""
    listing = _output_text(run([security, "find-certificate", "-a", "-p", str(keychain)],
                               check=True, stdout=subprocess.PIPE))
    certificates = {}
    end = "-----END CERTIFICATE-----"
    for block in listing.split(end)[:-1]:
        start = block.find("-----BEGIN CERTIFICATE-----")
        if start < 0:
            continue
        pem = block[start:] + end + "\n"
        try:
            certificates[certificate_digest(pem)] = pem
        except ValueError:
            continue
    with tempfile.TemporaryDirectory(prefix="friendzone-trust-") as directory:
        exported = Path(directory) / "admin-trust.plist"
        arguments = [security, "trust-settings-export", "-d", str(exported)]
        completed = run(arguments, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if completed.returncode != 0:
            # Older macOS releases exit 1 for an empty admin domain instead of
            # exporting an empty trustList; any other failure is still fatal.
            stderr = completed.stderr.decode("utf-8", "replace") if isinstance(completed.stderr, bytes) else completed.stderr or ""
            if "No Trust Settings were found" not in stderr:
                raise subprocess.CalledProcessError(completed.returncode, arguments, stderr=completed.stderr)
            return certificates, set()
        with exported.open("rb") as stream:
            settings = plistlib.load(stream)
    trust = settings.get("trustList") if isinstance(settings, dict) else None
    if not isinstance(trust, dict):
        raise ValueError("Unexpected macOS admin trust settings export")
    return certificates, {key.lower() for key in trust if isinstance(key, str)}


def install_macos_ca(cert, config, keychain=MACOS_KEYCHAIN, run=None, security=None, privilege=None):
    """Trust Friendzone's root in the System keychain; retire only a root it installed."""
    cert, config, keychain = map(lambda path: Path(path).absolute(), (cert, config, keychain))
    pem = cert.read_text(encoding="utf-8")
    digest = certificate_digest(pem)
    fingerprint = _macos_fingerprint(pem)
    state_path = config / MACOS_CA_STATE
    state = _load_ca_state(state_path, "macOS") if state_path.exists() else None
    if state is not None:
        try:
            valid = isinstance(state.get("pem"), str) and certificate_digest(state["pem"]) == state["sha256"]
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("Invalid Friendzone macOS CA ownership state; repair or remove " + str(state_path))
    run = run or subprocess.run
    security = security or _command_path("security", ("/usr/bin/security",))
    if not security:
        raise ValueError("macOS CA setup requires /usr/bin/security")
    certificates, trusted = _macos_trust_state(run, security, keychain)
    present = digest in certificates and fingerprint in trusted
    same = state is not None and state["sha256"] == digest
    # A root that was already trusted is used but never claimed.
    managed = state["managed"] if present and same else not present
    retired = state if state is not None and not same and state["managed"] else None
    record = json.dumps(dict(version=1, managed=managed, sha256=digest, pem=pem), indent=2) + "\n"
    if present and retired is None:
        if not same:
            config.mkdir(parents=True, exist_ok=True)
            atomic_write(state_path, record)
        return dict(installed=False, managed=managed, sha256=digest, keychain=str(keychain))

    if privilege is None:
        privilege = _sudo_prefix("macOS CA setup requires sudo from an administrator account")
    privilege = list(privilege)
    def privileged(arguments):
        return run(privilege + arguments, check=True)
    def trust(path):
        privileged([security, "add-trusted-cert", "-d", "-r", "trustRoot", "-k", str(keychain), str(path)])
    config.mkdir(parents=True, exist_ok=True)
    old_pem = config / ".friendzone-retired-ca.pem"
    old_fingerprint = None
    if retired is not None:
        atomic_write(old_pem, retired["pem"])
        old_fingerprint = _macos_fingerprint(retired["pem"])
    def restore():
        # Compare with the keychain before this run; never remove a root that predated it.
        now, now_trusted = _macos_trust_state(run, security, keychain)
        if fingerprint in now_trusted and fingerprint not in trusted:
            privileged([security, "remove-trusted-cert", "-d", str(cert)])
        if digest in now and digest not in certificates:
            privileged([security, "delete-certificate", "-Z", digest.upper(), str(keychain)])
        if retired is not None:
            if old_fingerprint in trusted and old_fingerprint not in now_trusted:
                trust(old_pem)
            elif retired["sha256"] in certificates and retired["sha256"] not in now:
                privileged([security, "add-certificates", "-k", str(keychain), str(old_pem)])
    attempted = False
    try:
        if not present:
            print("Trusting the Friendzone CA in the macOS System keychain; sudo and a macOS dialog may ask for your password.")
            attempted = True
            trust(cert)
            now, now_trusted = _macos_trust_state(run, security, keychain)
            if digest not in now or fingerprint not in now_trusted:
                raise RuntimeError("Friendzone CA is not trusted in the System keychain after installation")
        if retired is not None:
            attempted = True
            if old_fingerprint in trusted:
                privileged([security, "remove-trusted-cert", "-d", str(old_pem)])
            if retired["sha256"] in certificates:
                privileged([security, "delete-certificate", "-Z", retired["sha256"].upper(), str(keychain)])
        atomic_write(state_path, record)
    except Exception as error:
        try:
            if attempted:
                restore()
        except Exception:
            raise RuntimeError("macOS CA update failed and automatic rollback also failed; inspect the System keychain") from error
        raise RuntimeError("macOS CA update failed and was rolled back; verify sudo and approve the macOS password dialog") from error
    finally:
        try:
            old_pem.unlink()
        except FileNotFoundError:
            pass
    return dict(installed=not present, managed=managed, sha256=digest, keychain=str(keychain))


def _macos_proxy_value(text):
    """Parse networksetup -getwebproxy / -getsecurewebproxy output."""
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    try:
        port = int(fields.get("Port") or 0)
    except ValueError:
        port = None
    if fields.get("Enabled") not in ("Yes", "No") or port is None:
        raise ValueError("Unexpected networksetup proxy output")
    return dict(enabled=fields["Enabled"] == "Yes", server=fields.get("Server", ""), port=port,
                authenticated=fields.get("Authenticated Proxy Enabled", "0") not in ("", "0"))


def configure_macos_proxy(host, port, config, run=None, networksetup=None, privilege=None):
    """Point enabled network services' HTTP(S) proxies at Friendzone; keep originals."""
    if (not isinstance(host, str) or not host or host.startswith("-") or
            any(ord(character) <= 32 or ord(character) == 127 or character in "[]/\\@?#;,"
                for character in host) or
            isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536):
        raise ValueError("Invalid Friendzone macOS proxy address")
    config = Path(config).absolute()
    state_path = config / MACOS_PROXY_STATE
    run = run or subprocess.run
    networksetup = networksetup or _command_path("networksetup", ("/usr/sbin/networksetup",))
    if not networksetup:
        raise ValueError("macOS proxy setup requires /usr/sbin/networksetup")
    def read(*arguments):
        return _output_text(run([networksetup] + list(arguments), check=True, stdout=subprocess.PIPE))
    saved = None
    state_before = state_path.read_text(encoding="utf-8") if state_path.exists() else None
    if state_before is not None:
        try:
            saved = json.loads(state_before)
            valid = saved.get("version") == 1 and all(
                isinstance(entry, dict) and isinstance(entry.get("previous"), dict)
                for entry in saved["services"].values())
        except (ValueError, KeyError, TypeError, AttributeError):
            valid = False
        if not valid:
            raise ValueError("Unsupported Friendzone macOS proxy state; repair or remove " + str(state_path))
    lines = read("-listallnetworkservices").splitlines()
    if not lines or "asterisk" not in lines[0]:
        raise ValueError("Unexpected networksetup service list")
    services = [line for line in lines[1:] if line and not line.startswith("*")]
    if not services:
        raise ValueError("No enabled macOS network service to configure")
    before = {}
    for service in services:
        bypass = read("-getproxybypassdomains", service)
        before[service] = dict(
            web=_macos_proxy_value(read("-getwebproxy", service)),
            secure=_macos_proxy_value(read("-getsecurewebproxy", service)),
            bypass=[] if bypass.startswith("There aren't any bypass domains") else
            [line.strip() for line in bypass.splitlines() if line.strip()])
        if any(before[service][kind]["enabled"] and before[service][kind]["authenticated"] for kind in ("web", "secure")):
            raise ValueError("Network service " + service + " uses an authenticated proxy; Friendzone will not replace it")
    endpoint = dict(enabled=True, server=host, port=port, authenticated=False)
    applied = {}
    for service in services:
        bypass = []
        for item in before[service]["bypass"] + [host, "localhost", "127.0.0.1", "::1"]:
            if item.lower() not in [existing.lower() for existing in bypass]:
                bypass.append(item)
        applied[service] = dict(web=endpoint, secure=endpoint, bypass=bypass)
    # Reruns keep the first-run originals, including services disabled since then.
    records = dict(saved["services"]) if saved is not None else {}
    for service in services:
        previous = records[service]["previous"] if service in records else before[service]
        records[service] = dict(previous=previous, applied=applied[service])

    if privilege is None:
        privilege = _sudo_prefix("macOS proxy setup requires sudo from an administrator account")
    privilege = list(privilege)
    def privileged(arguments):
        return run(privilege + arguments, check=True)
    def equal(kind, left, right):
        if kind == "bypass":
            return left == right
        return all(left[key] == right[key] for key in ("enabled", "server", "port"))
    def write(service, kind, value):
        if kind == "bypass":
            privileged([networksetup, "-setproxybypassdomains", service] + (value or ["Empty"]))
            return
        option = "-setwebproxy" if kind == "web" else "-setsecurewebproxy"
        if value["server"] and value["port"]:
            privileged([networksetup, option, service, value["server"], str(value["port"]), "off"])
        if not value["enabled"]:
            privileged([networksetup, option + "state", service, "off"])
    config.mkdir(parents=True, exist_ok=True)
    # Recovery metadata is durable before the first network setting changes.
    atomic_write(state_path, json.dumps(dict(version=1, services=records), indent=2) + "\n")
    written = []
    try:
        for service in services:
            for kind in ("web", "secure", "bypass"):
                if not equal(kind, before[service][kind], applied[service][kind]):
                    written.append((service, kind))
                    write(service, kind, applied[service][kind])
    except Exception as error:
        try:
            for service, kind in reversed(written):
                write(service, kind, before[service][kind])
            if state_before is None:
                state_path.unlink()
            else:
                atomic_write(state_path, state_before)
        except Exception:
            raise RuntimeError("macOS proxy update failed and automatic rollback also failed; check System Settings > Network > Proxies") from error
        raise RuntimeError("macOS proxy update failed and was rolled back; verify sudo and networksetup") from error
    return dict(services=services, changed=bool(written))

def provider_update(path, fake):
    """Merge the OAuth-shaped guest facade for the broker-owned Cline session.

    Friendzone only delivers CLINE_API_KEY while the broker holds a Cline OAuth
    session, so this always writes the OAuth presentation. Any stale static
    ``apiKey`` from an older setup is removed: Cline prefers auth.accessToken,
    and a leftover key would otherwise shadow the facade after sign-out.
    """
    root = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(root, dict) or root.get("version", 1) != 1:
        raise ValueError("Unsupported Cline providers.json; no configuration changed")
    root["version"] = 1
    root.setdefault("modes", {})
    providers = root.setdefault("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("Cline providers must be an object")
    entry = providers.setdefault("cline", {"settings": {"provider": "cline"}})
    if not isinstance(entry, dict) or not isinstance(entry.get("settings"), dict):
        raise ValueError("Invalid Cline provider settings")
    entry["settings"].pop("apiKey", None)
    # This is an OAuth-shaped, guest-only facade. Friendzone owns the real
    # refresh token; the far-future local expiry prevents Cline from trying
    # to redeem credentials that deliberately do not exist in the guest.
    entry["settings"]["auth"] = {
        "accessToken": "workos:" + fake,
        "expiresAt": 253402300799000,
    }
    entry["tokenSource"] = "oauth"
    entry["updatedAt"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    root.setdefault("lastUsedProvider", "cline")
    return json.dumps(root, ensure_ascii=False, indent=2) + "\n"


def profile_update(old, activation, env, home):
    hook = MARKER + "\nif [ -r {0} ]; then . {0}; fi\n".format(shlex.quote(str(activation)))
    if hook in old:
        return old
    # Upgrade the previous Rust installer's always-quoted spelling in place.
    quoted = "'" + str(activation).replace("'", "'\"'\"'") + "'"
    previous_hook = MARKER + "\nif [ -r {0} ]; then . {0}; fi\n".format(quoted)
    if previous_hook in old:
        return old.replace(previous_hook, hook)
    if MARKER in old:
        raise ValueError("Existing Friendzone hook uses another directory; remove it before relocating configuration")
    candidates = set()
    for target in (activation, env):
        for command in (".", "source"):
            candidates.update((f"{command} {target}", f"{command} {shlex.quote(str(target))}", f'{command} "{target}"'))
            try:
                relative = target.relative_to(home).as_posix()
                candidates.update((f"{command} ~/{relative}", f'{command} "$HOME/{relative}"', f"{command} $HOME/{relative}"))
            except ValueError:
                pass
    lines = old.splitlines(keepends=True)
    matches = [i for i, line in enumerate(lines) if line.strip() in candidates]
    if matches:
        return "".join(hook if i == matches[0] else "" if i in matches else line for i, line in enumerate(lines))
    return hook + "\n" + old


def configure(data, home, config, zdotdir, environ, platform="linux"):
    """Only these explicit paths are written; caller owns network admission."""
    home, config, zdotdir = map(lambda p: Path(p).absolute(), (home, config, zdotdir))
    cert = config / "friendzone-ca.pem"
    env = config / "friendzone-env.sh"
    activation = config / "activate.sh"
    wrapper = config / "bash-env.sh"
    old_hook = config / "previous-bash-env"
    previous = old_hook.read_text(encoding="utf-8") if old_hook.exists() else environ.get("BASH_ENV", "")
    if previous == str(wrapper):
        previous = ""
    old_environment = env.read_text(encoding="utf-8") if env.exists() else ""
    old_github_token = None
    if old_environment.startswith("# Friendzone guest environment\n"):
        for line in old_environment.splitlines():
            try:
                fields = shlex.split(line)
            except ValueError:
                fields = []
            if len(fields) == 2 and fields[0] == "export" and fields[1].startswith("GITHUB_TOKEN="):
                if old_github_token is not None:
                    raise ValueError("Invalid previous Friendzone GITHUB_TOKEN environment")
                old_github_token = fields[1].split("=", 1)[1]
    legacy_idle = "export CLINE_PLUGIN_IDLE_TIMEOUT_MS=90000000\n"
    legacy_idle_marker = config / "remove-legacy-cline-idle-timeout"
    # The old generated file proves ownership. Preserve any user-authored value.
    remove_legacy_idle = legacy_idle_marker.exists() or (legacy_idle in old_environment and old_environment.count("CLINE_PLUGIN_IDLE_TIMEOUT_MS") == 1)
    origin = urllib.parse.urlsplit(data["broker"])
    proxy_host = "[" + origin.hostname + "]" if ":" in origin.hostname else origin.hostname
    proxy = "http://{}:{}".format(proxy_host, data["proxy_port"])
    values = dict(data["fakes"])
    values.update(FZ_HOST=origin.hostname, FZ_BROKER=data["broker"], HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy)
    for key in ("NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "GIT_SSL_CAINFO", "GIT_PROXY_SSL_CAINFO", "CARGO_HTTP_CAINFO"):
        values[key] = str(cert)
    git_config_text = data.get("git_credential_config") or ""
    git_config = config / "friendzone.gitconfig"
    if not git_config_text.startswith("# Friendzone managed Git configuration v1\n"):
        raise ValueError("Invalid managed Git credential configuration")
    expected = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "include.path", "GIT_CONFIG_VALUE_0": str(git_config)}
    injected = {key: value for key, value in environ.items()
                if key == "GIT_CONFIG_PARAMETERS" or key == "GIT_CONFIG_COUNT" or
                key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_")}
    if injected and injected != expected:
        raise ValueError("Existing GIT_CONFIG_* environment entries conflict with Friendzone Git authentication")
    values.update(expected)
    content = "# Friendzone guest environment\n" + "".join(f"export {key}={shlex.quote(value)}\n" for key, value in values.items())
    if old_github_token is not None and "GITHUB_TOKEN" not in values:
        content += "if [ \"${{GITHUB_TOKEN-}}\" = {0} ]; then unset GITHUB_TOKEN; fi\n".format(shlex.quote(old_github_token))
    if remove_legacy_idle:
        marker = shlex.quote(str(legacy_idle_marker))
        content += "if [ -r {0} ]; then\n  if [ \"${{CLINE_PLUGIN_IDLE_TIMEOUT_MS-}}\" = 90000000 ]; then unset CLINE_PLUGIN_IDLE_TIMEOUT_MS; fi\n  rm -f -- {0}\nfi\n".format(marker)
    content += '''_fz_rest="$FZ_HOST,localhost,127.0.0.1,::1,[::1],${NO_PROXY:-},${no_proxy:-},"
_fz_list=
while [ -n "$_fz_rest" ]; do
  _fz_item=${_fz_rest%%,*}; _fz_rest=${_fz_rest#*,}
  _fz_item=${_fz_item#"${_fz_item%%[![:space:]]*}"}; _fz_item=${_fz_item%"${_fz_item##*[![:space:]]}"}
  [ -n "$_fz_item" ] || continue
  case ,$_fz_list, in *,"$_fz_item",*) ;; *) _fz_list="${_fz_list:+$_fz_list,}$_fz_item" ;; esac
done
export NO_PROXY="$_fz_list" no_proxy="$_fz_list"
unset _fz_rest _fz_list _fz_item
'''
    source = ". " + shlex.quote(str(env)) + "\n"
    edits = ([(legacy_idle_marker, "Friendzone previously managed the exact value 90000000; activation removes only that value.\n")] if remove_legacy_idle else []) + [(git_config, git_config_text), (cert, data["ca"]), (env, content), (old_hook, previous),
             (activation, source + "export BASH_ENV=" + shlex.quote(str(wrapper)) + "\n"),
             (wrapper, ("if [ -r {0} ]; then . {0}; fi\n".format(shlex.quote(previous)) if previous else "") + source)]
    profiles = {home / ".profile", home / ".bashrc", zdotdir / ".zshenv"}
    profiles.update(home / name for name in (".bash_profile", ".bash_login") if (home / name).exists())
    backups = []
    modes = {}
    if platform == "darwin":
        # GUI apps started by launchd do not read shell profiles. A LaunchAgent
        # republishes the activated environment into the login session.
        agent = home / "Library/LaunchAgents" / (MACOS_AGENT_LABEL + ".plist")
        launchd_env = config / "launchd-env.sh"
        if agent.exists():
            try:
                with agent.open("rb") as stream:
                    existing = plistlib.load(stream)
            except Exception as error:
                raise ValueError("Unmanaged " + str(agent) + " exists; configuration unchanged") from error
            if not isinstance(existing, dict) or existing.get("Label") != MACOS_AGENT_LABEL:
                raise ValueError("Unmanaged " + str(agent) + " exists; configuration unchanged")
        names = list(values) + ["NO_PROXY", "no_proxy", "BASH_ENV"]
        if old_github_token is not None and "GITHUB_TOKEN" not in values:
            names.append("GITHUB_TOKEN")
        if remove_legacy_idle:
            names.append("CLINE_PLUGIN_IDLE_TIMEOUT_MS")
        edits.append((launchd_env, "# Friendzone launchd environment (managed)\n. " + shlex.quote(str(activation)) + "\n" + "".join(
            'if [ -n "${{{0}+x}}" ]; then /bin/launchctl setenv {0} "${0}"; else /bin/launchctl unsetenv {0}; fi\n'.format(name)
            for name in names)))
        edits.append((agent, plistlib.dumps(dict(
            Label=MACOS_AGENT_LABEL, ProgramArguments=["/bin/sh", str(launchd_env)], RunAtLoad=True)).decode("utf-8")))
        modes[agent] = 0o644
    if git_config.exists() and not git_config.read_text(encoding="utf-8").startswith("# Friendzone managed Git configuration v1\n"):
        raise ValueError("Unmanaged friendzone.gitconfig exists; configuration unchanged")
    cline_home = Path(environ.get("CLINE_DIR", "").strip() or home / ".cline").absolute()
    plugin_path = cline_home / "plugins/friendzone.js"
    plugin_config = cline_home / "friendzone.json"
    plugin = base64.b64decode(data["plugin"], validate=True).decode("utf-8")
    if not plugin.startswith("// Friendzone managed plugin v1."):
        raise ValueError("Invalid Friendzone plugin payload")
    if plugin_path.exists():
        old_plugin = plugin_path.read_text(encoding="utf-8")
        if not old_plugin.startswith("// Friendzone managed plugin v1."):
            raise ValueError("Unmanaged friendzone.js already exists; configuration unchanged")
        backups.append((plugin_path.with_name("friendzone.js.backup"), old_plugin))
    if plugin_config.exists():
        old_config = json.loads(plugin_config.read_text(encoding="utf-8"))
        if not isinstance(old_config, dict) or old_config.get("managed_by") != "friendzone":
            raise ValueError("Unmanaged Friendzone plugin configuration; configuration unchanged")
        backups.append((plugin_config.with_name("friendzone.json.backup"), plugin_config.read_text(encoding="utf-8")))
    edits.extend([(plugin_path, plugin), (plugin_config, json.dumps(dict(managed_by="friendzone",broker=data["broker"],container=data["container"]), indent=2)+"\n")])
    for path in sorted(profiles):
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        updated = profile_update(old, activation, env, home)
        if updated != old:
            edits.append((path, updated))
            if path.exists():
                backups.append((path.with_name(path.name + ".friendzone-backup"), old))
    if "CLINE_API_KEY" in data["fakes"]:
        provider = home / ".cline/data/settings/providers.json"
        edits.append((provider, provider_update(provider, data["fakes"]["CLINE_API_KEY"])))
        if provider.exists():
            backups.append((provider.with_name("providers.json.friendzone-backup"), provider.read_text(encoding="utf-8")))
    # All parsing and profile conflict checks complete before the first write.
    for path, text in backups:
        if not path.exists():
            atomic_write(path, text)
    for path, text in edits:
        mode = path.stat().st_mode & 0o777 if path in profiles and path.exists() else modes.get(path, 0o600)
        atomic_write(path, text, mode)
    return activation


def main(encoded):
    platform = "darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else None
    if platform is None:
        raise ValueError("Select the Windows script for a Windows guest")
    if os.environ.get("SUDO_USER"):
        raise ValueError("Run this script as the guest user without sudo")
    data = json.loads(base64.b64decode(encoded))
    data["container"] = data["container"] or socket.gethostname()
    if not data["container"] or ":" in data["container"] or len(data["container"].encode()) > 128:
        raise ValueError("Invalid guest name")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    url = data["broker"] + "/bootstrap/hello?" + urllib.parse.urlencode({"container": data["container"]})
    with client.open(url, timeout=10) as response:
        approval = json.load(response)
    canonical = approval.get("container") if isinstance(approval, dict) else None
    if not isinstance(canonical, str) or not canonical or ":" in canonical or len(canonical.encode()) > 128 or any(ord(character) < 32 or ord(character) == 127 for character in canonical):
        raise ValueError("Friendzone registration did not return a valid guest name; no guest settings were changed")
    requested = data["container"]
    data["container"] = canonical
    home = Path.home()
    config = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))) / "friendzone"
    activation = configure(data, home, config, os.environ.get("ZDOTDIR", str(home)), os.environ, platform)
    if platform == "darwin":
        trust = install_macos_ca(config / "friendzone-ca.pem", config)
        print("macOS System keychain trusts the Friendzone CA (SHA-256 " + trust["sha256"] + ").")
        proxy = configure_macos_proxy(urllib.parse.urlsplit(data["broker"]).hostname, data["proxy_port"], config)
        print("HTTP and HTTPS system proxy set for: " + ", ".join(proxy["services"]) + ".")
        subprocess.run(["/bin/sh", str(config / "launchd-env.sh")], check=True)
        print("Apps opened from the Dock, Finder or Spotlight now inherit the Friendzone environment; quit and reopen apps that are already running.")
    else:
        trust = install_linux_ca(config / "friendzone-ca.pem", config)
        print("Linux native trust ready at " + trust["destination"] + ".")
    if canonical != requested:
        print("Requested guest name " + requested + " was replaced with " + canonical + " because this VM source IP is already pinned to that guest.")
    message = approval.get("message") or ("Approved and pinned." if approval.get("approved") else "Use Approve + pin IP in the host Inbox.")
    print("Configured guest " + canonical + ". " + str(message))
    print("Installed the Friendzone Cline plugin for async GraphQL, reviewed Git publication, and session updates.")
    print("Activate this terminal, then restart guest Cline so it inherits the environment:\n  . " + shlex.quote(str(activation)))