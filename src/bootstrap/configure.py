"""Script-only Linux guest configuration; standard library, explicit test paths."""
import base64
import datetime
import json
import os
from pathlib import Path
import shlex
import socket
import sys
import tempfile
import urllib.parse
import urllib.request

MARKER = "# Friendzone guest environment (managed)"


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


def provider_update(path, fake):
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
    entry["settings"]["apiKey"] = fake
    entry["settings"].pop("auth", None)
    entry["tokenSource"] = "manual"
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


def configure(data, home, config, zdotdir, environ):
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
        mode = path.stat().st_mode & 0o777 if path in profiles and path.exists() else 0o600
        atomic_write(path, text, mode)
    return activation


def main(encoded):
    if not sys.platform.startswith("linux"):
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
    activation = configure(data, home, config, os.environ.get("ZDOTDIR", str(home)), os.environ)
    if canonical != requested:
        print("Requested guest name " + requested + " was replaced with " + canonical + " because this VM source IP is already pinned to that guest.")
    message = approval.get("message") or ("Approved and pinned." if approval.get("approved") else "Use Approve + pin IP in the host Inbox.")
    print("Configured guest " + canonical + ". " + str(message))
    print("Installed the Friendzone Cline plugin for async GraphQL, reviewed Git publication, and session updates.")
    print("Activate this terminal, then restart guest Cline so it inherits the environment:\n  . " + shlex.quote(str(activation)))