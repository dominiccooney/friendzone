import importlib.util
import base64
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import threading
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "src/bootstrap/configure.py"
# Fixed public certificate-only fixtures are source inputs, not generated files.
# Stable, distinct bytes are required to exercise ownership and CA rotation.
TEST_CA = (Path(__file__).resolve().parent / "fixtures/friendzone-test-ca.pem").read_text(encoding="utf-8")
ROTATED_CA = (Path(__file__).resolve().parent / "fixtures/friendzone-rotated-test-ca.pem").read_text(encoding="utf-8")
GIT_CONFIG = '''# Friendzone managed Git configuration v1
[credential "https://github.com"]
\thelper =
\thelper = "!fz_github_credential() { test \\"$1\\" = get || exit 0; protocol=; host=; while IFS= read -r line; do case \\"$line\\" in protocol=*) protocol=${line#protocol=} ;; host=*) host=${line#host=} ;; esac; done; test \\"$protocol\\" = https && test \\"$host\\" = github.com && test -n \\"$GITHUB_TOKEN\\" || exit 0; printf \\"%s\\\\n\\" \\"username=x-access-token\\" \\"password=$GITHUB_TOKEN\\"; }; fz_github_credential"
'''
spec = importlib.util.spec_from_file_location("configure", SOURCE)
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class FakeMac:
    """In-memory System keychain, admin trust settings and network services."""

    def __init__(self, services=None, disabled=()):
        self.certificates = {}
        self.trusted = set()
        self.services = services if services is not None else {"Ethernet": FakeMac.service()}
        self.disabled = list(disabled)
        self.calls = []
        self.fail = None

    @staticmethod
    def service(bypass=(), web=None, secure=None):
        off = dict(enabled=False, server="", port=0, authenticated=False)
        return dict(web=dict(web or off), secure=dict(secure or off), bypass=list(bypass))

    def trust(self, pem):
        self.certificates[configure.certificate_digest(pem)] = pem
        self.trusted.add(configure._macos_fingerprint(pem))

    def run(self, arguments, check, stdout=None):
        assert check
        command, rest = arguments[1], arguments[2:]
        if command not in ("find-certificate", "trust-settings-export", "-listallnetworkservices") and not command.startswith("-get"):
            self.calls.append(list(arguments))
        if self.fail is not None and self.fail(arguments):
            self.fail = None
            if command == "add-trusted-cert":
                # The certificate lands in the keychain before trust authorization is cancelled.
                pem = Path(rest[-1]).read_text()
                self.certificates[configure.certificate_digest(pem)] = pem
            raise subprocess.CalledProcessError(1, arguments)
        output = ""
        if command == "find-certificate":
            output = "".join(self.certificates.values())
        elif command == "trust-settings-export":
            with open(rest[-1], "wb") as stream:
                plistlib.dump({"trustList": {key.upper(): {} for key in self.trusted}, "trustVersion": 1}, stream)
        elif command == "add-trusted-cert":
            self.trust(Path(rest[-1]).read_text())
        elif command == "add-certificates":
            pem = Path(rest[-1]).read_text()
            self.certificates[configure.certificate_digest(pem)] = pem
        elif command == "remove-trusted-cert":
            fingerprint = configure._macos_fingerprint(Path(rest[-1]).read_text())
            if fingerprint not in self.trusted:
                raise subprocess.CalledProcessError(1, arguments)
            self.trusted.remove(fingerprint)
        elif command == "delete-certificate":
            if rest[1].lower() not in self.certificates:
                raise subprocess.CalledProcessError(1, arguments)
            del self.certificates[rest[1].lower()]
        elif command == "-listallnetworkservices":
            output = "An asterisk (*) denotes that a network service is disabled.\n" + "".join(
                name + "\n" for name in self.services) + "".join("*" + name + "\n" for name in self.disabled)
        elif command in ("-getwebproxy", "-getsecurewebproxy"):
            value = self.services[rest[0]]["web" if command == "-getwebproxy" else "secure"]
            output = "Enabled: {}\nServer: {}\nPort: {}\nAuthenticated Proxy Enabled: {}\n".format(
                "Yes" if value["enabled"] else "No", value["server"], value["port"], int(value["authenticated"]))
        elif command == "-getproxybypassdomains":
            bypass = self.services[rest[0]]["bypass"]
            output = "".join(item + "\n" for item in bypass) if bypass else "There aren't any bypass domains set on " + rest[0] + ".\n"
        elif command in ("-setwebproxy", "-setsecurewebproxy"):
            self.services[rest[0]]["web" if command == "-setwebproxy" else "secure"].update(
                enabled=True, server=rest[1], port=int(rest[2]), authenticated=rest[3] == "on")
        elif command in ("-setwebproxystate", "-setsecurewebproxystate"):
            self.services[rest[0]]["web" if command == "-setwebproxystate" else "secure"]["enabled"] = rest[1] == "on"
        elif command == "-setproxybypassdomains":
            self.services[rest[0]]["bypass"] = [] if rest[1:] == ["Empty"] else list(rest[1:])
        else:
            raise AssertionError(arguments)
        return types.SimpleNamespace(returncode=0, stdout=output.encode())


class GuestScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fz-script-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.config = self.home / "config"
        self.data = dict(broker="http://192.0.2.1:9082", container="guest", proxy_port=9080,
                         plugin=base64.b64encode((SOURCE.parents[1] / "plugin/friendzone.js").read_bytes()).decode(),
                         ca=TEST_CA, git_credential_config=GIT_CONFIG,
                         fakes={"CLINE_API_KEY": "fake'$(bad)", "OTHER_KEY": "other", "GITHUB_TOKEN": "fz-test-github-token"})

    def apply(self, env=None):
        return configure.configure(self.data, self.home, self.config, self.home / "zsh", env or {})

    def ca_runner(self, destination, fail_update_once=False):
        calls = []
        failures = [fail_update_once]
        def run(arguments, check):
            self.assertTrue(check)
            calls.append(list(arguments))
            command = arguments[0]
            if command == "fixture-install":
                source, target = Path(arguments[-2]), Path(arguments[-1])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
            elif command == "fixture-rm":
                Path(arguments[-1]).unlink(missing_ok=True)
            elif command == "fixture-update" and failures[0]:
                failures[0] = False
                raise subprocess.CalledProcessError(1, arguments)
            return types.SimpleNamespace(returncode=0)
        return run, calls

    def install_ca(self, pem=None, fail_update_once=False):
        self.config.mkdir(parents=True, exist_ok=True)
        certificate = self.config / "friendzone-ca.pem"
        certificate.write_text(pem or TEST_CA, encoding="utf-8")
        destination = self.home / "system/friendzone-local-ca.crt"
        runner, calls = self.ca_runner(destination, fail_update_once)
        result = configure.install_linux_ca(
            certificate, self.config, destination=destination, run=runner,
            updater="fixture-update", installer="fixture-install",
            remover="fixture-rm", privilege=[])
        return result, destination, calls

    def test_linux_native_ca_install_is_idempotent_and_rotates_only_owned_anchor(self):
        result, destination, calls = self.install_ca()
        self.assertTrue(result["installed"])
        self.assertTrue(result["managed"])
        self.assertEqual(destination.read_text(encoding="utf-8"), TEST_CA)
        state = json.loads((self.config / configure.SYSTEM_CA_STATE).read_text())
        self.assertTrue(state["managed"])
        self.assertEqual(state["sha256"], configure.certificate_digest(TEST_CA))
        result, _, repeated = self.install_ca()
        self.assertFalse(result["installed"])
        self.assertEqual(repeated, [])

        result, _, repeated = self.install_ca(ROTATED_CA)
        self.assertTrue(result["installed"])
        self.assertTrue(result["managed"])
        self.assertEqual(destination.read_text(encoding="utf-8"), ROTATED_CA)
        self.assertEqual(len(repeated), 2)
        self.assertGreaterEqual(len(calls), 2)

    def test_linux_native_ca_preserves_preexisting_and_rejects_external_changes(self):
        self.config.mkdir(parents=True)
        certificate = self.config / "friendzone-ca.pem"
        certificate.write_text(TEST_CA)
        destination = self.home / "system/friendzone-local-ca.crt"
        destination.parent.mkdir(parents=True)
        destination.write_text(TEST_CA)
        runner, calls = self.ca_runner(destination)
        result = configure.install_linux_ca(
            certificate, self.config, destination, runner, "fixture-update",
            "fixture-install", "fixture-rm", [])
        self.assertFalse(result["managed"])
        self.assertFalse(result["installed"])
        self.assertEqual(calls, [])
        destination.write_text(ROTATED_CA)
        with self.assertRaises(ValueError):
            configure.install_linux_ca(
                certificate, self.config, destination, runner, "fixture-update",
                "fixture-install", "fixture-rm", [])
        self.assertEqual(calls, [])

    def test_linux_native_ca_refresh_failure_restores_previous_state(self):
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            self.install_ca(fail_update_once=True)
        destination = self.home / "system/friendzone-local-ca.crt"
        self.assertFalse(destination.exists())
        self.assertFalse((self.config / configure.SYSTEM_CA_STATE).exists())

    def install_macos_ca(self, mac, pem=None):
        self.config.mkdir(parents=True, exist_ok=True)
        certificate = self.config / "friendzone-ca.pem"
        certificate.write_text(pem or TEST_CA, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            return configure.install_macos_ca(certificate, self.config, keychain=self.home / "System.keychain",
                                              run=mac.run, security="fixture-security", privilege=[])

    def test_macos_ca_install_is_idempotent_and_rotates_only_owned_root(self):
        mac = FakeMac()
        result = self.install_macos_ca(mac)
        self.assertTrue(result["installed"])
        self.assertTrue(result["managed"])
        self.assertEqual(mac.certificates, {configure.certificate_digest(TEST_CA): TEST_CA})
        self.assertEqual(mac.trusted, {configure._macos_fingerprint(TEST_CA)})
        state = json.loads((self.config / configure.MACOS_CA_STATE).read_text())
        self.assertEqual((state["managed"], state["sha256"], state["pem"]), (True, configure.certificate_digest(TEST_CA), TEST_CA))
        self.assertEqual([call[1] for call in mac.calls], ["add-trusted-cert"])
        self.assertIn("/System.keychain", mac.calls[0][-2])
        mac.calls.clear()
        result = self.install_macos_ca(mac)
        self.assertFalse(result["installed"])
        self.assertEqual(mac.calls, [])

        result = self.install_macos_ca(mac, ROTATED_CA)
        self.assertTrue(result["installed"])
        self.assertTrue(result["managed"])
        self.assertEqual([call[1] for call in mac.calls], ["add-trusted-cert", "remove-trusted-cert", "delete-certificate"])
        self.assertEqual(mac.certificates, {configure.certificate_digest(ROTATED_CA): ROTATED_CA})
        self.assertEqual(mac.trusted, {configure._macos_fingerprint(ROTATED_CA)})
        self.assertFalse((self.config / ".friendzone-retired-ca.pem").exists())

    def test_macos_ca_preserves_preexisting_root_and_rejects_invalid_state(self):
        mac = FakeMac()
        mac.trust(TEST_CA)
        result = self.install_macos_ca(mac)
        self.assertFalse(result["installed"])
        self.assertFalse(result["managed"])
        self.assertEqual(mac.calls, [])
        result = self.install_macos_ca(mac, ROTATED_CA)
        self.assertTrue(result["managed"])
        self.assertEqual([call[1] for call in mac.calls], ["add-trusted-cert"])
        # The root that predated setup was never claimed, so rotation keeps it.
        self.assertIn(configure._macos_fingerprint(TEST_CA), mac.trusted)
        state_path = self.config / configure.MACOS_CA_STATE
        state = json.loads(state_path.read_text())
        state["pem"] = TEST_CA
        state_path.write_text(json.dumps(state))
        mac.calls.clear()
        with self.assertRaisesRegex(ValueError, "Invalid Friendzone macOS CA ownership state"):
            self.install_macos_ca(mac, ROTATED_CA)
        self.assertEqual(mac.calls, [])

    def test_macos_ca_failures_restore_previous_trust(self):
        mac = FakeMac()
        self.install_macos_ca(mac)
        before = (dict(mac.certificates), set(mac.trusted))
        state = (self.config / configure.MACOS_CA_STATE).read_text()
        # A cancelled authorization dialog, then a failure while retiring the old root.
        for failing in ("add-trusted-cert", "delete-certificate"):
            mac.fail = lambda arguments, failing=failing: arguments[1] == failing
            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                self.install_macos_ca(mac, ROTATED_CA)
            self.assertEqual((mac.certificates, mac.trusted), before)
            self.assertEqual((self.config / configure.MACOS_CA_STATE).read_text(), state)
            self.assertFalse((self.config / ".friendzone-retired-ca.pem").exists())

    def configure_macos_proxy(self, mac):
        return configure.configure_macos_proxy("192.0.2.1", 9080, self.config, run=mac.run,
                                               networksetup="fixture-networksetup", privilege=[])

    def test_macos_proxy_saves_originals_merges_bypass_and_skips_disabled_services(self):
        corporate = dict(enabled=True, server="proxy.example", port=3128, authenticated=False)
        mac = FakeMac(services={"Wi-Fi": FakeMac.service(bypass=["*.local", "169.254/16", "LOCALHOST"]),
                                "USB LAN": FakeMac.service(web=corporate)},
                      disabled=["Thunderbolt Bridge"])
        result = self.configure_macos_proxy(mac)
        self.assertEqual(result, dict(services=["Wi-Fi", "USB LAN"], changed=True))
        for service in ("Wi-Fi", "USB LAN"):
            for kind in ("web", "secure"):
                self.assertEqual(mac.services[service][kind], dict(enabled=True, server="192.0.2.1", port=9080, authenticated=False))
        self.assertEqual(mac.services["Wi-Fi"]["bypass"], ["*.local", "169.254/16", "LOCALHOST", "192.0.2.1", "127.0.0.1", "::1"])
        self.assertEqual(mac.services["USB LAN"]["bypass"], ["192.0.2.1", "localhost", "127.0.0.1", "::1"])
        self.assertFalse(any("Thunderbolt Bridge" in call for call in mac.calls))
        state_path = self.config / configure.MACOS_PROXY_STATE
        self.assertEqual(json.loads(state_path.read_text())["services"]["USB LAN"]["previous"]["web"], corporate)
        mac.calls.clear()
        self.assertEqual(self.configure_macos_proxy(mac), dict(services=["Wi-Fi", "USB LAN"], changed=False))
        self.assertEqual(mac.calls, [])
        # Reruns keep the first-run originals rather than recording Friendzone's own values.
        self.assertEqual(json.loads(state_path.read_text())["services"]["USB LAN"]["previous"]["web"], corporate)

    def test_macos_proxy_failure_restores_written_settings(self):
        mac = FakeMac(services={"Ethernet": FakeMac.service(bypass=["*.local"])})
        mac.fail = lambda arguments: arguments[1] == "-setproxybypassdomains"
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            self.configure_macos_proxy(mac)
        self.assertFalse(mac.services["Ethernet"]["web"]["enabled"])
        self.assertFalse(mac.services["Ethernet"]["secure"]["enabled"])
        self.assertEqual(mac.services["Ethernet"]["bypass"], ["*.local"])
        self.assertFalse((self.config / configure.MACOS_PROXY_STATE).exists())

    def test_macos_proxy_rejects_authenticated_proxy_and_invalid_host_before_writes(self):
        secure = dict(enabled=True, server="proxy.example", port=8443, authenticated=True)
        mac = FakeMac(services={"Ethernet": FakeMac.service(secure=secure)})
        with self.assertRaisesRegex(ValueError, "authenticated proxy"):
            self.configure_macos_proxy(mac)
        for host in ("-setwebproxy", "host name", "[::1]", ""):
            with self.assertRaisesRegex(ValueError, "Invalid Friendzone macOS proxy address"):
                configure.configure_macos_proxy(host, 9080, self.config, run=mac.run, networksetup="fixture-networksetup", privilege=[])
        self.assertEqual(mac.calls, [])
        self.assertFalse((self.config / configure.MACOS_PROXY_STATE).exists())

    def test_macos_launch_agent_publishes_activated_environment_to_launchd(self):
        configure.configure(self.data, self.home, self.config, self.home / "zsh", {}, "darwin")
        agent = self.home / "Library/LaunchAgents" / (configure.MACOS_AGENT_LABEL + ".plist")
        launchd_env = self.config / "launchd-env.sh"
        with agent.open("rb") as stream:
            self.assertEqual(plistlib.load(stream), dict(Label=configure.MACOS_AGENT_LABEL,
                                                         ProgramArguments=["/bin/sh", str(launchd_env)], RunAtLoad=True))
        self.assertEqual(agent.stat().st_mode & 0o777, 0o644)
        log = self.home / "launchctl.log"
        launchctl = self.home / "launchctl"
        launchctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FZ_TEST_LOG"\n')
        launchctl.chmod(0o755)
        def published(environment):
            # The real script always uses /bin/launchctl; record calls instead.
            script = launchd_env.read_text().replace("/bin/launchctl", str(launchctl))
            log.write_text("")
            subprocess.run(["/bin/sh", "-c", script], check=True,
                           env=dict(environment, PATH="/usr/bin:/bin", FZ_TEST_LOG=str(log)))
            return log.read_text().splitlines()
        calls = published({"NO_PROXY": "corp.example"})
        self.assertIn("setenv HTTPS_PROXY http://192.0.2.1:9080", calls)
        self.assertIn("setenv NODE_EXTRA_CA_CERTS " + str(self.config / "friendzone-ca.pem"), calls)
        self.assertIn("setenv CLINE_API_KEY fake'$(bad)", calls)
        self.assertIn("setenv NO_PROXY 192.0.2.1,localhost,127.0.0.1,::1,[::1],corp.example", calls)
        self.assertIn("setenv BASH_ENV " + str(self.config / "bash-env.sh"), calls)
        self.assertEqual(sum(call.startswith("unsetenv") for call in calls), 0)

        del self.data["fakes"]["GITHUB_TOKEN"]
        configure.configure(self.data, self.home, self.config, self.home / "zsh", {}, "darwin")
        self.assertIn("unsetenv GITHUB_TOKEN", published({"GITHUB_TOKEN": "fz-test-github-token"}))
        self.assertIn("setenv GITHUB_TOKEN user-token", published({"GITHUB_TOKEN": "user-token"}))

        agent.write_bytes(plistlib.dumps(dict(Label="com.example.other")))
        with self.assertRaisesRegex(ValueError, "Unmanaged"):
            configure.configure(self.data, self.home, self.config, self.home / "zsh", {}, "darwin")
        self.assertEqual(plistlib.loads(agent.read_bytes())["Label"], "com.example.other")

    def test_profiles_preserve_and_repeat_without_shadowing(self):
        profile = self.home / ".profile"
        profile.write_text("# original\n", encoding="utf-8")
        (self.home / ".bash_login").write_text("# login\n", encoding="utf-8")
        self.apply({"BASH_ENV": "/old hook.sh"})
        first = profile.read_text(encoding="utf-8")
        self.apply({"BASH_ENV": str(self.config / "bash-env.sh")})
        self.assertEqual(profile.read_text(encoding="utf-8"), first)
        self.assertEqual(first.count(configure.MARKER), 1)
        self.assertFalse((self.home / ".bash_profile").exists())
        self.assertEqual((self.home / ".profile.friendzone-backup").read_text(), "# original\n")
        self.assertIn("/old hook.sh", (self.config / "bash-env.sh").read_text())
        self.assertIn(configure.MARKER, (self.home / "zsh/.zshenv").read_text())
        self.assertNotIn("CLINE_PLUGIN_IDLE_TIMEOUT_MS", (self.config / "friendzone-env.sh").read_text())
        self.assertIn("export CARGO_HTTP_CAINFO=", (self.config / "friendzone-env.sh").read_text())
        managed = (self.config / "friendzone.gitconfig").read_text()
        self.assertEqual(managed, GIT_CONFIG)
        self.assertIn("$GITHUB_TOKEN", managed)
        self.assertNotIn("fz-test-github-token", managed)

    def test_git_helper_is_automatic_and_exactly_github_scoped(self):
        activation = self.apply()
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"
        isolated = self.home / "isolated-global.gitconfig"
        isolated.write_text('[credential]\n\thelper = !f() { if test "$1" = get; then printf "%s\\n" "username=stale" "password=stale"; fi; }; f\n')
        command = r'''. "$1"
test "$GIT_CONFIG_COUNT" = 1
test "$GIT_CONFIG_KEY_0" = include.path
test "$GIT_CONFIG_VALUE_0" = "$2"
github=$(printf 'protocol=https\nhost=github.com\n\n' | GIT_TERMINAL_PROMPT=0 git credential fill)
case "$github" in *'username=x-access-token'*'password=fz-test-github-token'*) ;; *) exit 10;; esac
for input in 'protocol=http\nhost=github.com\n\n' 'protocol=https\nhost=github.com.evil.test\n\n' 'protocol=https\nhost=api.github.com\n\n'; do
  output=$(printf "$input" | GIT_TERMINAL_PROMPT=0 git credential fill 2>&1 || true)
  case "$output" in *fz-test-github-token*) exit 11;; esac
done
unset GITHUB_TOKEN
output=$(printf 'protocol=https\nhost=github.com\n\n' | GIT_TERMINAL_PROMPT=0 git credential fill 2>&1 || true)
case "$output" in *fz-test-github-token*|*username=x-access-token*) exit 12;; esac'''
        result = subprocess.run([bash, "--noprofile", "--norc", "-ec", command, "test", str(activation), str(self.config / "friendzone.gitconfig")],
                                env=dict(os.environ, HOME=str(self.home), GITHUB_TOKEN="outside", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(isolated)), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_removing_github_escrow_retires_only_the_managed_fake(self):
        self.apply()
        old = self.data["fakes"].pop("GITHUB_TOKEN")
        self.data["git_credential_config"] = "# Friendzone managed Git configuration v1\n"
        activation = self.apply({"GITHUB_TOKEN": old})
        environment = (self.config / "friendzone-env.sh").read_text()
        self.assertNotIn("export GITHUB_TOKEN=", environment)
        self.assertIn("unset GITHUB_TOKEN", environment)
        self.assertEqual((self.config / "friendzone.gitconfig").read_text(), self.data["git_credential_config"])
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"
        for current, expected in ((old, ""), ("external-token", "external-token")):
            command = '. "$1"; printf "%s" "${GITHUB_TOKEN-}"'
            result = subprocess.run([bash, "--noprofile", "--norc", "-ec", command, "test", str(activation)],
                                    env=dict(os.environ, GITHUB_TOKEN=current), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout.decode(), expected)

    def test_plugin_install_is_idempotent_custom_home_and_preserves_other_plugins(self):
        cline = self.home / "custom Cline ü"
        (cline / "plugins").mkdir(parents=True)
        other = cline / "plugins/other.js"
        other.write_text("other plugin")
        self.apply({"CLINE_DIR": str(cline)})
        plugin = cline / "plugins/friendzone.js"
        original = plugin.read_bytes()
        self.assertEqual(original, base64.b64decode(self.data["plugin"]))
        self.assertIn(b"module.exports=plugin;", original)
        self.apply({"CLINE_DIR": str(cline)})
        self.assertEqual(plugin.read_bytes(), original)
        self.assertEqual(other.read_text(), "other plugin")
        settings = json.loads((cline / "friendzone.json").read_text())
        self.assertEqual(settings["container"], "guest")
        self.assertEqual(settings["broker"], self.data["broker"])
        plugin.write_text("// manually owned plugin")
        before = (self.config / "friendzone-env.sh").read_bytes()
        self.data["proxy_port"] = 9999
        with self.assertRaises(ValueError):
            self.apply({"CLINE_DIR": str(cline)})
        self.assertEqual((self.config / "friendzone-env.sh").read_bytes(), before)

    def test_upgrade_removes_only_friendzones_legacy_idle_override(self):
        self.config.mkdir()
        env = self.config / "friendzone-env.sh"
        env.write_text("# Friendzone guest environment\nexport CLINE_PLUGIN_IDLE_TIMEOUT_MS=90000000\n")
        activation = self.apply({"CLINE_PLUGIN_IDLE_TIMEOUT_MS": "90000000"})
        text = env.read_text()
        self.assertNotIn("export CLINE_PLUGIN_IDLE_TIMEOUT_MS", text)
        self.assertIn("unset CLINE_PLUGIN_IDLE_TIMEOUT_MS", text)
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"
        command = '. "$1"; test -z "${CLINE_PLUGIN_IDLE_TIMEOUT_MS+x}"'
        result = subprocess.run([bash,"--noprofile","--norc","-ec",command,"test",str(activation)],env=dict(os.environ,CLINE_PLUGIN_IDLE_TIMEOUT_MS="90000000"),capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        # The one-shot marker is gone; a later user value is preserved.
        self.assertFalse((self.config / "remove-legacy-cline-idle-timeout").exists())
        self.apply({"CLINE_PLUGIN_IDLE_TIMEOUT_MS":"user-choice"})
        self.assertNotIn("unset CLINE_PLUGIN_IDLE_TIMEOUT_MS",env.read_text())

    def test_provider_merge_keeps_model_other_credentials_and_rejects_invalid_before_writes(self):
        provider = self.home / ".cline/data/settings/providers.json"
        provider.parent.mkdir(parents=True)
        provider.write_text(json.dumps({"version": 1, "lastUsedProvider": "other", "modes": {}, "providers": {
            "cline": {"settings": {"provider": "cline", "model": "keep", "apiKey": "legacy-static-key",
                                   "auth": {"refreshToken": "stale"}}},
            "other": {"settings": {"key": "preserve"}}}}))
        self.apply()
        root = json.loads(provider.read_text())
        entry = root["providers"]["cline"]
        self.assertEqual(entry["settings"]["model"], "keep")
        # Legacy static keys are gone: the guest only ever holds the OAuth facade.
        self.assertNotIn("apiKey", entry["settings"])
        self.assertEqual(entry["settings"]["auth"], {
            "accessToken": "workos:fake'$(bad)",
            "expiresAt": 253402300799000,
        })
        self.assertEqual(entry["tokenSource"], "oauth")
        self.assertNotIn("manual", provider.read_text())
        self.assertEqual(root["providers"]["other"]["settings"]["key"], "preserve")
        self.assertEqual(root["lastUsedProvider"], "other")
        provider.write_text('{"version":99}')
        before = (self.config / "friendzone-env.sh").read_bytes()
        self.data["proxy_port"] = 9999
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.config / "friendzone-env.sh").read_bytes(), before)

    def test_provider_oauth_facade_contains_only_worthless_guest_credentials(self):
        provider = self.home / ".cline/data/settings/providers.json"
        provider.parent.mkdir(parents=True)
        provider.write_text(json.dumps({"version": 1, "lastUsedProvider": "other", "modes": {}, "providers": {
            "cline": {"settings": {"provider": "cline", "model": "keep", "apiKey": "stale-key",
                                   "auth": {"refreshToken": "stale-refresh", "accountId": "stale-account"}}},
            "other": {"settings": {"key": "preserve"}}}}))
        self.apply()
        root = json.loads(provider.read_text())
        entry = root["providers"]["cline"]
        self.assertEqual(entry["settings"]["model"], "keep")
        self.assertNotIn("apiKey", entry["settings"])
        self.assertEqual(entry["settings"]["auth"], {
            "accessToken": "workos:fake'$(bad)",
            "expiresAt": 253402300799000,
        })
        self.assertEqual(entry["tokenSource"], "oauth")
        self.assertNotIn("refreshToken", json.dumps(entry))
        self.assertNotIn("accountId", json.dumps(entry))
        self.assertEqual(root["providers"]["other"]["settings"]["key"], "preserve")
        self.assertEqual(root["lastUsedProvider"], "other")

    def test_child_shell_activation_no_proxy_and_noninteractive_bash(self):
        previous = self.home / "previous.sh"
        previous.write_text("export PREVIOUS_HOOK=preserved\n")
        activation = self.apply({"BASH_ENV": str(previous)})
        bash = "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else "/bin/bash"
        env = dict(os.environ, HOME=str(self.home), NO_PROXY="existing.test", no_proxy="existing.test,second.test")
        env.pop("BASH_ENV", None)
        env.pop("ENV", None)
        command = '. "$1"; . "$1"; test "$NO_PROXY" = "192.0.2.1,localhost,127.0.0.1,::1,[::1],existing.test,second.test"; bash --noprofile --norc -c \'test "$PREVIOUS_HOOK" = preserved && test "$HTTP_PROXY" = http://192.0.2.1:9080\''
        result = subprocess.run([bash, "--noprofile", "--norc", "-ec", command, "test", str(activation)], env=env, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_manual_hook_is_replaced_and_conflicting_hook_fails(self):
        self.config.mkdir()
        profile = self.home / ".profile"
        profile.write_text('. "$HOME/config/friendzone-env.sh"\n# keep\n')
        self.apply()
        text = profile.read_text()
        self.assertNotIn('"$HOME/config/friendzone-env.sh"', text)
        self.assertEqual(text.count(configure.MARKER), 1)
        profile.write_text(configure.MARKER + "\n. /elsewhere\n")
        with self.assertRaises(ValueError):
            self.apply()

    def test_previous_binary_installation_hook_migrates_in_place(self):
        activation = self.config / "activate.sh"
        quote = "'" + str(activation).replace("'", "'\"'\"'") + "'"
        profile = self.home / ".profile"
        profile.write_text(configure.MARKER + "\nif [ -r {0} ]; then . {0}; fi\n# keep\n".format(quote))
        self.apply()
        self.apply()
        text = profile.read_text()
        self.assertEqual(text.count(configure.MARKER), 1)
        self.assertTrue(text.endswith("# keep\n"))

    def serve_registration(self):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"approved":false,"container":"canonical-guest","message":"Use host approval."}')
            def log_message(self, *args):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.data["broker"] = "http://127.0.0.1:" + str(server.server_port)
        encoded = base64.b64encode(json.dumps(self.data).encode()).decode()
        environment = {"SYSTEMROOT": os.environ.get("SYSTEMROOT", ""), "XDG_CONFIG_HOME": str(self.home / "xdg"), "ZDOTDIR": str(self.home / "zsh"),
                       "HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1"}
        return requests, encoded, environment

    def test_script_main_registers_directly_and_configures_only_temporary_home(self):
        requests, encoded, environment = self.serve_registration()
        # Explicit adapters: never let main discover the developer's home or
        # inherited shell startup paths. Only the fixture listener is contacted.
        with mock.patch.object(configure, "sys", types.SimpleNamespace(platform="linux")), \
                mock.patch.object(configure.Path, "home", return_value=self.home), \
                mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(configure, "install_linux_ca", return_value={"destination": "/fixture/friendzone.crt"}) as install_ca, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            configure.main(encoded)
        self.assertEqual(requests, ["/bootstrap/hello?container=guest"])
        self.assertIn("was replaced with canonical-guest", output.getvalue())
        self.assertIn("Configured guest canonical-guest. Use host approval.", output.getvalue())
        self.assertIn("Linux native trust ready at /fixture/friendzone.crt.", output.getvalue())
        install_ca.assert_called_once()
        self.assertEqual((self.home / "xdg/friendzone/friendzone-ca.pem").read_text(), TEST_CA)
        plugin = json.loads((self.home / ".cline/friendzone.json").read_text())
        self.assertEqual(plugin["container"], "canonical-guest")


    def test_script_main_on_macos_trusts_ca_sets_proxy_and_publishes_environment(self):
        requests, encoded, environment = self.serve_registration()
        config = self.home / "xdg/friendzone"
        with mock.patch.object(configure, "sys", types.SimpleNamespace(platform="darwin")), \
                mock.patch.object(configure.Path, "home", return_value=self.home), \
                mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch.object(configure, "install_linux_ca") as install_linux_ca, \
                mock.patch.object(configure, "install_macos_ca", return_value={"sha256": "ab" * 32}) as install_ca, \
                mock.patch.object(configure, "configure_macos_proxy", return_value={"services": ["Ethernet"], "changed": True}) as proxy, \
                mock.patch.object(configure.subprocess, "run") as run, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            configure.main(encoded)
        self.assertEqual(requests, ["/bootstrap/hello?container=guest"])
        install_linux_ca.assert_not_called()
        install_ca.assert_called_once_with(config / "friendzone-ca.pem", config)
        proxy.assert_called_once_with("127.0.0.1", 9080, config)
        run.assert_called_once_with(["/bin/sh", str(config / "launchd-env.sh")], check=True)
        self.assertIn("macOS System keychain trusts the Friendzone CA (SHA-256 " + "ab" * 32 + ").", output.getvalue())
        self.assertIn("HTTP and HTTPS system proxy set for: Ethernet.", output.getvalue())
        self.assertTrue((self.home / "Library/LaunchAgents" / (configure.MACOS_AGENT_LABEL + ".plist")).exists())
        self.assertIn("Configured guest canonical-guest. Use host approval.", output.getvalue())

if __name__ == "__main__":
    unittest.main()