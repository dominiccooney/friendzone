import importlib.util
import base64
import contextlib
import http.server
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import types
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "src/bootstrap/configure.py"
spec = importlib.util.spec_from_file_location("configure", SOURCE)
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class GuestScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fz-script-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.config = self.home / "config"
        self.data = dict(broker="http://192.0.2.1:9082", container="guest", proxy_port=9080,
                         plugin=base64.b64encode((SOURCE.parents[1] / "plugin/friendzone.js").read_bytes()).decode(),
                         ca="CERTIFICATE", fakes={"CLINE_API_KEY": "fake'$(bad)", "OTHER_KEY": "other"})

    def apply(self, env=None):
        return configure.configure(self.data, self.home, self.config, self.home / "zsh", env or {})

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
            "cline": {"settings": {"provider": "cline", "model": "keep", "auth": {"refreshToken": "stale"}}},
            "other": {"settings": {"key": "preserve"}}}}))
        self.apply()
        root = json.loads(provider.read_text())
        self.assertEqual(root["providers"]["cline"]["settings"]["model"], "keep")
        self.assertEqual(root["providers"]["cline"]["settings"]["apiKey"], "fake'$(bad)")
        self.assertNotIn("auth", root["providers"]["cline"]["settings"])
        self.assertEqual(root["providers"]["other"]["settings"]["key"], "preserve")
        self.assertEqual(root["lastUsedProvider"], "other")
        provider.write_text('{"version":99}')
        before = (self.config / "friendzone-env.sh").read_bytes()
        self.data["proxy_port"] = 9999
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual((self.config / "friendzone-env.sh").read_bytes(), before)

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

    def test_script_main_registers_directly_and_configures_only_temporary_home(self):
        requests = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"approved":false}')
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
        # Explicit adapters: never let main discover the developer's home or
        # inherited shell startup paths. Only the fixture listener is contacted.
        with mock.patch.object(configure, "sys", types.SimpleNamespace(platform="linux")), \
                mock.patch.object(configure.Path, "home", return_value=self.home), \
                mock.patch.dict(os.environ, environment, clear=True), contextlib.redirect_stdout(io.StringIO()) as output:
            configure.main(encoded)
        self.assertEqual(requests, ["/bootstrap/hello?container=guest"])
        self.assertIn("Approve + pin IP in the host Inbox", output.getvalue())
        self.assertEqual((self.home / "xdg/friendzone/friendzone-ca.pem").read_text(), "CERTIFICATE")


if __name__ == "__main__":
    unittest.main()