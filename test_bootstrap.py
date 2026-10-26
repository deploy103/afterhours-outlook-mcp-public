"""Public bootstrap CLI and generated real loopback launcher; no provider grants or I/O."""

import base64
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parent
PORT = 8004


class BootstrapCLI(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.root = self.parent / "owner's $config ; directory"
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

    def configure(self, *arguments, directory=None):
        return subprocess.run([sys.executable, "-B", str(REPO / "configure.py"), "--directory",
                               str(directory or self.root), *arguments], cwd=self.parent,
                              env=self.env, capture_output=True, text=True, timeout=10)

    def environment(self):
        return dict(shlex.split(line.removeprefix("export "))[0].split("=", 1)
                    for line in (self.root / "config.env").read_text().splitlines())

    def test_private_config_random_secrets_and_no_overwrite(self):
        result = self.configure()
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in (self.root, self.root / "credentials", self.root / "state"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        files = [self.root / "config.env", self.root / "credentials/mcp-token", self.root / "credentials/cache-key"]
        for path in files:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / "run.sh").stat().st_mode & 0o777, 0o700)
        token = (self.root / "credentials/mcp-token").read_text().strip()
        self.assertIsNotNone(re.fullmatch(r"[A-Za-z0-9_-]{64}", token))
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn(token, (self.root / "config.env").read_text())
        self.assertNotIn(token, (self.root / "run.sh").read_text())
        env = self.environment()
        self.assertEqual(env["CREDENTIALS_DIRECTORY"], str(self.root / "credentials"))
        self.assertEqual(env["OUTLOOK_PUBLIC_ORIGIN"], "https://mcp.example.com")
        for key in ("TENANT_ID", "CLIENT_ID", "OWNER_OBJECT_ID"):
            self.assertEqual(env["OUTLOOK_" + key], "00000000-0000-0000-0000-000000000000")
        key = (self.root / "credentials/cache-key").read_text().strip()
        self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)
        self.assertNotIn(key, result.stdout + result.stderr)
        self.assertEqual(env["OUTLOOK_STATE_DIRECTORY"], str(self.root / "state"))
        before = {str(path): path.read_bytes() for path in files + [self.root / "run.sh"]}
        self.assertNotEqual(self.configure().returncode, 0)
        self.assertEqual(before, {str(path): path.read_bytes() for path in files + [self.root / "run.sh"]})
        other = self.parent / "second"
        self.assertEqual(self.configure(directory=other).returncode, 0)
        self.assertNotEqual(token, (other / "credentials/mcp-token").read_text().strip())

    def test_existing_directories_files_and_symlinks_refused(self):
        self.root.mkdir()
        self.assertNotEqual(self.configure().returncode, 0)
        self.assertEqual(list(self.root.iterdir()), [])
        for name, target in (("alias", self.root), ("broken", self.parent / "missing")):
            alias = self.parent / name
            alias.symlink_to(target, target_is_directory=True)
            self.assertNotEqual(self.configure(directory=alias).returncode, 0)
            self.assertTrue(alias.is_symlink())
        self.assertNotEqual(self.configure(directory=self.parent / "alias" / "new").returncode, 0)
        self.assertFalse((self.root / "new").exists())
        ordinary = self.parent / "file"
        ordinary.write_text("keep")
        self.assertNotEqual(self.configure(directory=ordinary).returncode, 0)
        self.assertEqual(ordinary.read_text(), "keep")

    def test_invalid_origins_leave_no_configuration(self):
        for origin in ("http://mcp.example.com", "https://mcp.example.com/", "https://mcp.example.com/mcp",
                       "https://user@mcp.example.com", "https://:pass@mcp.example.com", "https://mcp.example.com?",
                       "https://mcp.example.com#", "https://mcp.example.com:8003", "https://mcp.example.com:0443",
                       "https://mcp.example.com:", "https://", "https://bad..host", "https://bad_host",
                       "https://mcp.example.com\n", "https://mcp.example.com\t", "https://[:::]",
                       "https://mcp.example.com\\evil", "https://mcp.example.com?q=x", "https://mcp.example.com#x"):
            with self.subTest(origin=origin):
                self.assertNotEqual(self.configure("--public-origin", origin).returncode, 0)
                self.assertFalse(self.root.exists())

    def test_required_directory_and_expansion_and_valid_origins(self):
        missing = subprocess.run([sys.executable, "-B", str(REPO / "configure.py")], env=self.env,
                                 capture_output=True, timeout=10)
        self.assertNotEqual(missing.returncode, 0)
        self.env["HOME"] = str(self.parent)
        self.assertEqual(self.configure("--public-origin", "https://MCP.Example.com:443", directory="~/tilde").returncode, 0)
        self.assertIn("https://mcp.example.com:443", (self.parent / "tilde/config.env").read_text())
        self.assertEqual(self.configure("--public-origin", "https://[::1]:443", directory="relative").returncode, 0)
        self.assertTrue((self.parent / "relative/run.sh").is_file())
        self.assertNotEqual(self.configure(directory=REPO).returncode, 0)
        self.assertNotEqual(self.configure(directory=REPO / "private-test").returncode, 0)

    def request(self, method, path, body=None, token=None):
        headers = {"Host": "mcp.example.com", "Origin": "https://mcp.example.com",
                   "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if body:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=2)
        try:
            connection.request(method, path, json.dumps(body) if body else None, headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_generated_run_sh_real_mcp_defaults_not_connected(self):
        result = self.configure("--public-origin", "https://mcp.example.com:443")
        self.assertEqual(result.returncode, 0, result.stderr)
        launcher = (self.root / "run.sh").read_text()
        for required in (str(REPO / ".venv/bin/python"), "-m uvicorn", "--workers 1",
                         "--no-access-log", "--no-proxy-headers", f"--host 127.0.0.1 --port {PORT}"):
            self.assertIn(required, launcher)
        process = subprocess.Popen([str(self.root / "run.sh")], cwd=self.parent, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 12
            while True:
                if process.poll() is not None:
                    self.fail("launcher exited: " + process.communicate(timeout=2)[1])
                try:
                    status, raw = self.request("GET", "/healthz")
                    if status == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    self.fail("launcher did not become healthy")
                time.sleep(0.05)
            self.assertEqual(json.loads(raw)["status"], "ok")
            self.assertEqual(self.request("POST", "/mcp")[0], 401)
            token = (self.root / "credentials/mcp-token").read_text().strip()

            def rpc(method, params):
                status, raw = self.request("POST", "/mcp", {"jsonrpc": "2.0", "id": 1,
                                                            "method": method, "params": params}, token)
                self.assertEqual(status, 200, raw)
                self.assertNotIn(token.encode(), raw)
                return json.loads(raw)["result"]

            self.assertIn("serverInfo", rpc("initialize", {"protocolVersion": "2025-11-25",
                            "capabilities": {}, "clientInfo": {"name": "bootstrap-test", "version": "1"}}))
            tools = rpc("tools/list", {})["tools"]
            self.assertEqual(len(tools), 3)
            result = rpc("tools/call", {"name": "outlook_status", "arguments": {}})
            self.assertFalse(result.get("isError"), result)
            data = result.get("structuredContent") or json.loads(result["content"][0]["text"])
            self.assertEqual(data["status"], "not_connected")
            self.assertFalse(data["connected"])
            self.assertTrue(data["read_only"])
            self.assertFalse((self.root / "state/tokens.cache").exists())
        finally:
            process.terminate()
            try:
                output, errors = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                output, errors = process.communicate(timeout=2)
            token = (self.root / "credentials/mcp-token").read_text().strip()
            self.assertNotIn(token, output + errors)

    def test_generated_env_supports_outlook_cache_and_disconnect_cli(self):
        self.assertEqual(self.configure().returncode, 0)
        program = """
from oauth import OutlookOAuth
from cryptography.fernet import Fernet
service = OutlookOAuth.from_env()
assert service.access_token() == ''
cache = service.load()
cache.deserialize('{"AccessToken": {}}')
service.save(cache)
assert service.load().serialize() == cache.serialize()
assert Fernet(service.key_file.read_bytes().strip()).decrypt(service.cache_file.read_bytes())
"""
        result = subprocess.run(["/bin/sh", "-c", '. "$1"; exec "$2" -B -c "$3"', "bootstrap-test",
                                 str(self.root / "config.env"), sys.executable, program], cwd=REPO,
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(["/bin/sh", "-c", '. "$1"; exec "$2" -B oauth.py disconnect', "bootstrap-test",
                                 str(self.root / "config.env"), sys.executable], cwd=REPO,
                                env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "state/tokens.cache").exists())


if __name__ == "__main__":
    unittest.main()
