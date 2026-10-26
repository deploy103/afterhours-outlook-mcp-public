"""Real MSAL flows with fake Microsoft HTTPS; disposable identities/keys only."""

import base64
import hashlib
import io
import json
import logging
import secrets
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from unittest.mock import patch

import requests
from cryptography.fernet import Fernet
from mcp.server.mcpserver.exceptions import ToolError

from oauth import OutlookOAuth, REDIRECT, SCOPES, receive_callback

TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"
OWNER = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
AUTHORITY = "https://login.microsoftonline.com/" + TENANT


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class OAuthContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.key = self.root / "cache-key"
        self.key.write_bytes(Fernet.generate_key())
        self.key.chmod(0o600)
        self.service = OutlookOAuth(TENANT, CLIENT, OWNER, self.root / "state", self.key)
        self.access = secrets.token_urlsafe(40)
        self.refresh = secrets.token_urlsafe(40)
        self.old_refresh = self.refresh
        self.expires_in = 3600
        self.owner = OWNER
        self.claim_overrides = {}
        self.failure = None
        self.token_posts = []
        self.nonce = None
        self.verifier = None
        self.logs = io.StringIO()
        handler = logging.StreamHandler(self.logs)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        # The only replacement is HTTPS I/O; OAuth generation, validation, cache and rotation are real MSAL.
        transport = patch("oauth.SafeSession.request", side_effect=self.request)
        transport.start()
        self.addCleanup(transport.stop)
        network = patch("socket.create_connection", side_effect=AssertionError("real network forbidden"))
        network.start()
        self.addCleanup(network.stop)
        callback = patch("oauth.receive_callback", side_effect=self.callback)
        callback.start()
        self.addCleanup(callback.stop)

    def request(self, method, url, **kwargs):
        self.assertEqual(urlsplit(url).netloc, "login.microsoftonline.com")
        response = requests.Response()
        response.status_code = 200
        if method == "GET":
            self.assertIn("/.well-known/openid-configuration", url)
            result = {"authorization_endpoint": AUTHORITY + "/oauth2/v2.0/authorize",
                      "token_endpoint": AUTHORITY + "/oauth2/v2.0/token",
                      "issuer": AUTHORITY + "/v2.0"}
        elif method == "POST":
            self.assertEqual(url, AUTHORITY + "/oauth2/v2.0/token")
            data = kwargs["data"]
            self.token_posts.append(dict(data))
            if self.failure:
                result = {"error": "invalid_grant", "error_description": self.failure}
                response.status_code = 400
            else:
                if data["grant_type"] == "authorization_code":
                    self.assertEqual(data["redirect_uri"], REDIRECT)
                    self.assertEqual(data["code_verifier"], self.verifier)
                else:
                    self.assertEqual(data["grant_type"], "refresh_token")
                    self.assertEqual(data["refresh_token"], self.refresh)
                    self.refresh = secrets.token_urlsafe(40)
                    self.access = secrets.token_urlsafe(40)
                claims = {"iss": AUTHORITY + "/v2.0", "aud": CLIENT, "iat": int(time.time()),
                          "exp": int(time.time()) + 3600, "tid": TENANT, "oid": self.owner,
                          "sub": "subject", "preferred_username": "dummy@example.invalid", "nonce": self.nonce}
                claims.update(self.claim_overrides)
                result = {"access_token": self.access, "refresh_token": self.refresh,
                          "expires_in": self.expires_in, "token_type": "Bearer",
                          "scope": " ".join(SCOPES), "client_info": b64({"uid": self.owner, "utid": TENANT}),
                          "id_token": b64({"alg": "none"}) + "." + b64(claims) + ".fixture"}
        else:
            self.fail("Unexpected OAuth method")
        response._content = json.dumps(result).encode()
        return response

    def callback(self, flow, show_url):
        query = parse_qs(urlsplit(flow["auth_uri"]).query)
        self.assertEqual(query["response_mode"], ["form_post"])
        self.assertEqual(query["redirect_uri"], [REDIRECT])
        self.assertEqual(query["client_id"], [CLIENT])
        self.assertEqual(set(query["scope"][0].split()), set(SCOPES) | {"openid", "profile", "offline_access"})
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.verifier = flow["code_verifier"]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        self.assertEqual(query["code_challenge"], [challenge])
        self.nonce = query["nonce"][0]
        return {"code": "disposable-code", "state": flow["state"]}

    def test_disconnected_never_contacts_identity_provider(self):
        self.assertEqual(self.service.access_token(), "")
        self.assertEqual(self.token_posts, [])

    def test_pkce_connect_encrypted_persistence_and_local_disconnect(self):
        self.service.connect()
        self.assertEqual(self.service.access_token(), self.access)
        recreated = OutlookOAuth(TENANT, CLIENT, OWNER, self.root / "state", self.key)
        self.assertEqual(recreated.access_token(), self.access)
        self.assertEqual(len(self.token_posts), 1)
        raw = self.service.cache_file.read_bytes()
        for secret in (self.access, self.refresh):
            self.assertNotIn(secret.encode(), raw)
            self.assertNotIn(secret, self.logs.getvalue())
        self.assertEqual(self.service.cache_file.stat().st_mode & 0o777, 0o600)
        recreated.disconnect()
        self.assertEqual(self.service.access_token(), "")
        self.assertEqual(len(self.token_posts), 1)

    def test_expired_access_refreshes_rotates_and_survives_restart(self):
        self.expires_in = -60
        self.service.connect()
        old_access = self.access
        self.expires_in = 3600
        token = self.service.access_token()
        self.assertNotEqual(token, old_access)
        self.assertEqual(token, self.access)
        self.assertNotEqual(self.refresh, self.old_refresh)
        self.assertEqual(len(self.token_posts), 2)
        rotated = list(self.service.load().search("RefreshToken"))
        self.assertEqual([row["secret"] for row in rotated], [self.refresh])
        restarted = OutlookOAuth(TENANT, CLIENT, OWNER, self.root / "state", self.key)
        self.assertEqual(restarted.access_token(), token)
        self.assertEqual(len(self.token_posts), 2)

    def test_refresh_rejection_sanitized_without_interactive_fallback(self):
        self.expires_in = -60
        self.service.connect()
        self.failure = "PRIVATE_PROVIDER_BODY " + self.refresh
        with self.assertRaises(ToolError) as raised:
            self.service.access_token()
        self.assertIn("owner must run", str(raised.exception))
        self.assertNotIn(self.refresh, str(raised.exception))
        self.assertNotIn("PRIVATE_PROVIDER_BODY", self.logs.getvalue())
        self.assertEqual(len(self.token_posts), 2)

    def test_wrong_owner_or_tenant_cache_is_never_used(self):
        self.service.connect()
        for tenant, owner in ((TENANT, OTHER), (OTHER, OWNER)):
            service = OutlookOAuth(tenant, CLIENT, owner, self.root / "state", self.key)
            with self.assertRaises(ToolError):
                service.access_token()
        self.assertEqual(len(self.token_posts), 1)

    def test_invalid_identity_claims_never_replace_working_cache(self):
        self.service.connect()
        previous = self.service.cache_file.read_bytes()
        for claim in ({"oid": OTHER}, {"tid": OTHER}, {"iss": "https://evil.invalid"},
                      {"aud": OTHER}, {"exp": int(time.time()) - 1},
                      {"nbf": int(time.time()) + 600}, {"nonce": "wrong-nonce"}):
            with self.subTest(claim=claim):
                self.claim_overrides = claim
                with self.assertRaises((ValueError, RuntimeError)):
                    self.service.connect()
                self.assertEqual(self.service.cache_file.read_bytes(), previous)

    def test_bad_key_tampering_or_public_cache_fails_closed(self):
        self.service.connect()
        original = self.service.cache_file.read_bytes()
        key = self.key.read_bytes()
        self.key.write_bytes(Fernet.generate_key())
        with self.assertRaises(ToolError):
            self.service.access_token()
        self.key.write_bytes(key)
        self.service.cache_file.write_bytes(original[:-2] + b"xx")
        with self.assertRaises(ToolError):
            self.service.access_token()
        self.service.cache_file.write_bytes(original)
        self.service.cache_file.chmod(0o644)
        with self.assertRaises(ToolError):
            self.service.access_token()
        self.assertEqual(len(self.token_posts), 1)


class CallbackContract(unittest.TestCase):
    def test_loopback_callback_rejects_csrf_and_ambiguous_forms(self):
        ready = threading.Event()
        errors = []
        received = []
        state = secrets.token_urlsafe(32)

        def run():
            try:
                received.append(receive_callback({"state": state, "auth_uri": "https://login.microsoftonline.com/fixture"},
                                                 lambda url: ready.set(), timeout=5))
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(3))
        session = requests.Session()
        session.trust_env = False
        try:
            cases = [("state=wrong&code=private-code", {}),
                     (urlencode({"state": state, "code": "private-code"}), {"Host": "evil.invalid"}),
                     (urlencode({"state": state, "code": "private-code"}) + "&code=second", {}),
                     ("state=%FF&code=private-code", {})]
            for body, headers in cases:
                response = session.post("http://127.0.0.1:8400/", data=body, timeout=3,
                                        headers={"Content-Type": "application/x-www-form-urlencoded"} | headers)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("private-code", response.text)
            response = session.post("http://127.0.0.1:8400/", data={"state": state, "code": "private-code"}, timeout=3)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["cache-control"], "no-store")
            self.assertNotIn("private-code", response.text)
        finally:
            session.close()
            thread.join(7)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(received, [{"state": state, "code": "private-code"}])


if __name__ == "__main__":
    unittest.main()
