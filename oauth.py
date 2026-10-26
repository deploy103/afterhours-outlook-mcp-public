"""Owner-operated delegated OAuth. No login or token mutation exposed over MCP."""

import argparse
import fcntl
import hmac
import os
import stat
import tempfile
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from uuid import UUID

import msal
import requests
from cryptography.fernet import Fernet
from mcp.server.mcpserver.exceptions import ToolError

SCOPES = ["https://graph.microsoft.com/Mail.Read", "https://graph.microsoft.com/Calendars.ReadBasic"]
REDIRECT = "http://localhost:8400"
RECONNECT = "Outlook authorization unavailable; owner must run oauth.py connect again or check tenant policy"


class SafeSession(requests.Session):
    def __init__(self):
        super().__init__()
        self.trust_env = False

    def request(self, method, url, **kwargs):
        kwargs["timeout"] = (5, 15)
        kwargs["allow_redirects"] = False
        return super().request(method, url, **kwargs)


def _systemd_credential(path, info, fd):
    """Recognize only the root-owned read-only systemd system-service credential mount."""
    directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
    path = Path(path)
    if (directory.parent != Path("/run/credentials") or path.parent != directory
            or path.name not in {"mcp-token", "cache-key"}
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o440
            or info.st_nlink != 1):
        return False
    try:
        # Reject symlink aliases and traversal before inspecting the protected directory.
        if directory.resolve(strict=True) != directory:
            return False
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parent = os.fstat(directory_fd)
            entry = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
            return (parent.st_uid == 0 and parent.st_gid == 0
                    and stat.S_IMODE(parent.st_mode) == 0o550
                    and (entry.st_dev, entry.st_ino) == (info.st_dev, info.st_ino)
                    and info.st_dev == parent.st_dev
                    and bool(os.fstatvfs(directory_fd).f_flag & os.ST_RDONLY)
                    and bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY))
        finally:
            os.close(directory_fd)
    except OSError:
        return False


def private_read(path, maximum=2_097_152, *, systemd_credential=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        private = not info.st_mode & 0o077
        if not private and systemd_credential:
            private = _systemd_credential(path, info, stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not private or info.st_size > maximum:
            raise ValueError("Credential/cache must be a bounded private regular file")
        return stream.read(maximum + 1)


class OutlookOAuth:
    def __init__(self, tenant, client, owner, state, key_file, login_hint=None):
        self.tenant, self.client, self.owner = (str(UUID(value)) for value in (tenant, client, owner))
        self.state = Path(state)
        self.key_file = Path(key_file)
        self.login_hint = login_hint
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state.stat()
        if self.state.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("OAuth state directory must be owner-only (0700)")
        self.cache_file = self.state / "tokens.cache"

    @classmethod
    def from_env(cls):
        credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
        return cls(os.environ["OUTLOOK_TENANT_ID"], os.environ["OUTLOOK_CLIENT_ID"],
                   os.environ["OUTLOOK_OWNER_OBJECT_ID"], os.environ["OUTLOOK_STATE_DIRECTORY"],
                   credentials / "cache-key", os.environ.get("OUTLOOK_LOGIN_HINT"))

    @contextmanager
    def locked(self):
        fd = os.open(self.state / "cache.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def load(self):
        cache = msal.SerializableTokenCache()
        if self.cache_file.exists():
            key = private_read(self.key_file, 128, systemd_credential=True).strip()
            raw = Fernet(key).decrypt(private_read(self.cache_file))
            cache.deserialize(raw.decode())
        return cache

    def save(self, cache):
        key = private_read(self.key_file, 128, systemd_credential=True).strip()
        payload = Fernet(key).encrypt(cache.serialize().encode())
        fd, name = tempfile.mkstemp(prefix=".cache-", dir=self.state)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.cache_file)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    def application(self, cache):
        return msal.PublicClientApplication(
            self.client, authority="https://login.microsoftonline.com/" + self.tenant,
            token_cache=cache, http_client=SafeSession(), instance_discovery=False,
            enable_pii_log=False,
        )

    def is_owner(self, account):
        return (account.get("local_account_id", "").lower() == self.owner
                and account.get("realm", "").lower() == self.tenant)

    def access_token(self):
        try:
            with self.locked():
                cache = self.load()
                # An empty cache is a disconnected service, not an invitation to log in.
                if not list(cache.search(msal.TokenCache.CredentialType.ACCOUNT)):
                    return ""
                app = self.application(cache)
                accounts = [account for account in app.get_accounts() if self.is_owner(account)]
                if len(accounts) != 1:
                    raise ValueError("Owner mismatch")
                result = app.acquire_token_silent_with_error(SCOPES, account=accounts[0])
                if cache.has_state_changed:
                    self.save(cache)  # Persist refresh-token rotation, including failure-side cache updates.
                if not result or not result.get("access_token"):
                    raise ValueError("Interactive authorization required")
                return result["access_token"]
        except Exception:
            # Provider/library/cache exception strings may contain tokens, claims or HTTP bodies.
            raise ToolError(RECONNECT) from None

    def connect(self, show_url=print):
        # Fresh cache: a failed/wrong-account login cannot replace the working owner's cache.
        cache = msal.SerializableTokenCache()
        app = self.application(cache)
        flow = app.initiate_auth_code_flow(SCOPES, redirect_uri=REDIRECT, response_mode="form_post",
                                           login_hint=self.login_hint, prompt="select_account")
        response = receive_callback(flow, show_url)
        result = app.acquire_token_by_auth_code_flow(flow, response)
        claims = result.get("id_token_claims", {})
        # MSAL >=1.38 leaves ID-token claim validation to callers. Tokens come directly
        # from the fixed tenant's TLS token endpoint (OIDC Core 3.1.3.7 item 6).
        # MSAL additionally validates PKCE/state/nonce; never accept a client-submitted ID token.
        if (not result.get("access_token") or claims.get("tid", "").lower() != self.tenant
                or claims.get("oid", "").lower() != self.owner
                or claims.get("iss") != "https://login.microsoftonline.com/" + self.tenant + "/v2.0"
                or claims.get("aud") != self.client
                or claims.get("exp", 0) <= time.time()
                or claims.get("nbf", 0) > time.time() + 120
                or not any(self.is_owner(a) for a in app.get_accounts())):
            raise ValueError("Authorization failed or wrong owner")
        with self.locked():
            self.save(cache)

    def disconnect(self):
        with self.locked():
            self.cache_file.unlink(missing_ok=True)


def receive_callback(flow, show_url, timeout=300):
    """Loopback only, form POST, no request/body logging or provider text rendering."""
    response = {}

    class LoopbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(2)  # Bound incomplete headers as well as form bodies.
            return connection, address

        def handle_error(self, request, client_address):
            pass  # Never log callback request contents or provider text.

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if (self.path != "/" or self.headers.get("Host") not in {"localhost:8400", "127.0.0.1:8400"}
                        or self.headers.get_content_type() != "application/x-www-form-urlencoded"
                        or not 0 < length <= 16384):
                    raise ValueError()
                self.connection.settimeout(2)
                params = parse_qs(self.rfile.read(length).decode(), strict_parsing=True, max_num_fields=20)
                if any(len(value) != 1 for value in params.values()):
                    raise ValueError()
                params = {key: value[0] for key, value in params.items()}
                if not hmac.compare_digest(params.get("state", ""), flow["state"]):
                    raise ValueError()
                if not (params.get("code") or params.get("error")):
                    raise ValueError()
            except (ValueError, TypeError, UnicodeError, OSError):
                self.send_error(400, "Invalid callback")
                return
            response.update(params)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(b"Callback received. Check the owner terminal for the final result. Close this tab.")

    with LoopbackServer(("127.0.0.1", 8400), Handler) as server:
        server.timeout = 1
        show_url(flow["auth_uri"])
        deadline = time.monotonic() + timeout
        while not response and time.monotonic() < deadline:
            server.handle_request()
    if not response:
        raise ValueError("Authorization timed out")
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["connect", "disconnect"])
    args = parser.parse_args()
    # MSAL/HTTP debug logs can contain OAuth messages; the owner CLI emits only its URL and generic status.
    import logging
    logging.disable(logging.CRITICAL)
    try:
        service = OutlookOAuth.from_env()
        if args.command == "connect":
            service.connect()
            print("Owner connected. Tokens were encrypted and stored locally.")
        else:
            service.disconnect()
            print("Local tokens removed. Revoke consent in Microsoft to revoke remote grants.")
    except (Exception, KeyboardInterrupt):
        raise SystemExit("Outlook operation failed; check app registration, owner, callback tunnel and tenant policy") from None


if __name__ == "__main__":
    main()
