# AfterHours Outlook MCP

Single-owner, authenticated Streamable HTTP MCP for read-only inbox previews and
basic calendar data through Microsoft Graph. Use **your own Entra application
and delegated consent**, independently of browser logins or other MCP servers.
There is no scheduler/background monitoring, message sending/replies/deletion,
read-state change, calendar mutation, full mail body or attachment download.

## Fresh clone and disconnected startup

Linux/POSIX, Python 3.11+ and a private local account are required. This public
repository can be cloned without GitHub authentication; Outlook still requires your own delegated consent.

```sh
git clone https://github.com/deploy103/afterhours-outlook-mcp-public.git
cd afterhours-outlook-mcp-public
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements.lock.txt
.venv/bin/python -m pip check
mkdir -p "$HOME/.config"
.venv/bin/python configure.py --directory "$HOME/.config/afterhours-outlook-mcp" \
  --public-origin https://mcp.example.com
"$HOME/.config/afterhours-outlook-mcp/run.sh"
```

Replace the example origin with your own HTTPS hostname before exposing the
service. The option defaults to `https://mcp.example.com`; only HTTPS origins on
443 (implicit or explicit) are accepted, with no trailing slash/path, userinfo,
query or fragment. The destination must be **new**, outside the checkout, with
an existing parent and no symlink components. `~` and relative paths become
absolute paths. There is no overwrite option. Partial failures leave the new
private directory for inspection, never recursively delete it. Choose a new
directory to regenerate; retire the old configuration deliberately.

The stdlib bootstrap creates secrets without printing them:

```text
~/.config/afterhours-outlook-mcp/            0700
  config.env                              0600 (exported paths, origin, zero UUIDs)
  run.sh                                  0700
  credentials/                            0700
    mcp-token                             0600 (random MCP bearer)
    cache-key                             0600 (random Fernet encryption key)
  state/                                  0700 (encrypted OAuth cache after consent)
```

Keep this directory out of Git, logs and chat. The three all-zero UUID settings
permit startup with no configured owner or consent. `outlook_status` then returns
`not_connected` without Microsoft I/O. Health `GET /healthz` proves only process
liveness. `run.sh` sources `config.env`, changes to the absolute checkout path,
and executes its `.venv/bin/python -m uvicorn server:app --factory` on
**127.0.0.1:8004**, one worker, no access logs and no proxy headers. All paths are
shell-quoted. Moving the checkout/venv requires a new configuration or a deliberate
launcher update.

## Client and HTTPS proxy

Internal MCP path is `/mcp`. Your own TLS reverse proxy must pass Authorization
and preserve the configured external Host, stripping any prefix (for example
`/outlook/mcp` → `/mcp`). Set `OUTLOOK_PUBLIC_ORIGIN` in the private `config.env`
to match your HTTPS hostname. Host/Origin are exact allowlists, not wildcard CORS.
For local MCP checks use `Host: mcp.example.com` (or your configured host), even
though the socket address is `127.0.0.1:8004`. No proxy/firewall/service is installed.
Keep the proxy on this host or design a separate authenticated TLS/VPN transport;
never expose a bearer over untrusted HTTP. Suppress sensitive proxy access/debug logs.

Register `https://YOUR_HOST/outlook/mcp` (or your chosen proxy path) as a
Streamable HTTP server in your client. The header is `Authorization: Bearer
<MCP token>`, **not** a Microsoft token. The token **file** is
`$HOME/.config/afterhours-outlook-mcp/credentials/mcp-token`; use the client's
protected file/secret input if available. The file path is not the bearer value.
Do not put the value in command arguments/history or chat. A bearer holder can
read this owner's data; this is not multi-user OAuth. Replace the private token
file and restart to rotate it.

## Register your own Entra app and authorize with PKCE

1. In your own organizational tenant, create an Entra app registration:
   **Single tenant**, **Mobile and desktop applications / public client**.
   Register redirect URI **`http://localhost:8400`** (Microsoft also supports
   the localhost port exception when `http://localhost` is registered). Do not
   use a Web/SPA platform, client secret, or another application's client ID.
   Check the tenant's public client flow setting/policy.
2. Add Microsoft Graph **delegated** `Mail.Read` and `Calendars.ReadBasic` only.
   No `Mail.Send`, ReadWrite or Application permissions. MSAL additionally
   requests `openid profile offline_access` for identity and refresh tokens.
3. Stop the launcher. Edit the generated private `config.env`, replacing:
   - `OUTLOOK_TENANT_ID`: your Directory (tenant) UUID.
   - `OUTLOOK_CLIENT_ID`: your Application (client) UUID.
   - `OUTLOOK_OWNER_OBJECT_ID`: your user **Object ID (oid) in that tenant**.
     This is not an email address. A wrong tenant/owner fails closed.
   - Optional `export OUTLOOK_LOGIN_HINT=...` is only a login hint, not an
     authorization check; quote shell values properly.
   Keep `CREDENTIALS_DIRECTORY` pointing to the generated `credentials/` and
   `OUTLOOK_STATE_DIRECTORY` to its `state/`. Do not generate another cache-key
   for an existing encrypted cache. Keep file mode 0600.
4. If the browser is on another computer, first open an authenticated tunnel
   **on the browser's computer**:

   ```sh
   ssh -N -L 8400:127.0.0.1:8400 YOUR_SSH_USER@YOUR_OUTLOOK_HOST
   ```

   Then, **in the checkout on the server**, run as the same UID that owns the
   generated configuration and will run the launcher:

   ```sh
   umask 077
   . "$HOME/.config/afterhours-outlook-mcp/config.env"
   .venv/bin/python oauth.py connect
   ```

   `config.env` exports **all** needed environment variables including
   `CREDENTIALS_DIRECTORY` (where `cache-key` is read) and
   `OUTLOOK_STATE_DIRECTORY` (where `tokens.cache`/`cache.lock` are written).
   No systemd credential mount is needed for this fresh-clone CLI workflow.
5. Open the printed Microsoft authorize URL in your own browser, sign in as the
   exact configured owner and consent. This URL is transient authorization
   material: do not share/log it. PKCE S256, state and nonce are checked by
   MSAL; the CLI additionally checks tenant, owner, issuer, audience and time
   claims. The loopback callback accepts form POST only on `127.0.0.1:8400`
   and times out after five minutes. No public callback route is exposed.
   A received callback is not proof of success: check the terminal's final
   result. Failed/wrong-owner consent does not replace a working cache.
6. Restart `run.sh`, then call `outlook_status` from your authenticated client.
   `inbox_access_verified` means a real inbox ID read succeeded; it does **not**
   verify calendar permission. Call `outlook_calendar` separately to check that.

Tenant app-registration rules, user-consent restrictions, admin consent, MFA and
Conditional Access may block this flow. Obtain the tenant administrator's
approval; do not bypass policy or extract browser sessions. Personal Microsoft
accounts/multi-tenant login are not supported by this owner/tenant contract.

The OAuth cache is Fernet-encrypted in `state/tokens.cache` (0600), locked across
processes and atomically replaced; the separate `credentials/cache-key` must be
preserved. No mail/calendar data is stored. MSAL refreshes on demand and persists
refresh-token rotation. Expiry/revocation/policy can require interactive CLI
reconnection; no permanent-login guarantee or automatic Graph retry is provided.
Fernet is not protection against compromise of the same OS account holding both
cache and key.

To disconnect locally, stop the launcher, source the same environment and run:

```sh
. "$HOME/.config/afterhours-outlook-mcp/config.env"
.venv/bin/python oauth.py disconnect
```

This removes local tokens only; revoke the app grant in Microsoft/Entra to revoke
remote access. An in-flight read may already hold a token. Restart disconnected
if desired.

## Tools and deployment boundaries

- `outlook_status`: disconnected on an empty cache; otherwise verifies inbox
  access only. Credential/provider errors are tool errors, not connected status.
- `outlook_inbox(limit=20)`: latest 1–50 INBOX previews, newest first, original
  message IDs/source/links/received timestamps. No full bodies or attachments.
- `outlook_calendar(start,end,limit=20)`: 1–50 occurrences from the default
  calendar, explicit timezone-aware timestamps with seconds, max 31 elapsed
  days. Preserves UTC and original timezone facts.

Reads use fixed Graph `/me` HTTPS GET endpoints, no arbitrary URL/OData inputs,
TLS validation, no ambient proxies/redirects, 15-second timeout, 1 MiB response
limit. Only one page is fetched; `has_more` is not a complete scan. Returned
mail text and links are untrusted source data, never instructions.

`deploy/` contains optional systemd/nginx/env **templates**, not an installation.
Review identity/paths/private state/Host and credential mounts before using them;
do not overwrite existing services. General credential/cache files are 0400/0600.
The code also recognizes its tightly bounded root-owned read-only systemd
`/run/credentials/<unit>` contract (0440 files / 0550 directory), not arbitrary
group-readable files. No shared systemd, production or Vooy configuration is
changed by the bootstrap. Dependencies retain their upstream licenses/notices;
this project's license is [MIT](LICENSE).

## Offline checks and limits

```sh
.venv/bin/python -B -m unittest -v
.venv/bin/python -m pip check
```

Tests use disposable keys/cache and fake provider I/O; bootstrap tests exercise
the CLI, modes, no-overwrite, origin validation, and the generated launcher's
real loopback MCP `not_connected` status. They do not contact Microsoft.
Actual Entra registration/consent, tenant policy, account access and public
TLS/proxy deployment require owner validation. Hash-locked dependencies are in
`requirements.lock.txt`.

Official references:
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://learn.microsoft.com/en-us/entra/msal/python/getting-started/acquiring-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/reply-url
