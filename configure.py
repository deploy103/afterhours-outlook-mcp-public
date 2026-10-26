#!/usr/bin/env python3
"""Create a new, private single-owner configuration outside this checkout (stdlib only)."""

import argparse
import base64
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shlex
from urllib.parse import urlsplit


def public_origin(value):
    message = "expected an HTTPS origin on port 443, without path, userinfo, query or fragment"
    if not re.fullmatch(r"https://(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::443)?", value):
        raise argparse.ArgumentTypeError(message)
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise argparse.ArgumentTypeError(message) from None
    host = parsed.hostname
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise argparse.ArgumentTypeError(message) from None
    elif (len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                for label in host.split("."))):
        raise argparse.ArgumentTypeError(message)
    return value.lower()


def write_private(path, text, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, help="new directory; parent must exist; never overwritten")
    parser.add_argument("--public-origin", type=public_origin, default="https://mcp.example.com")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent
    root = Path(os.path.abspath(os.path.expanduser(args.directory)))
    # Do not silently follow a directory alias or put secrets inside the clone.
    if root.resolve() != root or root == repo or repo in root.parents:
        parser.error("directory must be outside the checkout, without symlink components")
    os.umask(0o077)
    try:
        root.mkdir(mode=0o700)  # Exclusive mkdir also refuses existing/broken symlinks.
    except OSError:
        parser.error("cannot create a NEW directory; parent must exist and destination must not exist")
    try:
        credentials, state = root / "credentials", root / "state"
        credentials.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        write_private(credentials / "mcp-token", secrets.token_urlsafe(48) + "\n")
        write_private(credentials / "cache-key", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii") + "\n")
        zero = "00000000-0000-0000-0000-000000000000"
        env = {"CREDENTIALS_DIRECTORY": str(credentials), "OUTLOOK_STATE_DIRECTORY": str(state),
               "OUTLOOK_PUBLIC_ORIGIN": args.public_origin, "OUTLOOK_TENANT_ID": zero,
               "OUTLOOK_CLIENT_ID": zero, "OUTLOOK_OWNER_OBJECT_ID": zero}
        write_private(root / "config.env", "".join(f"export {key}={shlex.quote(value)}\n" for key, value in env.items()))
        command = [str(repo / ".venv/bin/python"), "-m", "uvicorn", "server:app", "--factory",
                   "--host", "127.0.0.1", "--port", "8004", "--workers", "1", "--no-access-log", "--no-proxy-headers"]
        write_private(root / "run.sh", "#!/bin/sh\nset -eu\numask 077\n"
                      + f". {shlex.quote(str(root / 'config.env'))}\ncd {shlex.quote(str(repo))}\n"
                      + "exec " + shlex.join(command) + "\n", 0o700)
    except OSError:
        parser.error("configuration incomplete; inspect the new private directory before removing it and retrying")
    print("Private configuration created. Run run.sh in that directory; credentials/mcp-token is the client token FILE.")
    print("Outlook remains not_connected until the owner configures their own Entra app and runs oauth.py connect.")


if __name__ == "__main__":
    main()
