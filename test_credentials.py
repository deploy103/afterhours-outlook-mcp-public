"""Credential read policy with disposable files and simulated systemd mount metadata."""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from oauth import private_read


class CredentialContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.addCleanup(os.chmod, self.root, 0o700)
        self.credential = self.root / "mcp-token"
        self.credential.write_bytes(b"disposable-credential")

    def test_regular_credentials_and_cache_remain_owner_only(self):
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(self.root)}):
            for mode in (0o400, 0o600):
                self.credential.chmod(mode)
                self.assertEqual(private_read(self.credential), b"disposable-credential")
            for mode in (0o440, 0o640, 0o644, 0o660):
                self.credential.chmod(mode)
                for allow_systemd in (False, True):
                    with self.subTest(mode=oct(mode), allow_systemd=allow_systemd):
                        with self.assertRaises(ValueError):
                            private_read(self.credential, systemd_credential=allow_systemd)

    def test_only_exact_protected_systemd_credential_mount_is_accepted(self):
        directory = Path("/run/credentials/outlook-test.service")
        self.root.chmod(0o550)
        self.credential.chmod(0o440)
        open_file = os.open
        fstat = os.fstat
        root_owner = True
        readonly = True

        def mapped_open(path, flags, *args, **kwargs):
            path = Path(path)
            if path == directory:
                path = self.root
            elif path.parent == directory:
                path = self.root / path.name
            return open_file(path, flags, *args, **kwargs)

        def metadata(fd):
            values = list(fstat(fd))
            values[4:6] = [0, 0] if root_owner else [123, 123]
            return os.stat_result(values)

        with (patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)}),
              patch("oauth.os.open", side_effect=mapped_open),
              patch("oauth.os.fstat", side_effect=metadata),
              patch("oauth.os.fstatvfs", side_effect=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0)),
              patch.object(Path, "resolve", lambda self, **kwargs: self)):
            token = directory / "mcp-token"
            self.assertEqual(private_read(token, systemd_credential=True), b"disposable-credential")
            # The default read path (used for token caches) never gains the exception.
            with self.assertRaises(ValueError):
                private_read(token)
            for valid_owner, valid_mount in ((False, True), (True, False)):
                root_owner, readonly = valid_owner, valid_mount
                with self.assertRaises(ValueError):
                    private_read(token, systemd_credential=True)
            root_owner, readonly = True, True
            for mode in (0o700, 0o750, 0o555, 0o770):
                self.root.chmod(mode)
                with self.assertRaises(ValueError):
                    private_read(token, systemd_credential=True)
            self.root.chmod(0o550)
            for mode in (0o640, 0o444, 0o660):
                self.credential.chmod(mode)
                with self.assertRaises(ValueError):
                    private_read(token, systemd_credential=True)
            self.credential.chmod(0o440)
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/run/credentials/other.service"}):
                with self.assertRaises(ValueError):
                    private_read(token, systemd_credential=True)
            self.root.chmod(0o700)
            self.credential.rename(self.root / "tokens.cache")
            self.root.chmod(0o550)
            with self.assertRaises(ValueError):
                private_read(directory / "tokens.cache", systemd_credential=True)
        self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
