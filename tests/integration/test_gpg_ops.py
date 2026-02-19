from __future__ import annotations

from pathlib import Path

import pytest

from yubikey_init import KeyType, SecureString
from yubikey_init.gpg_ops import GPGOperations


@pytest.mark.slow
class TestGPGMasterKeyGeneration:
    def test_generate_ed25519_master_key(self, gpg_home: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        passphrase = SecureString("test-passphrase-12345")

        result = ops.generate_master_key(
            identity="Test User <test@example.com>",
            passphrase=passphrase,
            key_type=KeyType.ED25519,
            expiry_days=365,
        )

        assert result.is_ok(), f"Key generation failed: {result.unwrap_err()}"
        key = result.unwrap()
        assert key.identity == "Test User <test@example.com>"
        assert ops.verify_key_exists(key.key_id, secret=True)

    def test_generate_rsa4096_master_key(self, gpg_home: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        passphrase = SecureString("test-passphrase-12345")

        result = ops.generate_master_key(
            identity="RSA User <rsa@example.com>",
            passphrase=passphrase,
            key_type=KeyType.RSA4096,
            expiry_days=365,
        )

        assert result.is_ok(), f"Key generation failed: {result.unwrap_err()}"
        key = result.unwrap()
        assert ops.verify_key_exists(key.key_id, secret=True)


@pytest.mark.slow
class TestGPGKeyExport:
    def test_export_public_key(self, gpg_home: Path, tmp_path: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        passphrase = SecureString("test-passphrase-12345")

        gen_result = ops.generate_master_key(
            identity="Export Test <export@example.com>",
            passphrase=passphrase,
        )
        assert gen_result.is_ok()
        key = gen_result.unwrap()

        output_path = tmp_path / "public.asc"
        export_result = ops.export_public_key(key.key_id, output_path)

        assert export_result.is_ok()
        assert output_path.exists()
        content = output_path.read_text()
        assert "BEGIN PGP PUBLIC KEY BLOCK" in content

    def test_export_secret_keys(self, gpg_home: Path, tmp_path: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        passphrase = SecureString("test-passphrase-12345")

        gen_result = ops.generate_master_key(
            identity="Secret Export Test <secret@example.com>",
            passphrase=passphrase,
        )
        assert gen_result.is_ok()
        key = gen_result.unwrap()

        output_path = tmp_path / "secret.asc"
        export_result = ops.export_secret_keys(key.key_id, passphrase, output_path)

        assert export_result.is_ok()
        assert output_path.exists()
        content = output_path.read_text()
        assert "BEGIN PGP PRIVATE KEY BLOCK" in content


@pytest.mark.slow
class TestGPGKeyImport:
    def test_import_exported_key(self, gpg_home: Path) -> None:
        import shutil
        import tempfile

        ops = GPGOperations(gnupghome=gpg_home)
        passphrase = SecureString("test-passphrase-12345")

        gen_result = ops.generate_master_key(
            identity="Import Test <import@example.com>",
            passphrase=passphrase,
        )
        assert gen_result.is_ok()
        key = gen_result.unwrap()

        # Use short temp path for export file
        export_dir = tempfile.mkdtemp(prefix="exp_")
        export_path = Path(export_dir) / "key.asc"
        ops.export_public_key(key.key_id, export_path)

        # Use short temp path for new GNUPGHOME (avoids socket path length issues)
        new_gpg_home = Path(tempfile.mkdtemp(prefix="gpg2_"))
        new_gpg_home.chmod(0o700)
        new_ops = GPGOperations(gnupghome=new_gpg_home)

        try:
            import_result = new_ops.import_key(export_path)

            assert import_result.is_ok(), f"Import failed: {import_result.unwrap_err()}"
            imported = import_result.unwrap()
            assert new_ops.verify_key_exists(imported.key_id)
        finally:
            shutil.rmtree(export_dir, ignore_errors=True)
            shutil.rmtree(new_gpg_home, ignore_errors=True)


class TestGPGKeyVerification:
    def test_verify_nonexistent_key_returns_false(self, gpg_home: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        assert not ops.verify_key_exists("0000000000000000")

    def test_list_secret_keys_empty_initially(self, gpg_home: Path) -> None:
        ops = GPGOperations(gnupghome=gpg_home)
        result = ops.list_secret_keys()
        assert result.is_ok()
        assert result.unwrap() == []
