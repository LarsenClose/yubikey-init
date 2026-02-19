"""Comprehensive unit tests for gpg_ops module with mocking."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pexpect

from yubikey_init.gpg_ops import GPGError, GPGOperations
from yubikey_init.types import KeySlot, KeyType, KeyUsage, Result, SecureString, SubkeyInfo


class TestGPGOperationsInit:
    """Test GPGOperations initialization."""

    def test_init_without_gnupghome(self) -> None:
        """Test initialization without GNUPGHOME."""
        gpg = GPGOperations()
        assert gpg._gnupghome is None
        assert isinstance(gpg._env, dict)

    def test_init_with_gnupghome(self, tmp_path: Path) -> None:
        """Test initialization with GNUPGHOME."""
        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        gpg = GPGOperations(gnupghome)
        assert gpg._gnupghome == gnupghome
        assert gpg._env["GNUPGHOME"] == str(gnupghome)

    def test_gnupghome_property_with_custom_path(self, tmp_path: Path) -> None:
        """Test gnupghome property returns custom path."""
        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        gpg = GPGOperations(gnupghome)
        assert gpg.gnupghome == gnupghome

    def test_gnupghome_property_with_env_var(self) -> None:
        """Test gnupghome property uses environment variable."""
        with patch.dict(os.environ, {"GNUPGHOME": "/custom/path"}):
            gpg = GPGOperations()
            assert str(gpg.gnupghome) == "/custom/path"

    def test_gnupghome_property_defaults_to_home(self) -> None:
        """Test gnupghome property defaults to ~/.gnupg."""
        with patch.dict(os.environ, {}, clear=True):
            gpg = GPGOperations()
            expected = Path.home() / ".gnupg"
            assert gpg.gnupghome == expected


class TestRunGpg:
    """Test _run_gpg method."""

    def test_run_gpg_basic_command(self) -> None:
        """Test running basic GPG command."""
        gpg = GPGOperations()
        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")
            gpg._run_gpg(["--list-keys"])
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["gpg", "--batch", "--yes", "--list-keys"]

    def test_run_gpg_with_input(self) -> None:
        """Test running GPG command with input text."""
        gpg = GPGOperations()
        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            gpg._run_gpg(["--command"], input_text="input data")
            assert mock_run.call_args[1]["input"] == "input data"

    def test_run_gpg_uses_custom_env(self, tmp_path: Path) -> None:
        """Test GPG command uses custom GNUPGHOME."""
        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        gpg = GPGOperations(gnupghome)
        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            gpg._run_gpg(["--list-keys"])
            env = mock_run.call_args[1]["env"]
            assert env["GNUPGHOME"] == str(gnupghome)


class TestExtractKeyId:
    """Test _extract_key_id method."""

    def test_extract_key_id_from_trusted_message(self) -> None:
        """Test extracting key ID from 'marked as ultimately trusted' message."""
        gpg = GPGOperations()
        output = "gpg: key 1234567890ABCDEF marked as ultimately trusted"
        key_id = gpg._extract_key_id(output)
        assert key_id == "1234567890ABCDEF"

    def test_extract_key_id_from_gpg_message(self) -> None:
        """Test extracting key ID from 'gpg: key' message."""
        gpg = GPGOperations()
        output = "gpg: key ABCDEF1234567890 created"
        key_id = gpg._extract_key_id(output)
        assert key_id == "ABCDEF1234567890"

    def test_extract_key_id_from_fingerprint(self) -> None:
        """Test extracting key ID from fingerprint."""
        gpg = GPGOperations()
        output = "/1234567890ABCDEF1234567890ABCDEF12345678"
        key_id = gpg._extract_key_id(output)
        assert key_id == "1234567890ABCDEF1234567890ABCDEF12345678"

    def test_extract_key_id_returns_none_when_not_found(self) -> None:
        """Test extract returns None when no key ID found."""
        gpg = GPGOperations()
        output = "No key information here"
        key_id = gpg._extract_key_id(output)
        assert key_id is None


class TestGenerateMasterKey:
    """Test generate_master_key method."""

    def test_generate_master_key_ed25519_success(self) -> None:
        """Test generating ED25519 master key successfully."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="gpg: key ABCDEF1234567890 marked as ultimately trusted",
            )
            mock_key_info = MagicMock(spec=KeyInfo)
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.generate_master_key(
                "Test User <test@example.com>",
                passphrase,
                KeyType.ED25519,
                730,
            )

            assert result.is_ok()
            mock_run.assert_called_once()
            # Verify ED25519 parameters in batch script
            batch_script = mock_run.call_args[1]["input_text"]
            assert "Key-Type: eddsa" in batch_script
            assert "Key-Curve: ed25519" in batch_script

    def test_generate_master_key_rsa4096_success(self) -> None:
        """Test generating RSA4096 master key successfully."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="gpg: key DEF4567890123456 marked as ultimately trusted",
            )
            mock_key_info = MagicMock(spec=KeyInfo)
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.generate_master_key(
                "Test User <test@example.com>",
                passphrase,
                KeyType.RSA4096,
                730,
            )

            assert result.is_ok()
            batch_script = mock_run.call_args[1]["input_text"]
            assert "Key-Type: RSA" in batch_script
            assert "Key-Length: 4096" in batch_script

    def test_generate_master_key_failure(self) -> None:
        """Test master key generation failure."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Error: generation failed",
            )

            result = gpg.generate_master_key(
                "Test User <test@example.com>",
                passphrase,
                KeyType.ED25519,
            )

            assert result.is_err()
            assert isinstance(result.unwrap_err(), GPGError)


class TestGetKeyInfo:
    """Test get_key_info method."""

    def test_get_key_info_success(self) -> None:
        """Test getting key info successfully."""
        gpg = GPGOperations()
        key_output = "pub:u:4096:1:ABC123:1640000000:1672000000:::u::::::23::0:\nuid:u::::1640000000::Test User <test@example.com>::::::::::0:"

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_get_uid_for_key", return_value="Test User <test@example.com>"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=key_output, stderr="")

            result = gpg.get_key_info("ABC123")

            assert result.is_ok()
            key_info = result.unwrap()
            assert key_info.key_id == "ABC123"
            assert key_info.identity == "Test User <test@example.com>"

    def test_get_key_info_not_found(self) -> None:
        """Test getting key info when key not found."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No key found")

            result = gpg.get_key_info("NOTFOUND")

            assert result.is_err()
            assert isinstance(result.unwrap_err(), GPGError)


class TestExportKeys:
    """Test key export methods."""

    def test_export_secret_keys_success(self, tmp_path: Path) -> None:
        """Test exporting secret keys successfully."""
        gpg = GPGOperations()
        output_path = tmp_path / "secret.asc"
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.export_secret_keys("ABC123", passphrase, output_path)

            assert result.is_ok()
            assert result.unwrap() == output_path

    def test_export_secret_keys_failure(self, tmp_path: Path) -> None:
        """Test export failure."""
        gpg = GPGOperations()
        output_path = tmp_path / "secret.asc"
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Export failed")

            result = gpg.export_secret_keys("ABC123", passphrase, output_path)

            assert result.is_err()

    def test_export_public_key_success(self, tmp_path: Path) -> None:
        """Test exporting public key successfully."""
        gpg = GPGOperations()
        output_path = tmp_path / "public.asc"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.export_public_key("ABC123", output_path)

            assert result.is_ok()
            assert result.unwrap() == output_path


class TestImportKey:
    """Test import_key method."""

    def test_import_key_success(self, tmp_path: Path) -> None:
        """Test importing key successfully."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        key_path = tmp_path / "key.asc"
        key_path.touch()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="gpg: key ABCDEF1234567890 imported",
            )
            mock_key_info = MagicMock(spec=KeyInfo)
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.import_key(key_path, passphrase)

            assert result.is_ok()

    def test_import_key_without_passphrase(self, tmp_path: Path) -> None:
        """Test importing public key without passphrase."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        key_path = tmp_path / "key.asc"
        key_path.touch()

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="gpg: key ABCDEF1234567890 imported",
            )
            mock_key_info = MagicMock(spec=KeyInfo)
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.import_key(key_path, passphrase=None)

            assert result.is_ok()
            # Verify passphrase-related args not used
            args = mock_run.call_args[0][0]
            assert "--passphrase-fd" not in args


class TestDeleteSecretKey:
    """Test delete_secret_key method."""

    def test_delete_secret_key_without_confirmation(self) -> None:
        """Test deletion without confirmation fails."""
        gpg = GPGOperations()

        result = gpg.delete_secret_key("ABC123", confirm=False)

        assert result.is_err()
        assert "confirmation" in str(result.unwrap_err()).lower()

    def test_delete_secret_key_with_confirmation(self) -> None:
        """Test deletion with confirmation succeeds.

        In batch mode, GPG requires the full fingerprint for deletion.
        """
        gpg = GPGOperations()

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_fp,
            patch.object(gpg, "_run_gpg") as mock_run,
        ):
            mock_fp.return_value = Result.ok("ABCD1234567890ABCDEF1234567890ABCDEF1234")
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.delete_secret_key("ABC123", confirm=True)

            assert result.is_ok()
            # Verify fingerprint was used in deletion command
            delete_call = mock_run.call_args
            assert "ABCD1234567890ABCDEF1234567890ABCDEF1234!" in delete_call[0][0]


class TestVerifyKeyExists:
    """Test verify_key_exists method."""

    def test_verify_key_exists_public(self) -> None:
        """Test verifying public key exists."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            exists = gpg.verify_key_exists("ABC123", secret=False)

            assert exists is True
            args = mock_run.call_args[0][0]
            assert "--list-keys" in args

    def test_verify_key_exists_secret(self) -> None:
        """Test verifying secret key exists."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            exists = gpg.verify_key_exists("ABC123", secret=True)

            assert exists is True
            args = mock_run.call_args[0][0]
            assert "--list-secret-keys" in args

    def test_verify_key_does_not_exist(self) -> None:
        """Test verifying key doesn't exist."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=2)

            exists = gpg.verify_key_exists("NOTFOUND")

            assert exists is False


class TestListSecretKeys:
    """Test list_secret_keys method."""

    def test_list_secret_keys_success(self) -> None:
        """Test listing secret keys successfully."""
        gpg = GPGOperations()
        # Format: uid:validity:cdate:edate:hash-algo:hash-flags:reserved:fpr:reserved:userid
        # The identity is at field index 9
        output = "sec:u:4096:1:ABCDEF1234567890:1640000000:::::::::::\nuid:u::::::::Test User <test@example.com>:"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.list_secret_keys()

            assert result.is_ok()
            keys = result.unwrap()
            assert len(keys) == 1
            assert keys[0].key_id == "ABCDEF1234567890"
            assert keys[0].identity == "Test User <test@example.com>"

    def test_list_secret_keys_empty(self) -> None:
        """Test listing secret keys when none exist."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.list_secret_keys()

            assert result.is_ok()
            assert result.unwrap() == []


class TestGenerateSubkey:
    """Test generate_subkey method."""

    def test_generate_subkey_certify_usage_error(self) -> None:
        """Test that generating CERTIFY subkey returns error."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        result = gpg.generate_subkey(
            "ABC123",
            passphrase,
            KeyUsage.CERTIFY,
            KeyType.ED25519,
        )

        assert result.is_err()
        assert "CERTIFY" in str(result.unwrap_err())

    def test_generate_subkey_ed25519_sign_success(self) -> None:
        """Test generating ED25519 signing subkey using --quick-add-key."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_get_fp,
            patch.object(gpg, "_run_gpg_with_passphrase") as mock_run,
            patch.object(gpg, "_get_latest_subkey") as mock_get_latest,
        ):
            mock_get_fp.return_value = Result.ok("ABCD1234567890ABCD1234567890ABCD12345678")
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            mock_get_latest.return_value = MagicMock(is_ok=lambda: True, unwrap=lambda: "subkey")

            result = gpg.generate_subkey(
                "ABC123",
                passphrase,
                KeyUsage.SIGN,
                KeyType.ED25519,
                730,
            )

            assert result.is_ok()
            # Verify --quick-add-key was called with correct arguments
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "--quick-add-key" in call_args
            assert "ed25519" in call_args
            assert "sign" in call_args
            assert "730d" in call_args

    def test_generate_subkey_ed25519_encrypt_success(self) -> None:
        """Test generating ED25519 encryption subkey (cv25519)."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_get_fp,
            patch.object(gpg, "_run_gpg_with_passphrase") as mock_run,
            patch.object(gpg, "_get_latest_subkey") as mock_get_latest,
        ):
            mock_get_fp.return_value = Result.ok("ABCD1234567890ABCD1234567890ABCD12345678")
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            mock_get_latest.return_value = MagicMock(is_ok=lambda: True, unwrap=lambda: "subkey")

            result = gpg.generate_subkey(
                "ABC123",
                passphrase,
                KeyUsage.ENCRYPT,
                KeyType.ED25519,
                730,
            )

            assert result.is_ok()
            # Encryption uses cv25519, not ed25519
            call_args = mock_run.call_args[0][0]
            assert "cv25519" in call_args
            assert "encr" in call_args

    def test_generate_subkey_rsa_auth_success(self) -> None:
        """Test generating RSA4096 authentication subkey."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_get_fp,
            patch.object(gpg, "_run_gpg_with_passphrase") as mock_run,
            patch.object(gpg, "_get_latest_subkey") as mock_get_latest,
        ):
            mock_get_fp.return_value = Result.ok("ABCD1234567890ABCD1234567890ABCD12345678")
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            mock_get_latest.return_value = MagicMock(is_ok=lambda: True, unwrap=lambda: "subkey")

            result = gpg.generate_subkey(
                "ABC123",
                passphrase,
                KeyUsage.AUTHENTICATE,
                KeyType.RSA4096,
                365,
            )

            assert result.is_ok()
            call_args = mock_run.call_args[0][0]
            assert "rsa4096" in call_args
            assert "auth" in call_args
            assert "365d" in call_args

    def test_generate_subkey_fingerprint_error(self) -> None:
        """Test subkey generation when fingerprint lookup fails."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "get_key_fingerprint") as mock_get_fp:
            mock_get_fp.return_value = Result.err(GPGError("Key not found"))

            result = gpg.generate_subkey(
                "INVALID",
                passphrase,
                KeyUsage.SIGN,
                KeyType.ED25519,
            )

            assert result.is_err()
            assert "Key not found" in str(result.unwrap_err())

    def test_generate_subkey_gpg_failure(self) -> None:
        """Test subkey generation when GPG command fails."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_get_fp,
            patch.object(gpg, "_run_gpg_with_passphrase") as mock_run,
        ):
            mock_get_fp.return_value = Result.ok("ABCD1234567890ABCD1234567890ABCD12345678")
            mock_run.return_value = MagicMock(returncode=1, stderr="gpg: error creating subkey")

            result = gpg.generate_subkey(
                "ABC123",
                passphrase,
                KeyUsage.SIGN,
                KeyType.ED25519,
            )

            assert result.is_err()
            assert "failed" in str(result.unwrap_err()).lower()


class TestGetKeyFingerprint:
    """Test get_key_fingerprint method."""

    def test_get_key_fingerprint_success(self) -> None:
        """Test successful fingerprint lookup."""
        gpg = GPGOperations()
        output = "fpr:::::::::ABCD1234567890ABCD1234567890ABCD12345678:"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.get_key_fingerprint("ABC123")

            assert result.is_ok()
            assert result.unwrap() == "ABCD1234567890ABCD1234567890ABCD12345678"

    def test_get_key_fingerprint_not_found(self) -> None:
        """Test fingerprint lookup when key doesn't exist."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=2, stdout="", stderr="gpg: error reading key"
            )

            result = gpg.get_key_fingerprint("INVALID")

            assert result.is_err()

    def test_get_key_fingerprint_no_fpr_line(self) -> None:
        """Test fingerprint lookup when no fpr line in output."""
        gpg = GPGOperations()
        output = "pub:u:4096:1:ABCDEF1234567890:1640000000:::::::::::"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.get_key_fingerprint("ABC123")

            assert result.is_err()


class TestGenerateAllSubkeys:
    """Test generate_all_subkeys method."""

    def test_generate_all_subkeys_success(self) -> None:
        """Test generating all subkeys successfully."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "generate_subkey") as mock_gen:
            # Return actual Result objects with SubkeyInfo
            mock_gen.return_value = Result.ok(
                SubkeyInfo(
                    key_id="SUB123DEF4567890",
                    fingerprint="SUB123DEF4567890",
                    creation_date=datetime.now(UTC),
                    expiry_date=None,
                    usage=KeyUsage.SIGN,
                    key_type=KeyType.ED25519,
                    parent_key_id="ABCDEF1234567890",
                )
            )

            result = gpg.generate_all_subkeys("ABCDEF1234567890", passphrase, KeyType.ED25519, 730)

            assert result.is_ok()
            subkeys = result.unwrap()
            assert len(subkeys) == 3
            # Verify all three usages were created
            assert mock_gen.call_count == 3

    def test_generate_all_subkeys_partial_failure(self) -> None:
        """Test that failure on any subkey fails the whole operation."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "generate_subkey") as mock_gen:
            # First succeeds, second fails
            mock_gen.side_effect = [
                Result.ok(
                    SubkeyInfo(
                        key_id="SUB123DEF4567890",
                        fingerprint="SUB123DEF4567890",
                        creation_date=datetime.now(UTC),
                        expiry_date=None,
                        usage=KeyUsage.SIGN,
                        key_type=KeyType.ED25519,
                        parent_key_id="ABCDEF1234567890",
                    )
                ),
                Result.err(GPGError("Failed")),
            ]

            result = gpg.generate_all_subkeys("ABCDEF1234567890", passphrase, KeyType.ED25519, 730)

            assert result.is_err()


class TestListSubkeys:
    """Test list_subkeys method."""

    def test_list_subkeys_success(self) -> None:
        """Test listing subkeys successfully."""
        gpg = GPGOperations()
        output = (
            "pub:u:4096:1:ABC123:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::s::::\n"
            "sub:u:4096:1:SUB2:1640000000:1672000000:::::e::::\n"
            "sub:u:4096:1:SUB3:1640000000:1672000000:::::a::::"
        )

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.list_subkeys("ABC123")

            assert result.is_ok()
            subkeys = result.unwrap()
            assert len(subkeys) == 3
            assert subkeys[0].usage == KeyUsage.SIGN
            assert subkeys[1].usage == KeyUsage.ENCRYPT
            assert subkeys[2].usage == KeyUsage.AUTHENTICATE


class TestExportSshKey:
    """Test export_ssh_key method."""

    def test_export_ssh_key_success(self) -> None:
        """Test exporting SSH key successfully."""
        gpg = GPGOperations()
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAA... openpgp:0xABC123"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=ssh_key, stderr="")

            result = gpg.export_ssh_key("ABC123")

            assert result.is_ok()
            assert result.unwrap() == ssh_key.strip()

    def test_export_ssh_key_failure(self) -> None:
        """Test SSH key export failure."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No auth key")

            result = gpg.export_ssh_key("ABC123")

            assert result.is_err()


class TestKeyserverOperations:
    """Test keyserver operations."""

    def test_send_to_keyserver_success(self) -> None:
        """Test sending key to keyserver successfully."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.send_to_keyserver("ABC123")

            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "--send-keys" in args
            assert "ABC123" in args

    def test_send_to_keyserver_custom_server(self) -> None:
        """Test sending to custom keyserver."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.send_to_keyserver("ABC123", keyserver="hkps://custom.server")

            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "hkps://custom.server" in args

    def test_receive_from_keyserver_success(self) -> None:
        """Test receiving key from keyserver."""
        gpg = GPGOperations()

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            mock_get_info.return_value = MagicMock(is_ok=lambda: True, unwrap=lambda: "key_info")

            result = gpg.receive_from_keyserver("ABC123")

            assert result.is_ok()

    def test_search_keyserver_success(self) -> None:
        """Test searching keyserver."""
        gpg = GPGOperations()
        # Key ID must be exactly 16 hex characters to match the regex
        search_output = "(1) Test User <test@example.com>\n      key ABCDEF1234567890"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=search_output,
                stderr="",
            )

            result = gpg.search_keyserver("test@example.com")

            assert result.is_ok()
            keys = result.unwrap()
            assert len(keys) == 1
            assert "ABCDEF1234567890" in keys


class TestCryptographicOperations:
    """Test sign/encrypt/decrypt operations."""

    def test_sign_data_success(self) -> None:
        """Test signing data successfully."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        data = b"Test data to sign"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"-----BEGIN PGP SIGNATURE-----\n...",
                stderr=b"",
            )

            result = gpg.sign_data("ABC123", data, passphrase, detached=True)

            assert result.is_ok()
            # Verify subprocess.run was called with correct args
            args = mock_run.call_args[0][0]
            assert "--detach-sign" in args

    def test_encrypt_data_success(self) -> None:
        """Test encrypting data successfully."""
        gpg = GPGOperations()
        data = b"Secret data"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"-----BEGIN PGP MESSAGE-----\n...",
                stderr=b"",
            )

            result = gpg.encrypt_data("ABC123", data)

            assert result.is_ok()

    def test_encrypt_and_sign_data(self) -> None:
        """Test encrypting and signing data."""
        gpg = GPGOperations()
        data = b"Secret data"
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"-----BEGIN PGP MESSAGE-----\n...",
                stderr=b"",
            )

            result = gpg.encrypt_data(
                "RECIPIENT123",
                data,
                sign_key_id="SIGNER123",
                passphrase=passphrase,
            )

            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "--sign" in args

    def test_decrypt_data_success(self) -> None:
        """Test decrypting data successfully."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        encrypted = b"-----BEGIN PGP MESSAGE-----\n..."

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"Decrypted data",
                stderr=b"",
            )

            result = gpg.decrypt_data(encrypted, passphrase)

            assert result.is_ok()
            assert result.unwrap() == b"Decrypted data"


class TestTransferKeyToCard:
    """Test transfer_key_to_card method.

    Uses subprocess with --command-fd=0 following drduh/YubiKey-Guide approach.
    """

    def test_transfer_key_to_card_success(self) -> None:
        """Test transferring key to card successfully."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.transfer_key_to_card(
                "ABC123",
                passphrase,
                admin_pin,
                KeySlot.SIGNATURE,
                1,
            )

            assert result.is_ok()
            # Verify command structure
            call_args = mock_run.call_args
            cmd = call_args[0][0]
            assert "--command-fd" in cmd
            assert "--pinentry-mode" in cmd
            # Verify input contains expected commands
            input_data = call_args[1]["input"]
            assert "key 1" in input_data
            assert "keytocard" in input_data
            assert "save" in input_data

    def test_transfer_key_to_card_failure(self) -> None:
        """Test transfer failure."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Transfer failed")

            result = gpg.transfer_key_to_card(
                "ABC123",
                passphrase,
                admin_pin,
                KeySlot.SIGNATURE,
                1,
            )

            assert result.is_err()
            assert "Transfer failed" in str(result.unwrap_err())


class TestRenewSubkey:
    """Test renew_subkey and renew_all_subkeys methods."""

    def test_renew_subkey_success(self) -> None:
        """Test renewing a single subkey."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.renew_subkey("ABC123", passphrase, 1, 730)

            assert result.is_ok()
            mock_child.sendline.assert_any_call("key 1")
            mock_child.sendline.assert_any_call("expire")

    def test_renew_all_subkeys_success(self) -> None:
        """Test renewing all subkeys."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        output = "pub:u:4096:1:ABCDEF1234567890:1640000000:::::::::::\nsub:u:4096:1:SUB1234567890123:1640000000:1672000000:::::s::::\nsub:u:4096:1:SUB2345678901234:1640000000:1672000000:::::e::::"

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "renew_subkey") as mock_renew,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
            # Use actual Result object so is_err() returns False
            mock_renew.return_value = Result.ok(None)

            result = gpg.renew_all_subkeys("ABCDEF1234567890", passphrase, 730)

            assert result.is_ok()
            # Should renew both subkeys
            assert mock_renew.call_count == 2


class TestGenerateRevocationCertificate:
    """Test generate_revocation_certificate method."""

    def test_generate_revocation_certificate_success(self, tmp_path: Path) -> None:
        """Test generating revocation certificate."""
        gpg = GPGOperations()
        output_path = tmp_path / "revoke.asc"

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.generate_revocation_certificate(
                "ABC123",
                output_path,
                reason=1,
                description="Key compromised",
            )

            assert result.is_ok()
            assert result.unwrap() == output_path


class TestGenerateMasterKeyFallback:
    """Test generate_master_key fallback paths."""

    def test_generate_master_key_fallback_to_list_keys(self) -> None:
        """Test master key generation falls back to list_secret_keys when key_id not in stderr."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        mock_key_info = MagicMock(spec=KeyInfo)
        mock_key_info.key_id = "FALLBACK123456789"

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_extract_key_id", return_value=None),
            patch.object(gpg, "list_secret_keys") as mock_list,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="no key id pattern here",
            )
            mock_list.return_value = Result.ok([mock_key_info])
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.generate_master_key(
                "Test User <test@example.com>",
                passphrase,
                KeyType.ED25519,
            )

            assert result.is_ok()
            mock_list.assert_called_once()
            mock_get_info.assert_called_with("FALLBACK123456789")

    def test_generate_master_key_fallback_fails_when_no_keys(self) -> None:
        """Test master key generation fails when fallback finds no keys."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_extract_key_id", return_value=None),
            patch.object(gpg, "list_secret_keys") as mock_list,
        ):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            mock_list.return_value = Result.ok([])

            result = gpg.generate_master_key(
                "Test User <test@example.com>",
                passphrase,
                KeyType.ED25519,
            )

            assert result.is_err()
            assert "Could not determine" in str(result.unwrap_err())


class TestExportSecretSubkeys:
    """Test export_secret_subkeys method."""

    def test_export_secret_subkeys_success(self, tmp_path: Path) -> None:
        """Test exporting secret subkeys successfully."""
        gpg = GPGOperations()
        output_path = tmp_path / "subkeys.asc"
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.export_secret_subkeys("ABC123", passphrase, output_path)

            assert result.is_ok()
            assert result.unwrap() == output_path
            args = mock_run.call_args[0][0]
            assert "--export-secret-subkeys" in args

    def test_export_secret_subkeys_failure(self, tmp_path: Path) -> None:
        """Test export secret subkeys failure."""
        gpg = GPGOperations()
        output_path = tmp_path / "subkeys.asc"
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Export failed")

            result = gpg.export_secret_subkeys("ABC123", passphrase, output_path)

            assert result.is_err()


class TestGetUidForKey:
    """Test _get_uid_for_key method."""

    def test_get_uid_for_key_found(self) -> None:
        """Test getting UID for a key."""
        gpg = GPGOperations()
        # Colon-delimited format: uid:validity:cdate:edate:hash-algo:hash-flags:reserved:fpr:reserved:userid
        # Field 9 (index 9) is the userid
        output = "pub:u:4096:1:ABC123:1640000000:::::::\nuid:u::::::::Test User <test@example.com>:"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            uid = gpg._get_uid_for_key("ABC123")

            # Note: field 9 in the colon-delimited output is the user ID
            assert uid == "Test User <test@example.com>"

    def test_get_uid_for_key_not_found(self) -> None:
        """Test getting UID when none found."""
        gpg = GPGOperations()
        output = "pub:u:4096:1:ABC123:1640000000:::::::"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            uid = gpg._get_uid_for_key("ABC123")

            assert uid == ""


class TestAddUid:
    """Test add_uid method."""

    def test_add_uid_success(self) -> None:
        """Test adding UID successfully."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.add_uid(
                "ABC123",
                passphrase,
                "New Name",
                "new@email.com",
                "Optional Comment",
            )

            assert result.is_ok()
            mock_child.sendline.assert_any_call("adduid")
            mock_child.sendline.assert_any_call("New Name")
            mock_child.sendline.assert_any_call("new@email.com")

    def test_add_uid_timeout(self) -> None:
        """Test add_uid handles timeout."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.TIMEOUT("Timeout")
            mock_spawn.return_value = mock_child

            result = gpg.add_uid("ABC123", passphrase, "Name", "email@test.com")

            assert result.is_err()
            assert "Timeout" in str(result.unwrap_err())

    def test_add_uid_eof(self) -> None:
        """Test add_uid handles EOF."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.EOF("EOF")
            mock_spawn.return_value = mock_child

            result = gpg.add_uid("ABC123", passphrase, "Name", "email@test.com")

            assert result.is_err()
            assert "EOF" in str(result.unwrap_err())

    def test_add_uid_non_zero_exit(self) -> None:
        """Test add_uid with non-zero exit status."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 1
            mock_spawn.return_value = mock_child

            result = gpg.add_uid("ABC123", passphrase, "Name", "email@test.com")

            assert result.is_err()


class TestSetPrimaryUid:
    """Test set_primary_uid method."""

    def test_set_primary_uid_success(self) -> None:
        """Test setting primary UID successfully."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.set_primary_uid("ABC123", passphrase, 2)

            assert result.is_ok()
            mock_child.sendline.assert_any_call("uid 2")
            mock_child.sendline.assert_any_call("primary")

    def test_set_primary_uid_timeout(self) -> None:
        """Test set_primary_uid handles timeout."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.TIMEOUT("Timeout")
            mock_spawn.return_value = mock_child

            result = gpg.set_primary_uid("ABC123", passphrase, 1)

            assert result.is_err()
            assert "Timeout" in str(result.unwrap_err())

    def test_set_primary_uid_eof(self) -> None:
        """Test set_primary_uid handles EOF."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.EOF("EOF")
            mock_spawn.return_value = mock_child

            result = gpg.set_primary_uid("ABC123", passphrase, 1)

            assert result.is_err()
            assert "EOF" in str(result.unwrap_err())


class TestRenewSubkeyErrors:
    """Test renew_subkey error handling."""

    def test_renew_subkey_timeout(self) -> None:
        """Test renew_subkey handles timeout."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.TIMEOUT("Timeout")
            mock_spawn.return_value = mock_child

            result = gpg.renew_subkey("ABC123", passphrase, 1, 730)

            assert result.is_err()
            assert "Timeout" in str(result.unwrap_err())

    def test_renew_subkey_eof(self) -> None:
        """Test renew_subkey handles EOF."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.expect.side_effect = pexpect.exceptions.EOF("EOF")
            mock_spawn.return_value = mock_child

            result = gpg.renew_subkey("ABC123", passphrase, 1, 730)

            assert result.is_err()
            assert "EOF" in str(result.unwrap_err())


class TestGetLatestSubkeyErrors:
    """Test _get_latest_subkey error handling."""

    def test_get_latest_subkey_gpg_error(self) -> None:
        """Test _get_latest_subkey handles GPG errors."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Error")

            result = gpg._get_latest_subkey("ABC123", KeyUsage.SIGN)

            assert result.is_err()

    def test_get_latest_subkey_no_subkeys(self) -> None:
        """Test _get_latest_subkey when no subkeys found."""
        gpg = GPGOperations()
        output = "pub:u:4096:1:ABC123:1640000000:::::::"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg._get_latest_subkey("ABC123", KeyUsage.SIGN)

            assert result.is_err()
            assert "No subkeys found" in str(result.unwrap_err())


class TestGetKeyInfoEdgeCases:
    """Test get_key_info edge cases."""

    def test_get_key_info_no_pub_line(self) -> None:
        """Test get_key_info when no pub line found."""
        gpg = GPGOperations()
        output = "uid:u::::::::Test User <test@example.com>:"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.get_key_info("ABC123")

            assert result.is_err()
            assert "not found" in str(result.unwrap_err()).lower()


class TestImportKeyEdgeCases:
    """Test import_key edge cases."""

    def test_import_key_failure(self, tmp_path: Path) -> None:
        """Test import_key failure."""
        gpg = GPGOperations()
        key_path = tmp_path / "key.asc"
        key_path.touch()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Import failed",
            )

            result = gpg.import_key(key_path)

            assert result.is_err()

    def test_import_key_no_key_id_found(self, tmp_path: Path) -> None:
        """Test import_key when key ID cannot be extracted."""
        gpg = GPGOperations()
        key_path = tmp_path / "key.asc"
        key_path.touch()

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_extract_key_id", return_value=None),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="no key id")

            result = gpg.import_key(key_path)

            assert result.is_err()
            assert "Could not determine" in str(result.unwrap_err())


class TestListSecretKeysEdgeCases:
    """Test list_secret_keys edge cases."""

    def test_list_secret_keys_failure(self) -> None:
        """Test list_secret_keys GPG failure."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")

            result = gpg.list_secret_keys()

            assert result.is_err()


class TestExportPublicKeyEdgeCases:
    """Test export_public_key edge cases."""

    def test_export_public_key_failure(self, tmp_path: Path) -> None:
        """Test export_public_key failure."""
        gpg = GPGOperations()
        output_path = tmp_path / "public.asc"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Export failed")

            result = gpg.export_public_key("ABC123", output_path)

            assert result.is_err()


class TestDeleteSecretKeyEdgeCases:
    """Test delete_secret_key edge cases."""

    def test_delete_secret_key_failure(self) -> None:
        """Test delete_secret_key failure."""
        gpg = GPGOperations()

        with (
            patch.object(gpg, "get_key_fingerprint") as mock_fp,
            patch.object(gpg, "_run_gpg") as mock_run,
        ):
            mock_fp.return_value = Result.ok("ABCD1234567890ABCDEF1234567890ABCDEF1234")
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Deletion failed")

            result = gpg.delete_secret_key("ABC123", confirm=True)

            assert result.is_err()

    def test_delete_secret_key_fingerprint_failure(self) -> None:
        """Test delete_secret_key fails when fingerprint lookup fails."""
        gpg = GPGOperations()

        with patch.object(gpg, "get_key_fingerprint") as mock_fp:
            mock_fp.return_value = Result.err(GPGError("Key not found"))

            result = gpg.delete_secret_key("ABC123", confirm=True)

            assert result.is_err()
            assert "fingerprint" in str(result.unwrap_err()).lower()


class TestGenerateMasterKeyBatchScript:
    """Test generate_master_key batch script generation."""

    def test_generate_master_key_identity_parsing(self) -> None:
        """Test master key generation with complex identity."""
        from yubikey_init.types import KeyInfo, Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "get_key_info") as mock_get_info,
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="gpg: key ABCDEF1234567890 marked as ultimately trusted",
            )
            mock_key_info = MagicMock(spec=KeyInfo)
            mock_get_info.return_value = Result.ok(mock_key_info)

            result = gpg.generate_master_key(
                "Test User Jr. <test.user+alias@example.com>",
                passphrase,
                KeyType.ED25519,
                365,
            )

            assert result.is_ok()
            # Verify batch script contains parsed identity
            batch_script = mock_run.call_args[1]["input_text"]
            assert "Name-Real: Test User Jr." in batch_script
            assert "Name-Email: test.user+alias@example.com" in batch_script
            assert "Expire-Date: 365d" in batch_script


class TestGetKeyInfoEdgeCasesExtended:
    """Test get_key_info additional edge cases."""

    def test_get_key_info_with_expiry(self) -> None:
        """Test get_key_info with expiry date."""
        gpg = GPGOperations()
        key_output = "pub:u:4096:1:ABC123:1640000000:1672000000:::u::::::23::0:\nuid:u::::1640000000::Test User <test@example.com>::::::::::0:"

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_get_uid_for_key", return_value="Test User <test@example.com>"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=key_output, stderr="")

            result = gpg.get_key_info("ABC123")

            assert result.is_ok()
            key_info = result.unwrap()
            assert key_info.expiry_date is not None

    def test_get_key_info_multiple_uid_lines(self) -> None:
        """Test get_key_info with multiple UID lines."""
        gpg = GPGOperations()
        key_output = "pub:u:4096:1:ABC123:1640000000:::::::\nuid:u::::::::Primary <primary@example.com>:\nuid:u::::::::Secondary <secondary@example.com>:"

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "_get_uid_for_key", return_value="Primary <primary@example.com>"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=key_output, stderr="")

            result = gpg.get_key_info("ABC123")

            assert result.is_ok()


class TestExportSecretSubkeysEdgeCases:
    """Test export_secret_subkeys edge cases."""

    def test_export_secret_subkeys_uses_correct_command(self, tmp_path: Path) -> None:
        """Test export_secret_subkeys uses correct GPG command."""
        gpg = GPGOperations()
        output_path = tmp_path / "subkeys.asc"
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = gpg.export_secret_subkeys("ABC123", passphrase, output_path)

            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "--export-secret-subkeys" in args
            assert str(output_path) in args


class TestRenewAllSubkeysEdgeCases:
    """Test renew_all_subkeys edge cases."""

    def test_renew_all_subkeys_no_subkeys(self) -> None:
        """Test renew_all_subkeys when no subkeys exist."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        output = "pub:u:4096:1:ABCDEF1234567890:1640000000:::::::::::"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.renew_all_subkeys("ABCDEF1234567890", passphrase, 730)

            # Should succeed with 0 subkeys
            assert result.is_ok()

    def test_renew_all_subkeys_gpg_list_error(self) -> None:
        """Test renew_all_subkeys when listing keys fails."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")

            result = gpg.renew_all_subkeys("ABCDEF1234567890", passphrase, 730)

            assert result.is_err()


class TestTransferAllSubkeysToCard:
    """Test transfer_all_subkeys_to_card method."""

    def test_transfer_all_subkeys_to_card_success(self) -> None:
        """Test transferring all subkeys to card."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        subkeys = [
            SubkeyInfo(
                key_id="SUB1",
                fingerprint="SUB1",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                usage=KeyUsage.SIGN,
                key_type=KeyType.ED25519,
                parent_key_id="ABC123",
            ),
            SubkeyInfo(
                key_id="SUB2",
                fingerprint="SUB2",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                usage=KeyUsage.ENCRYPT,
                key_type=KeyType.ED25519,
                parent_key_id="ABC123",
            ),
            SubkeyInfo(
                key_id="SUB3",
                fingerprint="SUB3",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                usage=KeyUsage.AUTHENTICATE,
                key_type=KeyType.ED25519,
                parent_key_id="ABC123",
            ),
        ]

        with (
            patch.object(gpg, "list_subkeys") as mock_list,
            patch.object(gpg, "transfer_key_to_card") as mock_transfer,
        ):
            mock_list.return_value = Result.ok(subkeys)
            mock_transfer.return_value = Result.ok(None)

            result = gpg.transfer_all_subkeys_to_card("ABC123", passphrase, admin_pin)

            assert result.is_ok()
            assert mock_transfer.call_count == 3

    def test_transfer_all_subkeys_to_card_list_error(self) -> None:
        """Test transfer_all_subkeys_to_card when list fails."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch.object(gpg, "list_subkeys") as mock_list:
            mock_list.return_value = Result.err(GPGError("List failed"))

            result = gpg.transfer_all_subkeys_to_card("ABC123", passphrase, admin_pin)

            assert result.is_err()

    def test_transfer_all_subkeys_to_card_transfer_error(self) -> None:
        """Test transfer_all_subkeys_to_card when transfer fails."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        subkeys = [
            SubkeyInfo(
                key_id="SUB1",
                fingerprint="SUB1",
                creation_date=datetime.now(UTC),
                expiry_date=None,
                usage=KeyUsage.SIGN,
                key_type=KeyType.ED25519,
                parent_key_id="ABC123",
            ),
        ]

        with (
            patch.object(gpg, "list_subkeys") as mock_list,
            patch.object(gpg, "transfer_key_to_card") as mock_transfer,
        ):
            mock_list.return_value = Result.ok(subkeys)
            mock_transfer.return_value = Result.err(GPGError("Transfer failed"))

            result = gpg.transfer_all_subkeys_to_card("ABC123", passphrase, admin_pin)

            assert result.is_err()


class TestListSubkeysEdgeCases:
    """Test list_subkeys edge cases."""

    def test_list_subkeys_empty(self) -> None:
        """Test listing subkeys when none exist."""
        gpg = GPGOperations()
        output = "pub:u:4096:1:ABC123:1640000000:::::::"

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.list_subkeys("ABC123")

            assert result.is_ok()
            assert result.unwrap() == []

    def test_list_subkeys_with_expiry(self) -> None:
        """Test listing subkeys with expiry dates."""
        gpg = GPGOperations()
        output = (
            "pub:u:4096:1:ABC123:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::s::::"
        )

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg.list_subkeys("ABC123")

            assert result.is_ok()
            subkeys = result.unwrap()
            assert len(subkeys) == 1
            assert subkeys[0].expiry_date is not None

    def test_list_subkeys_gpg_error(self) -> None:
        """Test list_subkeys GPG error."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Error")

            result = gpg.list_subkeys("ABC123")

            assert result.is_err()


class TestSignDataEdgeCases:
    """Test sign_data edge cases."""

    def test_sign_data_cleartext_signature(self) -> None:
        """Test signing with cleartext signature."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        data = b"Test data"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"-----BEGIN PGP SIGNED MESSAGE-----\n...",
                stderr=b"",
            )

            result = gpg.sign_data("ABC123", data, passphrase, detached=False)

            assert result.is_ok()
            # Verify --sign was used instead of --detach-sign
            args = mock_run.call_args[0][0]
            assert "--sign" in args
            assert "--detach-sign" not in args

    def test_sign_data_failure(self) -> None:
        """Test sign_data failure."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        data = b"Test data"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout=b"",
                stderr=b"Signing failed",
            )

            result = gpg.sign_data("ABC123", data, passphrase)

            assert result.is_err()


class TestEncryptDataEdgeCases:
    """Test encrypt_data edge cases."""

    def test_encrypt_data_without_signing(self) -> None:
        """Test encryption without signing."""
        gpg = GPGOperations()
        data = b"Secret data"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=b"-----BEGIN PGP MESSAGE-----\n...",
                stderr=b"",
            )

            result = gpg.encrypt_data("RECIPIENT123", data)

            assert result.is_ok()
            # Verify no signing was done
            args = mock_run.call_args[0][0]
            assert "--sign" not in args

    def test_encrypt_data_failure(self) -> None:
        """Test encrypt_data failure."""
        gpg = GPGOperations()
        data = b"Secret data"

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout=b"",
                stderr=b"Encryption failed",
            )

            result = gpg.encrypt_data("RECIPIENT123", data)

            assert result.is_err()


class TestDecryptDataEdgeCases:
    """Test decrypt_data edge cases."""

    def test_decrypt_data_failure(self) -> None:
        """Test decrypt_data failure."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        encrypted = b"-----BEGIN PGP MESSAGE-----\n..."

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout=b"",
                stderr=b"Decryption failed",
            )

            result = gpg.decrypt_data(encrypted, passphrase)

            assert result.is_err()


class TestGenerateRevocationCertificateEdgeCases:
    """Test generate_revocation_certificate edge cases."""

    def test_generate_revocation_certificate_failure(self, tmp_path: Path) -> None:
        """Test revocation certificate generation failure."""
        gpg = GPGOperations()
        output_path = tmp_path / "revoke.asc"

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 1  # Non-zero exit status = failure
            mock_spawn.return_value = mock_child

            result = gpg.generate_revocation_certificate("ABC123", output_path)

            assert result.is_err()

    def test_generate_revocation_certificate_with_reason(self, tmp_path: Path) -> None:
        """Test revocation certificate with specific reason."""
        gpg = GPGOperations()
        output_path = tmp_path / "revoke.asc"

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.generate_revocation_certificate(
                "ABC123",
                output_path,
                reason=1,
                description="Key compromised",
            )

            assert result.is_ok()
            # Verify reason and description were sent via sendline
            sendline_calls = [str(c) for c in mock_child.sendline.call_args_list]
            assert any("1" in c for c in sendline_calls)  # reason code
            assert any("Key compromised" in c for c in sendline_calls)  # description

    def test_generate_revocation_certificate_with_passphrase(self, tmp_path: Path) -> None:
        """Test revocation certificate generation with passphrase for protected key.

        Regression test: previously the function didn't accept passphrase, causing
        revocation certificate generation to fail for passphrase-protected keys.

        Uses pexpect for interactive prompt handling.
        """
        gpg = GPGOperations()
        output_path = tmp_path / "revoke.asc"
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            result = gpg.generate_revocation_certificate(
                "ABC123",
                output_path,
                passphrase=passphrase,
                reason=0,
                description="",
            )

            assert result.is_ok()

            # Verify pexpect was called with correct command
            mock_spawn.assert_called_once()
            call_args = mock_spawn.call_args
            cmd_name = call_args[0][0]
            cmd_args = call_args[0][1]

            assert cmd_name == "gpg"
            assert "--pinentry-mode" in cmd_args
            assert "loopback" in cmd_args
            assert "--gen-revoke" in cmd_args
            assert "ABC123" in cmd_args

            # Verify interactive prompts were answered
            assert mock_child.expect.called
            assert mock_child.sendline.called

            # Check that passphrase was sent (should be one of the sendline calls)
            sendline_calls = [str(c) for c in mock_child.sendline.call_args_list]
            assert any("test-passphrase" in c for c in sendline_calls)


class TestKeyserverSearchEdgeCases:
    """Test search_keyserver edge cases."""

    def test_search_keyserver_no_results(self) -> None:
        """Test search_keyserver with no results."""
        gpg = GPGOperations()

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="No keys found",
                stderr="",
            )

            result = gpg.search_keyserver("nonexistent@example.com")

            assert result.is_ok()
            assert result.unwrap() == []

    def test_search_keyserver_multiple_keys(self) -> None:
        """Test search_keyserver with multiple results."""
        gpg = GPGOperations()
        search_output = (
            "(1) First User <first@example.com>\n"
            "      key ABCDEF1234567890\n"
            "(2) Second User <second@example.com>\n"
            "      key 1234567890ABCDEF"
        )

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=search_output,
                stderr="",
            )

            result = gpg.search_keyserver("test@example.com")

            assert result.is_ok()
            keys = result.unwrap()
            assert len(keys) == 2
            assert "ABCDEF1234567890" in keys
            assert "1234567890ABCDEF" in keys


class TestSendToKeyserverEdgeCases:
    """Test send_to_keyserver edge cases."""

    def test_send_to_keyserver_failure(self) -> None:
        """Test send_to_keyserver failure."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Upload failed")

            result = gpg.send_to_keyserver("ABC123")

            assert result.is_err()


class TestReceiveFromKeyserverEdgeCases:
    """Test receive_from_keyserver edge cases."""

    def test_receive_from_keyserver_failure(self) -> None:
        """Test receive_from_keyserver failure."""
        gpg = GPGOperations()

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Download failed")

            result = gpg.receive_from_keyserver("ABC123")

            assert result.is_err()


class TestTransferKeyToCardEdgeCases:
    """Test transfer_key_to_card edge cases."""

    def test_transfer_key_to_card_different_slots(self) -> None:
        """Test transferring to different card slots."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            # Test encryption slot
            result = gpg.transfer_key_to_card(
                "ABC123",
                passphrase,
                admin_pin,
                KeySlot.ENCRYPTION,
                2,
            )

            assert result.is_ok()
            input_data = mock_run.call_args[1]["input"]
            assert "key 2" in input_data
            # Slot 2 for encryption
            lines = input_data.split("\n")
            assert "2" in lines  # Encryption slot number

            # Test authentication slot
            result = gpg.transfer_key_to_card(
                "ABC123",
                passphrase,
                admin_pin,
                KeySlot.AUTHENTICATION,
                3,
            )

            assert result.is_ok()
            input_data = mock_run.call_args[1]["input"]
            assert "key 3" in input_data

    def test_transfer_key_to_card_timeout(self) -> None:
        """Test transfer_key_to_card timeout error."""
        import subprocess

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="gpg", timeout=120)

            result = gpg.transfer_key_to_card(
                "ABC123",
                passphrase,
                admin_pin,
                KeySlot.SIGNATURE,
                1,
            )

            assert result.is_err()


class TestGetLatestSubkeyVariants:
    """Test _get_latest_subkey with different usage types."""

    def test_get_latest_subkey_encrypt(self) -> None:
        """Test getting latest encryption subkey."""
        gpg = GPGOperations()
        output = (
            "pub:u:4096:1:ABC123:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::e::::"
        )

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg._get_latest_subkey("ABC123", KeyUsage.ENCRYPT)

            assert result.is_ok()
            subkey = result.unwrap()
            assert subkey.usage == KeyUsage.ENCRYPT

    def test_get_latest_subkey_authenticate(self) -> None:
        """Test getting latest authentication subkey."""
        gpg = GPGOperations()
        output = (
            "pub:u:4096:1:ABC123:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::a::::"
        )

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            result = gpg._get_latest_subkey("ABC123", KeyUsage.AUTHENTICATE)

            assert result.is_ok()
            subkey = result.unwrap()
            assert subkey.usage == KeyUsage.AUTHENTICATE

    def test_get_latest_subkey_no_matching_capabilities(self) -> None:
        """Test getting latest subkey when no exact match found."""
        gpg = GPGOperations()
        output = (
            "pub:u:4096:1:ABC123:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::s::::"
        )

        with patch.object(gpg, "_run_gpg") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")

            # Request encryption but only sign exists - should return most recent
            result = gpg._get_latest_subkey("ABC123", KeyUsage.ENCRYPT)

            assert result.is_ok()


class TestRenewAllSubkeysError:
    """Test renew_all_subkeys error path."""

    def test_renew_all_subkeys_partial_error(self) -> None:
        """Test renew_all_subkeys when one renewal fails."""
        from yubikey_init.types import Result

        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        output = (
            "pub:u:4096:1:ABCDEF1234567890:1640000000:::::::::::\n"
            "sub:u:4096:1:SUB1:1640000000:1672000000:::::s::::\n"
            "sub:u:4096:1:SUB2:1640000000:1672000000:::::e::::"
        )

        with (
            patch.object(gpg, "_run_gpg") as mock_run,
            patch.object(gpg, "renew_subkey") as mock_renew,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
            # First renewal succeeds, second fails
            mock_renew.side_effect = [
                Result.ok(None),
                Result.err(GPGError("Renewal failed")),
            ]

            result = gpg.renew_all_subkeys("ABCDEF1234567890", passphrase, 730)

            assert result.is_err()


class TestPexpectCommandFlags:
    """Test that all pexpect-based GPG commands use correct flags.

    These tests verify that:
    1. --pinentry-mode loopback is present (allows passphrase input via pexpect)
    2. --status-fd is NOT present (it outputs machine-readable status that breaks prompt matching)
    3. --command-fd is NOT present (pexpect handles stdin/stdout through the pty)

    This test class exists because all unit tests were passing but the actual
    functionality was broken due to --status-fd and --command-fd interfering with pexpect prompts.
    """

    def _verify_command_flags(self, cmd_args: list[str]) -> None:
        """Helper to verify command has correct flags."""
        # Verify --pinentry-mode loopback is present
        assert "--pinentry-mode" in cmd_args, "--pinentry-mode should be in command args"
        pinentry_idx = cmd_args.index("--pinentry-mode")
        assert cmd_args[pinentry_idx + 1] == "loopback", "--pinentry-mode should be loopback"

        # Verify --status-fd is NOT present (it breaks pexpect prompt matching)
        assert "--status-fd" not in cmd_args, "--status-fd should NOT be in command args"

        # Verify --command-fd is NOT present (pexpect handles stdin/stdout through pty)
        assert "--command-fd" not in cmd_args, "--command-fd should NOT be in command args"

    def test_add_uid_uses_correct_flags(self) -> None:
        """Test add_uid uses --pinentry-mode loopback, not --status-fd."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            gpg.add_uid("ABC123", passphrase, "Test User", "test@example.com")

            mock_spawn.assert_called_once()
            cmd_args = mock_spawn.call_args[0][1]
            self._verify_command_flags(cmd_args)

    def test_set_primary_uid_uses_correct_flags(self) -> None:
        """Test set_primary_uid uses --pinentry-mode loopback, not --status-fd."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            gpg.set_primary_uid("ABC123", passphrase, 1)

            mock_spawn.assert_called_once()
            cmd_args = mock_spawn.call_args[0][1]
            self._verify_command_flags(cmd_args)

    def test_renew_subkey_uses_correct_flags(self) -> None:
        """Test renew_subkey uses --pinentry-mode loopback, not --status-fd."""
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")

        with patch("yubikey_init.gpg_ops.pexpect.spawn") as mock_spawn:
            mock_child = MagicMock()
            mock_child.exitstatus = 0
            mock_spawn.return_value = mock_child

            gpg.renew_subkey("ABC123", passphrase, 1, 730)

            mock_spawn.assert_called_once()
            cmd_args = mock_spawn.call_args[0][1]
            self._verify_command_flags(cmd_args)

    def test_transfer_key_to_card_uses_correct_flags(self) -> None:
        """Test transfer_key_to_card uses correct flags following drduh guide.

        Uses subprocess with --command-fd=0 approach from drduh/YubiKey-Guide
        which is more reliable than interactive pexpect.
        """
        gpg = GPGOperations()
        passphrase = SecureString("test-passphrase")
        admin_pin = SecureString("12345678")

        with patch("yubikey_init.gpg_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            gpg.transfer_key_to_card("ABC123", passphrase, admin_pin, KeySlot.SIGNATURE, 1)

            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]

            # Verify --command-fd 0 is present (drduh guide approach)
            assert "--command-fd" in cmd
            cmd_fd_idx = cmd.index("--command-fd")
            assert cmd[cmd_fd_idx + 1] == "0"

            # Verify --pinentry-mode loopback is present
            assert "--pinentry-mode" in cmd
            pinentry_idx = cmd.index("--pinentry-mode")
            assert cmd[pinentry_idx + 1] == "loopback"
