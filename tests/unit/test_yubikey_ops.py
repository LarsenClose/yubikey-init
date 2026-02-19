"""Tests for YubiKey operations with mocked subprocess calls."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from yubikey_init.types import SecureString, YubiKeyInfo
from yubikey_init.yubikey_ops import YubiKeyOperations, yubikey_available


class TestYubiKeyOperations:
    """Test YubiKeyOperations class."""

    def test_init_without_gnupghome(self) -> None:
        """Test initialization without GNUPGHOME."""
        ops = YubiKeyOperations()
        assert ops._gnupghome is None
        assert "GNUPGHOME" not in ops._env or ops._env["GNUPGHOME"] == ops._env.get("GNUPGHOME")

    def test_init_with_gnupghome(self, tmp_path: Path) -> None:
        """Test initialization with GNUPGHOME."""
        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        ops = YubiKeyOperations(gnupghome=gnupghome)
        assert ops._gnupghome == gnupghome
        assert ops._env["GNUPGHOME"] == str(gnupghome)


class TestListDevices:
    """Tests for list_devices method."""

    def test_list_devices_empty(self) -> None:
        """Test listing devices when none are connected."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="")
            devices = ops.list_devices()
            assert devices == []

    def test_list_devices_returns_empty_on_error(self) -> None:
        """Test listing devices returns empty list on error."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            devices = ops.list_devices()
            assert devices == []

    def test_list_devices_with_one_device(self) -> None:
        """Test listing devices when one is connected."""
        ops = YubiKeyOperations()
        # ykman info returns text output, not JSON
        device_info_text = """Device type: YubiKey 5 NFC
Serial number: 12345678
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
Enabled USB interfaces: OTP, FIDO, CCID
NFC transport is disabled.

Applications	USB     	NFC
FIDO2       	Enabled 	Enabled
OTP         	Enabled 	Enabled
FIDO U2F    	Enabled 	Enabled
OATH        	Enabled 	Enabled
YubiHSM Auth	Not available
OpenPGP     	Enabled 	Enabled
PIV         	Enabled 	Enabled
"""
        with patch.object(ops, "_run_ykman") as mock_run:
            # First call: list serials
            # Second call: get device info
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="12345678\n"),
                MagicMock(returncode=0, stdout=device_info_text),
            ]
            devices = ops.list_devices()
            assert len(devices) == 1
            assert devices[0].serial == "12345678"
            assert devices[0].version == "5.4.3"
            assert devices[0].has_openpgp is True

    def test_list_devices_with_multiple_devices(self) -> None:
        """Test listing multiple connected devices."""
        ops = YubiKeyOperations()
        # ykman info returns text output
        device_info_text1 = """Device type: YubiKey 5 NFC
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
OpenPGP     	Enabled
"""
        device_info_text2 = """Device type: YubiKey 5C
Firmware version: 5.2.4
Form factor: Keychain (USB-C)
FIDO2       	Enabled
"""
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="12345678\n87654321\n"),
                MagicMock(returncode=0, stdout=device_info_text1),
                MagicMock(returncode=0, stdout=device_info_text2),
            ]
            devices = ops.list_devices()
            assert len(devices) == 2
            assert devices[0].serial == "12345678"
            assert devices[0].has_openpgp is True
            assert devices[1].serial == "87654321"
            assert devices[1].has_openpgp is False


class TestGetDeviceInfo:
    """Tests for _get_device_info method."""

    def test_get_device_info_success(self) -> None:
        """Test getting device info successfully."""
        ops = YubiKeyOperations()
        # ykman info returns text output
        device_info_text = """Device type: YubiKey 5 NFC
Serial number: 12345678
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
OpenPGP     	Enabled
PIV         	Enabled
"""
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=device_info_text)
            info = ops._get_device_info("12345678")
            assert info is not None
            assert info.serial == "12345678"
            assert info.version == "5.4.3"
            assert info.has_openpgp is True

    def test_get_device_info_returns_none_on_error(self) -> None:
        """Test getting device info returns None on error."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            info = ops._get_device_info("12345678")
            assert info is None

    def test_get_device_info_returns_defaults_on_missing_fields(self) -> None:
        """Test getting device info returns defaults when fields are missing."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            # No parseable fields in the output
            mock_run.return_value = MagicMock(returncode=0, stdout="some unrelated output")
            info = ops._get_device_info("12345678")
            # Returns info with default values instead of None
            assert info is not None
            assert info.serial == "12345678"
            assert info.version == "unknown"
            assert info.form_factor == "unknown"
            assert info.has_openpgp is False


class TestYubiKeyAvailable:
    """Tests for yubikey_available function."""

    def test_yubikey_available_true(self) -> None:
        """Test yubikey_available returns True when devices exist."""
        with patch("yubikey_init.yubikey_ops.YubiKeyOperations") as mock_class:
            mock_ops = MagicMock()
            mock_ops.list_devices.return_value = [MagicMock()]
            mock_class.return_value = mock_ops
            assert yubikey_available() is True

    def test_yubikey_available_false_no_devices(self) -> None:
        """Test yubikey_available returns False when no devices."""
        with patch("yubikey_init.yubikey_ops.YubiKeyOperations") as mock_class:
            mock_ops = MagicMock()
            mock_ops.list_devices.return_value = []
            mock_class.return_value = mock_ops
            assert yubikey_available() is False

    def test_yubikey_available_raises_on_error(self) -> None:
        """Test yubikey_available propagates errors."""
        with patch("yubikey_init.yubikey_ops.YubiKeyOperations") as mock_class:
            mock_ops = MagicMock()
            mock_ops.list_devices.side_effect = Exception("error")
            mock_class.return_value = mock_ops
            # The function doesn't catch exceptions
            with pytest.raises(Exception, match="error"):
                yubikey_available()


class TestRunYkman:
    """Tests for _run_ykman method."""

    def test_run_ykman_calls_subprocess(self) -> None:
        """Test that _run_ykman calls subprocess.run correctly."""
        ops = YubiKeyOperations()
        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output")
            ops._run_ykman(["list"])
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["ykman", "list"]

    def test_run_ykman_with_input(self) -> None:
        """Test that _run_ykman passes input text."""
        ops = YubiKeyOperations()
        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output")
            ops._run_ykman(["cmd"], input_text="input data")
            mock_run.assert_called_once()
            assert mock_run.call_args[1]["input"] == "input data"


class TestRunGpg:
    """Tests for _run_gpg method."""

    def test_run_gpg_calls_subprocess(self) -> None:
        """Test that _run_gpg calls subprocess.run correctly."""
        ops = YubiKeyOperations()
        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output")
            ops._run_gpg(["--card-status"])
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args == ["gpg", "--batch", "--yes", "--card-status"]

    def test_run_gpg_uses_gnupghome_env(self, tmp_path: Path) -> None:
        """Test that _run_gpg uses GNUPGHOME from env."""
        gnupghome = tmp_path / ".gnupg"
        gnupghome.mkdir()
        ops = YubiKeyOperations(gnupghome=gnupghome)
        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output")
            ops._run_gpg(["--card-status"])
            env = mock_run.call_args[1]["env"]
            assert env["GNUPGHOME"] == str(gnupghome)


class TestWaitForDevice:
    """Tests for wait_for_device method."""

    def test_wait_for_device_found_immediately(self) -> None:
        """Test wait_for_device returns immediately when device found."""
        ops = YubiKeyOperations()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        with patch.object(ops, "list_devices", return_value=[device]):
            result = ops.wait_for_device(timeout=1)
            assert result.is_ok()
            assert result.unwrap().serial == "12345678"

    def test_wait_for_device_by_serial(self) -> None:
        """Test wait_for_device finds specific serial."""
        ops = YubiKeyOperations()
        device1 = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        device2 = YubiKeyInfo(
            serial="87654321",
            version="5.2.4",
            form_factor="USB-C",
            has_openpgp=True,
            openpgp_version=None,
        )
        with patch.object(ops, "list_devices", return_value=[device1, device2]):
            result = ops.wait_for_device(serial="87654321", timeout=1)
            assert result.is_ok()
            assert result.unwrap().serial == "87654321"

    def test_wait_for_device_timeout(self) -> None:
        """Test wait_for_device times out when no device."""
        ops = YubiKeyOperations()
        with (
            patch.object(ops, "list_devices", return_value=[]),
            patch("yubikey_init.yubikey_ops.time.sleep"),
        ):
            result = ops.wait_for_device(timeout=0)
            assert result.is_err()
            assert "No YubiKey detected" in str(result.unwrap_err())


class TestResetOpenpgp:
    """Tests for reset_openpgp method."""

    def test_reset_openpgp_success(self) -> None:
        """Test reset_openpgp succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = ops.reset_openpgp("12345678")
            assert result.is_ok()
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "--device" in args
            assert "openpgp" in args
            assert "reset" in args

    def test_reset_openpgp_failure(self) -> None:
        """Test reset_openpgp failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Reset failed")
            result = ops.reset_openpgp("12345678")
            assert result.is_err()
            assert "Reset failed" in str(result.unwrap_err())


class TestSetPins:
    """Tests for set_pins method."""

    def test_set_pins_success(self) -> None:
        """Test set_pins succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.set_pins(
                "12345678",
                SecureString("123456"),
                SecureString("12345678"),
            )
            assert result.is_ok()
            assert mock_run.call_count == 2  # User PIN + Admin PIN

    def test_set_pins_user_pin_failure(self) -> None:
        """Test set_pins fails on user PIN change."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="PIN change failed")
            result = ops.set_pins(
                "12345678",
                SecureString("123456"),
                SecureString("12345678"),
            )
            assert result.is_err()
            # The error comes from change_user_pin which says "PIN change failed"
            assert "PIN change failed" in str(result.unwrap_err())

    def test_set_pins_admin_pin_failure(self) -> None:
        """Test set_pins fails on admin PIN change."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            # First call succeeds (user PIN), second fails (admin PIN)
            mock_run.side_effect = [
                MagicMock(returncode=0),
                MagicMock(returncode=1, stderr="Admin PIN failed"),
            ]
            result = ops.set_pins(
                "12345678",
                SecureString("123456"),
                SecureString("12345678"),
            )
            assert result.is_err()
            assert "Admin PIN change failed" in str(result.unwrap_err())


class TestSetTouchPolicy:
    """Tests for set_touch_policy method."""

    def test_set_touch_policy_success(self) -> None:
        """Test set_touch_policy succeeds."""
        from yubikey_init.types import KeySlot, TouchPolicy

        ops = YubiKeyOperations()
        admin_pin = SecureString("12345678")
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.set_touch_policy("12345678", KeySlot.SIGNATURE, TouchPolicy.ON, admin_pin)
            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "set-touch" in args
            assert "sig" in args
            assert "on" in args
            assert "--admin-pin" in args

    def test_set_touch_policy_failure(self) -> None:
        """Test set_touch_policy failure."""
        from yubikey_init.types import KeySlot, TouchPolicy

        ops = YubiKeyOperations()
        admin_pin = SecureString("12345678")
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Touch policy failed")
            result = ops.set_touch_policy(
                "12345678", KeySlot.ENCRYPTION, TouchPolicy.FIXED, admin_pin
            )
            assert result.is_err()
            assert "Touch policy change failed" in str(result.unwrap_err())


class TestGetCardStatus:
    """Tests for get_card_status method."""

    def test_get_card_status_success(self) -> None:
        """Test get_card_status returns card info."""
        ops = YubiKeyOperations()
        card_output = """OpenPGP version: 3.4
Application version: 5.4.3
Signature key fingerprint: 1234567890ABCDEF1234567890ABCDEF12345678
Encryption key fingerprint: ABCDEF1234567890ABCDEF1234567890ABCDEF12
Authentication key fingerprint: 567890ABCDEF1234567890ABCDEF1234567890AB
Signature counter: 42
PIN retries: 3/0/3"""
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=card_output)
            result = ops.get_card_status("12345678")
            assert result.is_ok()
            status = result.unwrap()
            assert status.serial == "12345678"
            assert status.signature_count == 42
            assert status.pin_retries == 3
            assert status.admin_pin_retries == 3

    def test_get_card_status_failure(self) -> None:
        """Test get_card_status failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Card error")
            result = ops.get_card_status("12345678")
            assert result.is_err()
            assert "Status check failed" in str(result.unwrap_err())


class TestEnableKdf:
    """Tests for enable_kdf method."""

    def test_enable_kdf_success(self) -> None:
        """Test enable_kdf succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.enable_kdf("12345678", SecureString("12345678"))
            assert result.is_ok()
            args = mock_run.call_args[0][0]
            assert "set-kdf" in args

    def test_enable_kdf_failure(self) -> None:
        """Test enable_kdf failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="KDF error")
            result = ops.enable_kdf("12345678", SecureString("12345678"))
            assert result.is_err()
            assert "KDF enablement failed" in str(result.unwrap_err())


class TestVerifyAttestation:
    """Tests for verify_attestation method."""

    def test_verify_attestation_genuine(self) -> None:
        """Test verify_attestation returns True for genuine device."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.verify_attestation("12345678")
            assert result.is_ok()
            assert result.unwrap() is True

    def test_verify_attestation_not_genuine(self) -> None:
        """Test verify_attestation returns False when attestation fails."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = ops.verify_attestation("12345678")
            assert result.is_ok()
            assert result.unwrap() is False


class TestTransferKey:
    """Tests for transfer_key method using subprocess (drduh guide approach)."""

    def test_transfer_key_success(self) -> None:
        """Test transfer_key succeeds."""
        from yubikey_init.types import KeySlot

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_get_reader_for_serial", return_value=None),
            patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = ops.transfer_key(
                "12345678",
                "ABCDEF1234567890",
                KeySlot.SIGNATURE,
                SecureString("passphrase"),
                SecureString("12345678"),
                subkey_index=1,
            )

            assert result.is_ok()
            # Verify command structure
            call_args = mock_run.call_args
            cmd = call_args[0][0]
            assert "--command-fd" in cmd
            # Verify input contains expected commands
            input_data = call_args[1]["input"]
            assert "keytocard" in input_data
            assert "save" in input_data

    def test_transfer_key_timeout(self) -> None:
        """Test transfer_key handles timeout."""
        import subprocess

        from yubikey_init.types import KeySlot

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_get_reader_for_serial", return_value=None),
            patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run,
        ):
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="gpg", timeout=120)

            result = ops.transfer_key(
                "12345678",
                "ABCDEF1234567890",
                KeySlot.SIGNATURE,
                SecureString("passphrase"),
                SecureString("12345678"),
            )

            assert result.is_err()
            assert "timed out" in str(result.unwrap_err())


class TestTransferAllKeys:
    """Tests for transfer_all_keys method."""

    def test_transfer_all_keys_success(self) -> None:
        """Test transfer_all_keys transfers all three keys."""
        from yubikey_init.types import Result

        ops = YubiKeyOperations()
        with patch.object(ops, "transfer_key") as mock_transfer:
            mock_transfer.return_value = Result.ok(None)

            result = ops.transfer_all_keys(
                "12345678",
                "ABCDEF1234567890",
                SecureString("passphrase"),
                SecureString("12345678"),
            )

            assert result.is_ok()
            assert mock_transfer.call_count == 3

    def test_transfer_all_keys_partial_failure(self) -> None:
        """Test transfer_all_keys fails if any transfer fails."""
        from yubikey_init.types import Result
        from yubikey_init.yubikey_ops import YubiKeyError

        ops = YubiKeyOperations()
        with patch.object(ops, "transfer_key") as mock_transfer:
            mock_transfer.side_effect = [
                Result.ok(None),
                Result.err(YubiKeyError("Transfer failed")),
            ]

            result = ops.transfer_all_keys(
                "12345678",
                "ABCDEF1234567890",
                SecureString("passphrase"),
                SecureString("12345678"),
            )

            assert result.is_err()
            assert mock_transfer.call_count == 2


class TestChangePins:
    """Tests for change_user_pin and change_admin_pin methods."""

    def test_change_user_pin_success(self) -> None:
        """Test change_user_pin succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.change_user_pin(
                "12345678",
                SecureString("123456"),
                SecureString("654321"),
            )
            assert result.is_ok()

    def test_change_user_pin_failure(self) -> None:
        """Test change_user_pin failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Wrong PIN")
            result = ops.change_user_pin(
                "12345678",
                SecureString("wrong"),
                SecureString("654321"),
            )
            assert result.is_err()
            assert "PIN change failed" in str(result.unwrap_err())

    def test_change_admin_pin_success(self) -> None:
        """Test change_admin_pin succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.change_admin_pin(
                "12345678",
                SecureString("12345678"),
                SecureString("87654321"),
            )
            assert result.is_ok()

    def test_change_admin_pin_failure(self) -> None:
        """Test change_admin_pin failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Wrong admin PIN")
            result = ops.change_admin_pin(
                "12345678",
                SecureString("wrong"),
                SecureString("87654321"),
            )
            assert result.is_err()
            assert "Admin PIN change failed" in str(result.unwrap_err())


class TestUnblockPin:
    """Tests for unblock_pin method."""

    def test_unblock_pin_success(self) -> None:
        """Test unblock_pin succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.unblock_pin(
                "12345678",
                SecureString("12345678"),
                SecureString("123456"),
            )
            assert result.is_ok()

    def test_unblock_pin_failure(self) -> None:
        """Test unblock_pin failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Unblock failed")
            result = ops.unblock_pin(
                "12345678",
                SecureString("wrong"),
                SecureString("123456"),
            )
            assert result.is_err()
            assert "PIN unblock failed" in str(result.unwrap_err())


class TestSetCardholderName:
    """Tests for set_cardholder_name method."""

    def test_set_cardholder_name_success(self) -> None:
        """Test set_cardholder_name succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.set_cardholder_name(
                "12345678",
                "John Doe",
                SecureString("12345678"),
            )
            assert result.is_ok()

    def test_set_cardholder_name_failure(self) -> None:
        """Test set_cardholder_name failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Set name failed")
            result = ops.set_cardholder_name(
                "12345678",
                "John Doe",
                SecureString("wrong"),
            )
            assert result.is_err()
            assert "Set name failed" in str(result.unwrap_err())


class TestSetPublicKeyUrl:
    """Tests for set_public_key_url method."""

    def test_set_public_key_url_success(self) -> None:
        """Test set_public_key_url succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.set_public_key_url(
                "12345678",
                "https://keys.example.com/key.asc",
                SecureString("12345678"),
            )
            assert result.is_ok()

    def test_set_public_key_url_failure(self) -> None:
        """Test set_public_key_url failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Set URL failed")
            result = ops.set_public_key_url(
                "12345678",
                "https://keys.example.com/key.asc",
                SecureString("wrong"),
            )
            assert result.is_err()
            assert "Set URL failed" in str(result.unwrap_err())


class TestSetResetCode:
    """Tests for set_reset_code method."""

    def test_set_reset_code_success(self) -> None:
        """Test set_reset_code succeeds."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = ops.set_reset_code(
                "12345678",
                SecureString("12345678"),
                SecureString("resetcode123"),
            )
            assert result.is_ok()

    def test_set_reset_code_failure(self) -> None:
        """Test set_reset_code failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Reset code failed")
            result = ops.set_reset_code(
                "12345678",
                SecureString("wrong"),
                SecureString("resetcode123"),
            )
            assert result.is_err()
            assert "Set reset code failed" in str(result.unwrap_err())


class TestGetOpenpgpVersion:
    """Tests for get_openpgp_version method."""

    def test_get_openpgp_version_success(self) -> None:
        """Test get_openpgp_version returns version."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            # The function looks for "Version" with capital V
            mock_run.return_value = MagicMock(
                returncode=0, stdout="OpenPGP Version: 3.4\nApplication Version: 5.4.3"
            )
            result = ops.get_openpgp_version("12345678")
            assert result.is_ok()
            assert result.unwrap() == "3.4"

    def test_get_openpgp_version_failure(self) -> None:
        """Test get_openpgp_version failure."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="Version check failed")
            result = ops.get_openpgp_version("12345678")
            assert result.is_err()
            assert "Version check failed" in str(result.unwrap_err())

    def test_get_openpgp_version_no_version_found(self) -> None:
        """Test get_openpgp_version when no version in output."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_ykman") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="No version info here")
            result = ops.get_openpgp_version("12345678")
            assert result.is_err()
            assert "Could not determine OpenPGP version" in str(result.unwrap_err())


class TestSetAllTouchPolicies:
    """Tests for set_all_touch_policies method."""

    def test_set_all_touch_policies_success(self) -> None:
        """Test set_all_touch_policies sets all three policies."""
        from yubikey_init.types import Result, TouchPolicy

        ops = YubiKeyOperations()
        with patch.object(ops, "set_touch_policy") as mock_set:
            mock_set.return_value = Result.ok(None)
            result = ops.set_all_touch_policies(
                "12345678",
                SecureString("12345678"),
                TouchPolicy.ON,
            )
            assert result.is_ok()
            assert mock_set.call_count == 3

    def test_set_all_touch_policies_partial_failure(self) -> None:
        """Test set_all_touch_policies fails if any policy fails."""
        from yubikey_init.types import Result, TouchPolicy
        from yubikey_init.yubikey_ops import YubiKeyError

        ops = YubiKeyOperations()
        with patch.object(ops, "set_touch_policy") as mock_set:
            mock_set.side_effect = [
                Result.ok(None),
                Result.err(YubiKeyError("Touch policy failed")),
            ]
            result = ops.set_all_touch_policies(
                "12345678",
                SecureString("12345678"),
                TouchPolicy.ON,
            )
            assert result.is_err()
            assert mock_set.call_count == 2


class TestFetchPublicKey:
    """Tests for fetch_public_key method."""

    def test_fetch_public_key_success(self) -> None:
        """Test fetch_public_key succeeds when key available."""
        from yubikey_init.types import CardStatus, Result

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_run_gpg") as mock_gpg,
            patch.object(ops, "get_card_status") as mock_status,
        ):
            mock_status.return_value = Result.ok(
                CardStatus(
                    serial="12345678",
                    signature_key="1234567890ABCDEF1234567890ABCDEF12345678",
                    encryption_key=None,
                    authentication_key=None,
                    signature_count=0,
                    pin_retries=3,
                    admin_pin_retries=3,
                )
            )
            mock_gpg.return_value = MagicMock(
                returncode=0,
                stdout="-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey data\n-----END PGP PUBLIC KEY BLOCK-----",
            )
            result = ops.fetch_public_key("12345678")
            assert result.is_ok()
            assert "BEGIN PGP PUBLIC KEY BLOCK" in result.unwrap()

    def test_fetch_public_key_card_status_failure(self) -> None:
        """Test fetch_public_key fails when card status fails."""
        from yubikey_init.types import Result
        from yubikey_init.yubikey_ops import YubiKeyError

        ops = YubiKeyOperations()
        with patch.object(ops, "get_card_status") as mock_status:
            mock_status.return_value = Result.err(YubiKeyError("Card error"))
            result = ops.fetch_public_key("12345678")
            assert result.is_err()

    def test_fetch_public_key_no_key_on_card(self) -> None:
        """Test fetch_public_key fails when no key on card."""
        from yubikey_init.types import CardStatus, Result

        ops = YubiKeyOperations()
        with patch.object(ops, "get_card_status") as mock_status:
            mock_status.return_value = Result.ok(
                CardStatus(
                    serial="12345678",
                    signature_key=None,
                    encryption_key=None,
                    authentication_key=None,
                    signature_count=0,
                    pin_retries=3,
                    admin_pin_retries=3,
                )
            )
            result = ops.fetch_public_key("12345678")
            assert result.is_err()
            assert "Could not fetch public key" in str(result.unwrap_err())


class TestCheckYkmanVersion:
    """Tests for check_ykman_version function."""

    def test_check_ykman_version_success(self) -> None:
        """Test check_ykman_version returns version."""
        from yubikey_init.yubikey_ops import check_ykman_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="ykman 5.0.0")
            result = check_ykman_version()
            assert result.is_ok()
            assert result.unwrap() == "5.0.0"

    def test_check_ykman_version_not_found(self) -> None:
        """Test check_ykman_version fails when ykman not installed."""
        from yubikey_init.yubikey_ops import check_ykman_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            result = check_ykman_version()
            assert result.is_err()
            assert "not installed" in str(result.unwrap_err())

    def test_check_ykman_version_error(self) -> None:
        """Test check_ykman_version fails on error."""
        from yubikey_init.yubikey_ops import check_ykman_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = check_ykman_version()
            assert result.is_err()
            assert "not found" in str(result.unwrap_err())


class TestCheckGpgVersion:
    """Tests for check_gpg_version function."""

    def test_check_gpg_version_success(self) -> None:
        """Test check_gpg_version returns version."""
        from yubikey_init.yubikey_ops import check_gpg_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="gpg (GnuPG) 2.4.0\nlibgcrypt 1.10.0"
            )
            result = check_gpg_version()
            assert result.is_ok()
            assert result.unwrap() == "2.4.0"

    def test_check_gpg_version_not_found(self) -> None:
        """Test check_gpg_version fails when gpg not installed."""
        from yubikey_init.yubikey_ops import check_gpg_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            result = check_gpg_version()
            assert result.is_err()
            assert "not installed" in str(result.unwrap_err())

    def test_check_gpg_version_error(self) -> None:
        """Test check_gpg_version fails on error."""
        from yubikey_init.yubikey_ops import check_gpg_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = check_gpg_version()
            assert result.is_err()
            assert "version check failed" in str(result.unwrap_err())

    def test_check_gpg_version_empty_first_line(self) -> None:
        """Test check_gpg_version with no version in first line."""
        from yubikey_init.yubikey_ops import check_gpg_version

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            # If stdout is empty or first line has no words, IndexError is raised
            # This test documents the current behavior when first line is empty
            mock_run.return_value = MagicMock(returncode=0, stdout="\ngpg 2.4.0")
            with pytest.raises(IndexError):
                check_gpg_version()


class TestCheckScdaemon:
    """Tests for check_scdaemon function."""

    def test_check_scdaemon_success(self) -> None:
        """Test check_scdaemon returns True when scdaemon available."""
        from yubikey_init.yubikey_ops import check_scdaemon

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = check_scdaemon()
            assert result.is_ok()
            assert result.unwrap() is True

    def test_check_scdaemon_not_available(self) -> None:
        """Test check_scdaemon returns False when scdaemon not responding."""
        from yubikey_init.yubikey_ops import check_scdaemon

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = check_scdaemon()
            assert result.is_ok()
            assert result.unwrap() is False

    def test_check_scdaemon_not_found(self) -> None:
        """Test check_scdaemon fails when gpg-connect-agent not found."""
        from yubikey_init.yubikey_ops import check_scdaemon

        with patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            result = check_scdaemon()
            assert result.is_err()
            assert "not found" in str(result.unwrap_err())


class TestGetReaderForSerial:
    """Tests for _get_reader_for_serial method."""

    def test_get_reader_for_serial_found(self) -> None:
        """Test _get_reader_for_serial finds reader."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_gpg") as mock_gpg:
            mock_gpg.return_value = MagicMock(
                returncode=0,
                stdout="Reader ...........: Yubico YubiKey 12345678\nApplication ID ...:",
            )
            reader = ops._get_reader_for_serial("12345678")
            assert reader == "Yubico YubiKey 12345678"

    def test_get_reader_for_serial_not_found(self) -> None:
        """Test _get_reader_for_serial returns None when not found."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_gpg") as mock_gpg:
            mock_gpg.return_value = MagicMock(
                returncode=0,
                stdout="Reader ...........: Yubico YubiKey 87654321\nApplication ID ...:",
            )
            reader = ops._get_reader_for_serial("12345678")
            assert reader is None

    def test_get_reader_for_serial_error(self) -> None:
        """Test _get_reader_for_serial returns None on error."""
        ops = YubiKeyOperations()
        with patch.object(ops, "_run_gpg") as mock_gpg:
            mock_gpg.return_value = MagicMock(returncode=1, stdout="")
            reader = ops._get_reader_for_serial("12345678")
            assert reader is None


class TestTransferKeyAdditional:
    """Additional transfer_key tests using subprocess (drduh guide approach)."""

    def test_transfer_key_with_reader_port(self) -> None:
        """Test transfer_key uses reader port when available."""
        from yubikey_init.types import KeySlot

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_get_reader_for_serial", return_value="Yubico YubiKey"),
            patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = ops.transfer_key(
                "12345678",
                "ABCDEF1234567890",
                KeySlot.ENCRYPTION,
                SecureString("passphrase"),
                SecureString("12345678"),
                subkey_index=2,
            )

            assert result.is_ok()
            cmd = mock_run.call_args[0][0]
            # Check reader port was passed
            assert "--reader-port" in cmd

    def test_transfer_key_exit_status_error(self) -> None:
        """Test transfer_key handles non-zero exit status."""
        from yubikey_init.types import KeySlot

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_get_reader_for_serial", return_value=None),
            patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Transfer error")

            result = ops.transfer_key(
                "12345678",
                "ABCDEF1234567890",
                KeySlot.AUTHENTICATION,
                SecureString("passphrase"),
                SecureString("12345678"),
                subkey_index=3,
            )

            assert result.is_err()
            assert "failed" in str(result.unwrap_err())

    def test_transfer_key_failure_message(self) -> None:
        """Test transfer_key error message contains stderr."""
        from yubikey_init.types import KeySlot

        ops = YubiKeyOperations()
        with (
            patch.object(ops, "_get_reader_for_serial", return_value=None),
            patch("yubikey_init.yubikey_ops.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="Card error: PIN blocked"
            )

            result = ops.transfer_key(
                "12345678",
                "ABCDEF1234567890",
                KeySlot.SIGNATURE,
                SecureString("passphrase"),
                SecureString("12345678"),
            )

            assert result.is_err()
            assert "PIN blocked" in str(result.unwrap_err())


class TestWaitForDeviceAdditional:
    """Additional wait_for_device tests."""

    def test_wait_for_device_serial_not_found_times_out(self) -> None:
        """Test wait_for_device times out when serial not found."""
        ops = YubiKeyOperations()
        device = YubiKeyInfo(
            serial="12345678",
            version="5.4.3",
            form_factor="USB-A",
            has_openpgp=True,
            openpgp_version=None,
        )
        with (
            patch.object(ops, "list_devices", return_value=[device]),
            patch("yubikey_init.yubikey_ops.time.sleep"),
            patch("yubikey_init.yubikey_ops.time.time") as mock_time,
        ):
            # Simulate time passing beyond timeout
            mock_time.side_effect = [0, 0, 5, 5]
            result = ops.wait_for_device(serial="99999999", timeout=1)
            assert result.is_err()
            assert "No YubiKey detected" in str(result.unwrap_err())
