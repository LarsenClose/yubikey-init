from __future__ import annotations

import pytest

from yubikey_init import SecureString
from yubikey_init.yubikey_ops import YubiKeyOperations, yubikey_available


@pytest.mark.hardware
class TestYubiKeyDetection:
    def test_list_devices_returns_connected_yubikeys(self) -> None:
        ops = YubiKeyOperations()
        devices = ops.list_devices()
        assert len(devices) > 0
        assert devices[0].serial is not None

    def test_wait_for_device_finds_yubikey(self) -> None:
        ops = YubiKeyOperations()
        result = ops.wait_for_device(timeout=5)
        assert result.is_ok()
        device = result.unwrap()
        assert device.serial is not None


@pytest.mark.hardware
class TestYubiKeyOpenPGP:
    def test_get_card_status(self) -> None:
        ops = YubiKeyOperations()
        devices = ops.list_devices()
        assert len(devices) > 0

        result = ops.get_card_status(devices[0].serial)
        assert result.is_ok()
        status = result.unwrap()
        assert status.serial == devices[0].serial

    @pytest.mark.skip(reason="Destructive test - run manually")
    def test_reset_openpgp_applet(self) -> None:
        ops = YubiKeyOperations()
        devices = ops.list_devices()
        assert len(devices) > 0

        result = ops.reset_openpgp(devices[0].serial)
        assert result.is_ok()

    @pytest.mark.skip(reason="Destructive test - run manually")
    def test_set_pins(self) -> None:
        ops = YubiKeyOperations()
        devices = ops.list_devices()
        assert len(devices) > 0

        user_pin = SecureString("654321")
        admin_pin = SecureString("87654321")

        result = ops.set_pins(devices[0].serial, user_pin, admin_pin)
        assert result.is_ok()


class TestYubiKeyAvailability:
    def test_yubikey_available_function(self) -> None:
        result = yubikey_available()
        assert isinstance(result, bool)
