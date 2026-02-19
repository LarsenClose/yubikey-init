"""Tests for __main__.py entry point."""

from __future__ import annotations

from unittest.mock import patch


def test_main_calls_run() -> None:
    """Test that main() calls run() with sys.argv."""
    with patch("yubikey_init.__main__.run") as mock_run:
        mock_run.return_value = 0
        from yubikey_init.__main__ import main

        result = main()
        assert result == 0
        mock_run.assert_called_once()


def test_main_passes_argv_to_run() -> None:
    """Test that main() passes sys.argv[1:] to run()."""
    with (
        patch("yubikey_init.__main__.run") as mock_run,
        patch("yubikey_init.__main__.sys.argv", ["yubikey-init", "--help"]),
    ):
        mock_run.return_value = 0
        from yubikey_init.__main__ import main

        main()
        mock_run.assert_called_once_with(["--help"])


def test_main_returns_run_exit_code() -> None:
    """Test that main() returns whatever run() returns."""
    with patch("yubikey_init.__main__.run") as mock_run:
        mock_run.return_value = 42
        from yubikey_init.__main__ import main

        result = main()
        assert result == 42
