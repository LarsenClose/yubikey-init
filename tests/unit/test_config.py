"""Tests for config module."""

from pathlib import Path

from yubikey_init.config import (
    HARDENED_GPG_AGENT_CONF,
    HARDENED_GPG_CONF,
    SCDAEMON_CONF,
    ensure_gnupg_dir,
    generate_ssh_agent_setup_script,
    get_ssh_auth_socket,
    setup_all_configs,
    write_gpg_agent_conf,
    write_gpg_conf,
)


class TestHardenedConfigs:
    """Test hardened configuration content."""

    def test_gpg_conf_disables_weak_algorithms(self):
        """Verify gpg.conf disables weak algorithms."""
        assert "disable-cipher-algo 3DES" in HARDENED_GPG_CONF
        assert "disable-cipher-algo IDEA" in HARDENED_GPG_CONF
        assert "weak-digest SHA1" in HARDENED_GPG_CONF

    def test_gpg_conf_sets_strong_defaults(self):
        """Verify gpg.conf sets strong cipher preferences."""
        assert "personal-cipher-preferences AES256" in HARDENED_GPG_CONF
        assert "personal-digest-preferences SHA512" in HARDENED_GPG_CONF
        assert "s2k-cipher-algo AES256" in HARDENED_GPG_CONF
        assert "cert-digest-algo SHA512" in HARDENED_GPG_CONF

    def test_gpg_conf_security_settings(self):
        """Verify gpg.conf has security settings."""
        assert "no-emit-version" in HARDENED_GPG_CONF
        assert "no-comments" in HARDENED_GPG_CONF
        assert "throw-keyids" in HARDENED_GPG_CONF
        assert "require-cross-certification" in HARDENED_GPG_CONF

    def test_gpg_agent_conf_has_ssh_support(self):
        """Verify gpg-agent.conf enables SSH support."""
        assert "enable-ssh-support" in HARDENED_GPG_AGENT_CONF

    def test_gpg_agent_conf_has_cache_ttl(self):
        """Verify gpg-agent.conf sets cache TTL."""
        assert "default-cache-ttl" in HARDENED_GPG_AGENT_CONF
        assert "max-cache-ttl" in HARDENED_GPG_AGENT_CONF

    def test_scdaemon_conf_disables_ccid(self):
        """Verify scdaemon.conf disables built-in CCID."""
        assert "disable-ccid" in SCDAEMON_CONF


class TestConfigWriting:
    """Test configuration file writing."""

    def test_ensure_gnupg_dir_creates_directory(self, tmp_path):
        """Test that ensure_gnupg_dir creates the directory."""
        gnupg_dir = tmp_path / ".gnupg"
        result = ensure_gnupg_dir(gnupg_dir)

        assert result.is_ok()
        assert gnupg_dir.exists()
        assert gnupg_dir.is_dir()

    def test_write_gpg_conf_creates_file(self, tmp_path):
        """Test that write_gpg_conf creates the config file."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        result = write_gpg_conf(gnupg_dir)

        assert result.is_ok()
        conf_path = gnupg_dir / "gpg.conf"
        assert conf_path.exists()
        content = conf_path.read_text()
        assert "personal-cipher-preferences" in content

    def test_write_gpg_conf_backs_up_existing(self, tmp_path):
        """Test that write_gpg_conf backs up existing config."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        # Create existing config
        conf_path = gnupg_dir / "gpg.conf"
        conf_path.write_text("# Old config")

        result = write_gpg_conf(gnupg_dir, backup_existing=True)

        assert result.is_ok()
        backup_path = gnupg_dir / "gpg.conf.bak"
        assert backup_path.exists()
        assert backup_path.read_text() == "# Old config"

    def test_write_gpg_conf_custom_content(self, tmp_path):
        """Test write_gpg_conf with custom content."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        custom_content = "# Custom config\ndefault-key ABCD1234"
        result = write_gpg_conf(gnupg_dir, content=custom_content)

        assert result.is_ok()
        conf_path = gnupg_dir / "gpg.conf"
        assert conf_path.read_text() == custom_content

    def test_write_gpg_agent_conf_disables_ssh(self, tmp_path):
        """Test write_gpg_agent_conf can disable SSH support."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        result = write_gpg_agent_conf(gnupg_dir, enable_ssh=False)

        assert result.is_ok()
        conf_path = gnupg_dir / "gpg-agent.conf"
        content = conf_path.read_text()
        assert "# enable-ssh-support" in content

    def test_setup_all_configs(self, tmp_path):
        """Test setup_all_configs creates all files."""
        gnupg_dir = tmp_path / ".gnupg"

        result = setup_all_configs(gnupg_dir)

        assert result.is_ok()
        paths = result.unwrap()
        assert "gpg.conf" in paths
        assert "gpg-agent.conf" in paths
        assert "scdaemon.conf" in paths
        assert (gnupg_dir / "gpg.conf").exists()
        assert (gnupg_dir / "gpg-agent.conf").exists()
        assert (gnupg_dir / "scdaemon.conf").exists()


class TestSSHSetup:
    """Test SSH setup functions."""

    def test_get_ssh_auth_socket_returns_path(self):
        """Test get_ssh_auth_socket returns a Path."""
        socket_path = get_ssh_auth_socket()
        assert isinstance(socket_path, Path)
        assert "gpg-agent.ssh" in str(socket_path) or "S.gpg-agent.ssh" in str(socket_path)

    def test_generate_ssh_agent_setup_script_bash(self):
        """Test SSH agent setup script for bash."""
        script = generate_ssh_agent_setup_script("bash")

        assert "export GPG_TTY" in script
        assert "export SSH_AUTH_SOCK" in script
        assert "gpgconf --launch gpg-agent" in script

    def test_generate_ssh_agent_setup_script_fish(self):
        """Test SSH agent setup script for fish."""
        script = generate_ssh_agent_setup_script("fish")

        assert "set -gx GPG_TTY" in script
        assert "set -gx SSH_AUTH_SOCK" in script

    def test_generate_ssh_agent_setup_script_zsh(self):
        """Test SSH agent setup script for zsh."""
        script = generate_ssh_agent_setup_script("zsh")

        assert "export GPG_TTY" in script
        assert "export SSH_AUTH_SOCK" in script
        assert "gpgconf --launch gpg-agent" in script

    def test_generate_ssh_agent_setup_script_sh(self):
        """Test SSH agent setup script for sh."""
        script = generate_ssh_agent_setup_script("sh")

        assert "export GPG_TTY" in script
        assert "export SSH_AUTH_SOCK" in script

    def test_generate_ssh_agent_setup_script_unknown_shell(self):
        """Test SSH agent setup script for unknown shell returns minimal output."""
        script = generate_ssh_agent_setup_script("powershell")

        assert "SSH_AUTH_SOCK=" in script
        assert script.startswith("#")


class TestGetGnupgHome:
    """Test get_gnupghome function."""

    def test_get_gnupghome_default(self):
        """Test get_gnupghome returns default path when env not set."""
        import os

        from yubikey_init.config import get_gnupghome

        # Ensure GNUPGHOME is not set
        original = os.environ.pop("GNUPGHOME", None)
        try:
            result = get_gnupghome()
            assert result == Path.home() / ".gnupg"
        finally:
            if original:
                os.environ["GNUPGHOME"] = original

    def test_get_gnupghome_from_env(self):
        """Test get_gnupghome returns path from GNUPGHOME env var."""
        import os

        from yubikey_init.config import get_gnupghome

        original = os.environ.get("GNUPGHOME")
        try:
            os.environ["GNUPGHOME"] = "/custom/gnupg/path"
            result = get_gnupghome()
            assert result == Path("/custom/gnupg/path")
        finally:
            if original:
                os.environ["GNUPGHOME"] = original
            else:
                os.environ.pop("GNUPGHOME", None)


class TestEnsureGnupgDirErrors:
    """Test ensure_gnupg_dir error handling."""

    def test_ensure_gnupg_dir_oserror(self, tmp_path):
        """Test ensure_gnupg_dir returns error on OSError."""
        from unittest.mock import patch

        with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
            result = ensure_gnupg_dir(tmp_path / "test_gnupg")
            assert result.is_err()
            assert "Could not create GnuPG directory" in str(result.unwrap_err())


class TestWriteGpgConfErrors:
    """Test write_gpg_conf error handling."""

    def test_write_gpg_conf_oserror(self, tmp_path):
        """Test write_gpg_conf returns error on OSError."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("pathlib.Path.write_text", side_effect=OSError("Disk full")):
            result = write_gpg_conf(gnupg_dir)
            assert result.is_err()
            assert "Could not write gpg.conf" in str(result.unwrap_err())

    def test_write_gpg_conf_no_backup(self, tmp_path):
        """Test write_gpg_conf without backup."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        # Create existing config
        conf_path = gnupg_dir / "gpg.conf"
        conf_path.write_text("# Old config")

        result = write_gpg_conf(gnupg_dir, backup_existing=False)

        assert result.is_ok()
        # Backup should not exist
        backup_path = gnupg_dir / "gpg.conf.bak"
        assert not backup_path.exists()
        # New content should be written
        assert "personal-cipher-preferences" in conf_path.read_text()


class TestWriteGpgAgentConfErrors:
    """Test write_gpg_agent_conf error handling."""

    def test_write_gpg_agent_conf_oserror(self, tmp_path):
        """Test write_gpg_agent_conf returns error on OSError."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("pathlib.Path.write_text", side_effect=OSError("Disk full")):
            result = write_gpg_agent_conf(gnupg_dir)
            assert result.is_err()
            assert "Could not write gpg-agent.conf" in str(result.unwrap_err())

    def test_write_gpg_agent_conf_backs_up_existing(self, tmp_path):
        """Test write_gpg_agent_conf backs up existing config."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        # Create existing config
        conf_path = gnupg_dir / "gpg-agent.conf"
        conf_path.write_text("# Old agent config")

        result = write_gpg_agent_conf(gnupg_dir, backup_existing=True)

        assert result.is_ok()
        backup_path = gnupg_dir / "gpg-agent.conf.bak"
        assert backup_path.exists()
        assert backup_path.read_text() == "# Old agent config"

    def test_write_gpg_agent_conf_custom_content(self, tmp_path):
        """Test write_gpg_agent_conf with custom content."""
        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        custom_content = "# Custom agent config\ndefault-cache-ttl 300"
        result = write_gpg_agent_conf(gnupg_dir, content=custom_content)

        assert result.is_ok()
        conf_path = gnupg_dir / "gpg-agent.conf"
        assert conf_path.read_text() == custom_content


class TestWriteScdaemonConf:
    """Test write_scdaemon_conf function."""

    def test_write_scdaemon_conf_creates_file(self, tmp_path):
        """Test write_scdaemon_conf creates the config file."""
        from yubikey_init.config import write_scdaemon_conf

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        result = write_scdaemon_conf(gnupg_dir)

        assert result.is_ok()
        conf_path = gnupg_dir / "scdaemon.conf"
        assert conf_path.exists()
        content = conf_path.read_text()
        assert "disable-ccid" in content

    def test_write_scdaemon_conf_backs_up_existing(self, tmp_path):
        """Test write_scdaemon_conf backs up existing config."""
        from yubikey_init.config import write_scdaemon_conf

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        # Create existing config
        conf_path = gnupg_dir / "scdaemon.conf"
        conf_path.write_text("# Old scdaemon config")

        result = write_scdaemon_conf(gnupg_dir, backup_existing=True)

        assert result.is_ok()
        backup_path = gnupg_dir / "scdaemon.conf.bak"
        assert backup_path.exists()
        assert backup_path.read_text() == "# Old scdaemon config"

    def test_write_scdaemon_conf_custom_content(self, tmp_path):
        """Test write_scdaemon_conf with custom content."""
        from yubikey_init.config import write_scdaemon_conf

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        custom_content = "# Custom scdaemon config\ncard-timeout 10"
        result = write_scdaemon_conf(gnupg_dir, content=custom_content)

        assert result.is_ok()
        conf_path = gnupg_dir / "scdaemon.conf"
        assert conf_path.read_text() == custom_content

    def test_write_scdaemon_conf_oserror(self, tmp_path):
        """Test write_scdaemon_conf returns error on OSError."""
        from unittest.mock import patch

        from yubikey_init.config import write_scdaemon_conf

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("pathlib.Path.write_text", side_effect=OSError("Disk full")):
            result = write_scdaemon_conf(gnupg_dir)
            assert result.is_err()
            assert "Could not write scdaemon.conf" in str(result.unwrap_err())


class TestSetupAllConfigsErrors:
    """Test setup_all_configs error handling."""

    def test_setup_all_configs_dir_creation_fails(self, tmp_path):
        """Test setup_all_configs fails when directory creation fails."""
        from unittest.mock import patch

        with patch("yubikey_init.config.ensure_gnupg_dir") as mock_ensure:
            from yubikey_init.config import ConfigError
            from yubikey_init.types import Result

            mock_ensure.return_value = Result.err(ConfigError("Cannot create dir"))

            result = setup_all_configs(tmp_path / "test")
            assert result.is_err()

    def test_setup_all_configs_gpg_conf_fails(self, tmp_path):
        """Test setup_all_configs fails when gpg.conf write fails."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("yubikey_init.config.write_gpg_conf") as mock_write:
            from yubikey_init.config import ConfigError
            from yubikey_init.types import Result

            mock_write.return_value = Result.err(ConfigError("Write failed"))

            result = setup_all_configs(gnupg_dir)
            assert result.is_err()

    def test_setup_all_configs_gpg_agent_conf_fails(self, tmp_path):
        """Test setup_all_configs fails when gpg-agent.conf write fails."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("yubikey_init.config.write_gpg_agent_conf") as mock_write:
            from yubikey_init.config import ConfigError
            from yubikey_init.types import Result

            mock_write.return_value = Result.err(ConfigError("Write failed"))

            result = setup_all_configs(gnupg_dir)
            assert result.is_err()

    def test_setup_all_configs_scdaemon_conf_fails(self, tmp_path):
        """Test setup_all_configs fails when scdaemon.conf write fails."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with patch("yubikey_init.config.write_scdaemon_conf") as mock_write:
            from yubikey_init.config import ConfigError
            from yubikey_init.types import Result

            mock_write.return_value = Result.err(ConfigError("Write failed"))

            result = setup_all_configs(gnupg_dir)
            assert result.is_err()


class TestGetSshAuthSocketPlatforms:
    """Test get_ssh_auth_socket on different platforms."""

    def test_get_ssh_auth_socket_macos(self):
        """Test get_ssh_auth_socket on macOS."""
        from unittest.mock import patch

        with patch("platform.system", return_value="Darwin"):
            socket_path = get_ssh_auth_socket()
            assert socket_path == Path.home() / ".gnupg" / "S.gpg-agent.ssh"

    def test_get_ssh_auth_socket_linux_with_xdg(self):
        """Test get_ssh_auth_socket on Linux with XDG_RUNTIME_DIR."""
        import os
        from unittest.mock import patch

        with patch("platform.system", return_value="Linux"):
            original = os.environ.get("XDG_RUNTIME_DIR")
            try:
                os.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
                socket_path = get_ssh_auth_socket()
                assert socket_path == Path("/run/user/1000/gnupg/S.gpg-agent.ssh")
            finally:
                if original:
                    os.environ["XDG_RUNTIME_DIR"] = original
                else:
                    os.environ.pop("XDG_RUNTIME_DIR", None)

    def test_get_ssh_auth_socket_linux_without_xdg(self):
        """Test get_ssh_auth_socket on Linux without XDG_RUNTIME_DIR."""
        import os
        from unittest.mock import patch

        with patch("platform.system", return_value="Linux"):
            original = os.environ.pop("XDG_RUNTIME_DIR", None)
            try:
                socket_path = get_ssh_auth_socket()
                assert socket_path == Path.home() / ".gnupg" / "S.gpg-agent.ssh"
            finally:
                if original:
                    os.environ["XDG_RUNTIME_DIR"] = original

    def test_get_ssh_auth_socket_unknown_platform(self):
        """Test get_ssh_auth_socket on unknown platform falls back."""
        from unittest.mock import patch

        with patch("platform.system", return_value="FreeBSD"):
            socket_path = get_ssh_auth_socket()
            assert socket_path == Path.home() / ".gnupg" / "S.gpg-agent.ssh"


class TestRestartGpgAgent:
    """Test restart_gpg_agent function."""

    def test_restart_gpg_agent_success(self):
        """Test restart_gpg_agent succeeds."""
        from unittest.mock import MagicMock, patch

        from yubikey_init.config import restart_gpg_agent

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = restart_gpg_agent()
            assert result.is_ok()
            assert mock_run.call_count == 2

    def test_restart_gpg_agent_launch_fails(self):
        """Test restart_gpg_agent fails when launch fails."""
        from subprocess import CalledProcessError
        from unittest.mock import MagicMock, patch

        from yubikey_init.config import restart_gpg_agent

        with patch("subprocess.run") as mock_run:
            # First call (kill) succeeds, second call (launch) fails
            mock_run.side_effect = [
                MagicMock(returncode=0),
                CalledProcessError(1, "gpgconf"),
            ]
            result = restart_gpg_agent()
            assert result.is_err()
            assert "Could not restart gpg-agent" in str(result.unwrap_err())

    def test_restart_gpg_agent_gpgconf_not_found(self):
        """Test restart_gpg_agent fails when gpgconf not found."""
        from unittest.mock import patch

        from yubikey_init.config import restart_gpg_agent

        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = restart_gpg_agent()
            assert result.is_err()
            assert "gpgconf not found" in str(result.unwrap_err())


class TestWindowsPlatform:
    """Test Windows platform-specific behavior."""

    def test_ensure_gnupg_dir_windows_no_chmod(self, tmp_path):
        """Test ensure_gnupg_dir doesn't chmod on Windows."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"

        with (
            patch("platform.system", return_value="Windows"),
            patch.object(Path, "chmod") as mock_chmod,
        ):
            result = ensure_gnupg_dir(gnupg_dir)
            assert result.is_ok()
            mock_chmod.assert_not_called()

    def test_write_gpg_conf_windows_no_chmod(self, tmp_path):
        """Test write_gpg_conf doesn't chmod on Windows."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with (
            patch("platform.system", return_value="Windows"),
            patch.object(Path, "chmod") as mock_chmod,
        ):
            result = write_gpg_conf(gnupg_dir)
            assert result.is_ok()
            mock_chmod.assert_not_called()

    def test_write_gpg_agent_conf_windows_no_chmod(self, tmp_path):
        """Test write_gpg_agent_conf doesn't chmod on Windows."""
        from unittest.mock import patch

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with (
            patch("platform.system", return_value="Windows"),
            patch.object(Path, "chmod") as mock_chmod,
        ):
            result = write_gpg_agent_conf(gnupg_dir)
            assert result.is_ok()
            mock_chmod.assert_not_called()

    def test_write_scdaemon_conf_windows_no_chmod(self, tmp_path):
        """Test write_scdaemon_conf doesn't chmod on Windows."""
        from unittest.mock import patch

        from yubikey_init.config import write_scdaemon_conf

        gnupg_dir = tmp_path / ".gnupg"
        gnupg_dir.mkdir()

        with (
            patch("platform.system", return_value="Windows"),
            patch.object(Path, "chmod") as mock_chmod,
        ):
            result = write_scdaemon_conf(gnupg_dir)
            assert result.is_ok()
            mock_chmod.assert_not_called()
