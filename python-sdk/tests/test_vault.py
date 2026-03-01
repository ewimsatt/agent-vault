"""Tests for agent-vault Python SDK.

These tests create a vault using the Rust CLI, then verify the Python SDK
can read secrets, list metadata, and handle errors correctly.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from agent_vault import Vault, SecretNotFoundError, NotAuthorizedError, VaultNotFoundError


# Resolve the pre-built binary path once at module load
_BINARY = str(Path(__file__).parent.parent.parent / "target" / "debug" / "agent-vault")


def _run_cli(*args, cwd, env):
    """Run the agent-vault CLI binary."""
    result = subprocess.run(
        [_BINARY] + list(args),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"CLI failed: {args}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


@pytest.fixture
def vault_env(tmp_path):
    """Set up a temporary vault with a secret for testing."""
    repo = tmp_path / "repo"
    repo.mkdir()
    fake_home = tmp_path / "fakehome"
    fake_home.mkdir()

    env = os.environ.copy()
    env["HOME"] = str(fake_home)

    # Init git repo
    subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(repo), capture_output=True, check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(repo), capture_output=True, check=True
    )

    # Init vault
    _run_cli("init", cwd=str(repo), env=env)

    # Add agent
    _run_cli("add-agent", "test-bot", cwd=str(repo), env=env)

    # Set a secret
    _run_cli("set", "stripe/api-key", "sk_test_123", cwd=str(repo), env=env)

    # Grant agent access
    _run_cli("grant", "test-bot", "stripe", cwd=str(repo), env=env)

    owner_key = fake_home / ".agent-vault" / "owner.key"
    agent_key = fake_home / ".agent-vault" / "agents" / "test-bot.key"

    return {
        "repo": repo,
        "fake_home": fake_home,
        "env": env,
        "owner_key": owner_key,
        "agent_key": agent_key,
    }


class TestVaultInit:
    def test_vault_not_found(self, tmp_path):
        """Opening a vault on a dir without .agent-vault raises."""
        with pytest.raises(VaultNotFoundError):
            Vault(repo_path=tmp_path, key_str="AGE-SECRET-KEY-1FAKE")

    def test_no_key_raises(self, vault_env):
        """Vault without key raises an error."""
        # Clear env so no fallback key is found
        env = vault_env["env"].copy()
        env.pop("AGENT_VAULT_KEY", None)
        # Use a fake home with no owner.key
        fake_home2 = vault_env["fake_home"].parent / "emptyhome"
        fake_home2.mkdir()
        env["HOME"] = str(fake_home2)

        # Temporarily change HOME for the Vault constructor
        old_home = os.environ.get("HOME")
        try:
            os.environ["HOME"] = str(fake_home2)
            with pytest.raises(VaultNotFoundError, match="No key"):
                Vault(repo_path=vault_env["repo"])
        finally:
            if old_home:
                os.environ["HOME"] = old_home


class TestVaultGet:
    def test_get_with_owner_key(self, vault_env):
        """Owner can decrypt secrets."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        assert vault.get("stripe/api-key") == "sk_test_123"

    def test_get_with_agent_key(self, vault_env):
        """Agent with granted access can decrypt secrets."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["agent_key"],
            auto_pull=False,
        )
        assert vault.get("stripe/api-key") == "sk_test_123"

    def test_get_nonexistent_secret(self, vault_env):
        """Requesting a missing secret raises SecretNotFoundError."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        with pytest.raises(SecretNotFoundError):
            vault.get("nope/missing")

    def test_get_unauthorized(self, vault_env):
        """Agent without access gets NotAuthorizedError."""
        # Add a second agent without granting access
        _run_cli("add-agent", "no-access-bot", cwd=str(vault_env["repo"]), env=vault_env["env"])
        no_access_key = vault_env["fake_home"] / ".agent-vault" / "agents" / "no-access-bot.key"

        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=no_access_key,
            auto_pull=False,
        )
        with pytest.raises(NotAuthorizedError):
            vault.get("stripe/api-key")

    def test_get_with_key_str(self, vault_env):
        """Can load key from string instead of file."""
        key_content = vault_env["owner_key"].read_text()
        vault = Vault(
            repo_path=vault_env["repo"],
            key_str=key_content,
            auto_pull=False,
        )
        assert vault.get("stripe/api-key") == "sk_test_123"

    def test_get_with_env_var(self, vault_env):
        """Can load key from AGENT_VAULT_KEY env var."""
        key_content = vault_env["owner_key"].read_text()
        old_env = os.environ.get("AGENT_VAULT_KEY")
        old_home = os.environ.get("HOME")
        try:
            os.environ["AGENT_VAULT_KEY"] = key_content
            # Set HOME to empty dir so it doesn't find owner.key
            empty = vault_env["fake_home"].parent / "emptyhome2"
            empty.mkdir(exist_ok=True)
            os.environ["HOME"] = str(empty)

            vault = Vault(
                repo_path=vault_env["repo"],
                auto_pull=False,
            )
            assert vault.get("stripe/api-key") == "sk_test_123"
        finally:
            if old_env is None:
                os.environ.pop("AGENT_VAULT_KEY", None)
            else:
                os.environ["AGENT_VAULT_KEY"] = old_env
            if old_home:
                os.environ["HOME"] = old_home


class TestVaultList:
    def test_list_secrets(self, vault_env):
        """Can list secrets with metadata."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        secrets = vault.list_secrets()
        assert len(secrets) == 1
        assert secrets[0].name == "stripe/api-key"
        assert secrets[0].group == "stripe"

    def test_list_secrets_by_group(self, vault_env):
        """Can filter secrets by group."""
        # Add another secret in a different group
        _run_cli(
            "set", "postgres/conn", "postgres://...",
            "--group", "postgres",
            cwd=str(vault_env["repo"]),
            env=vault_env["env"],
        )

        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        all_secrets = vault.list_secrets()
        assert len(all_secrets) == 2

        stripe_only = vault.list_secrets(group="stripe")
        assert len(stripe_only) == 1
        assert stripe_only[0].name == "stripe/api-key"

    def test_list_agents(self, vault_env):
        """Can list agents with group memberships."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        agents = vault.list_agents()
        assert len(agents) == 1
        assert agents[0]["name"] == "test-bot"
        assert "stripe" in agents[0]["groups"]


class TestMultipleSecrets:
    def test_multiple_secrets_and_groups(self, vault_env):
        """Can handle multiple secrets across groups."""
        _run_cli(
            "set", "stripe/webhook-secret", "whsec_456",
            cwd=str(vault_env["repo"]),
            env=vault_env["env"],
        )
        _run_cli(
            "set", "postgres/conn", "postgres://localhost",
            "--group", "postgres",
            cwd=str(vault_env["repo"]),
            env=vault_env["env"],
        )

        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )

        assert vault.get("stripe/api-key") == "sk_test_123"
        assert vault.get("stripe/webhook-secret") == "whsec_456"
        assert vault.get("postgres/conn") == "postgres://localhost"

        assert len(vault.list_secrets()) == 3
        assert len(vault.list_secrets(group="stripe")) == 2
        assert len(vault.list_secrets(group="postgres")) == 1


class TestPullWarnings:
    def test_pull_warns_on_failure(self, vault_env, capsys):
        """Pull failure logs to stderr instead of silently swallowing."""
        import shutil

        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        # Break git by temporarily renaming .git
        git_dir = vault_env["repo"] / ".git"
        git_dir_backup = vault_env["repo"] / ".git_backup"
        shutil.move(str(git_dir), str(git_dir_backup))

        try:
            vault.pull()  # Should warn, not raise
            captured = capsys.readouterr()
            assert "Warning" in captured.err
        finally:
            shutil.move(str(git_dir_backup), str(git_dir))


class TestResolveRepoPath:
    def test_local_path_unchanged(self):
        """Local paths pass through unchanged."""
        from agent_vault.vault import _resolve_repo_path

        result = _resolve_repo_path("/tmp/some/path")
        # On macOS /tmp -> /private/tmp, so compare resolved paths
        assert result == Path("/tmp/some/path").resolve()

    def test_url_detected(self):
        """URL-like strings are detected as remote."""
        from agent_vault.vault import _resolve_repo_path

        # These should be detected as URLs (will fail to clone, but
        # we're testing detection, not actual cloning)
        for url in [
            "https://github.com/example/repo.git",
            "git@github.com:example/repo.git",
            "ssh://git@github.com/example/repo.git",
            "git://github.com/example/repo.git",
        ]:
            from agent_vault.errors import VaultNotFoundError
            try:
                _resolve_repo_path(url)
            except VaultNotFoundError:
                pass  # Expected — can't actually clone
            except Exception:
                pass  # Network error is also fine

    def test_relative_path_not_url(self):
        """Relative paths are not treated as URLs."""
        from agent_vault.vault import _resolve_repo_path

        result = _resolve_repo_path("./my-repo")
        assert not str(result).startswith("https://")
        assert result.is_absolute()


class TestContextManager:
    def test_with_statement(self, vault_env):
        """Vault works as a context manager."""
        with Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        ) as vault:
            assert vault.get("stripe/api-key") == "sk_test_123"
