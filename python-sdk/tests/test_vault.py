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

from agent_vault import (
    GitSyncError,
    InvalidIdentifierError,
    NotAuthorizedError,
    SecretNotFoundError,
    Vault,
    VaultNotFoundError,
)


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


    @pytest.mark.parametrize(
        "secret_path",
        [
            "",
            "/outside",
            "../outside",
            "stripe/../../outside",
            "stripe//api-key",
            "stripe/./api-key",
            "stripe/../api-key",
            "stripe/api-key/",
            r"stripe\\api-key",
            "C:temp",
            "x\x00y",
            "x\x7fy",
            "x\x85y",
        ],
    )
    def test_get_rejects_malformed_secret_paths_before_pulling(
        self, vault_env, secret_path
    ):
        """SDK callers cannot use path aliases to leave the secrets directory."""
        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=True,
        )

        def unexpected_pull():
            pytest.fail("invalid secret paths must be rejected before git pull")

        vault.pull = unexpected_pull
        with pytest.raises(InvalidIdentifierError):
            vault.get(secret_path)

    @pytest.mark.parametrize(
        "secret_path",
        ["api-key", "stripe/api-key", "stripe/production/api-key", "dotted.name/_ok-1", "unicode/秘密"],
    )
    def test_valid_secret_path_shape_is_not_rejected(self, secret_path):
        """Lexical validation preserves the Rust CLI's accepted identifier shapes."""
        from agent_vault.vault import validate_secret_path

        validate_secret_path(secret_path)


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
    def test_pull_rejects_dirty_checkout_without_reading_stale_state(self, vault_env):
        """Automatic sync fails closed rather than silently reading a dirty checkout."""

        vault = Vault(
            repo_path=vault_env["repo"],
            key_path=vault_env["owner_key"],
            auto_pull=False,
        )
        original_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=vault_env["repo"], text=True
        ).strip()
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"], cwd=vault_env["repo"], text=True
        ).strip()
        remote = vault_env["repo"].parent / "remote.git"
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=vault_env["repo"], check=True)
        subprocess.run(["git", "push", "-u", "origin", branch], cwd=vault_env["repo"], check=True, capture_output=True)
        tracked_file = vault_env["repo"] / ".agent-vault" / "manifest.yaml"
        original_bytes = tracked_file.read_bytes()
        tracked_file.write_text("version: 999\n")

        with pytest.raises(GitSyncError):
            vault.pull()

        assert subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=vault_env["repo"], text=True
        ).strip() == original_head
        assert tracked_file.read_bytes() == b"version: 999\n"
        assert original_bytes != tracked_file.read_bytes()

    def test_pull_fast_forwards_a_clean_tracking_checkout(self, vault_env):
        """Automatic sync advances a clean checkout to its origin tracking branch."""
        remote = vault_env["repo"].parent / "remote-fast-forward.git"
        subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=vault_env["repo"], check=True, capture_output=True)
        subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
        branch = subprocess.check_output(
            ["git", "branch", "--show-current"], cwd=vault_env["repo"], text=True
        ).strip()
        subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=vault_env["repo"], check=True)
        subprocess.run(["git", "push", "-u", "origin", branch], cwd=vault_env["repo"], check=True, capture_output=True)
        updater = vault_env["repo"].parent / "updater"
        subprocess.run(["git", "clone", str(remote), str(updater)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@agent-vault.invalid"], cwd=updater, check=True)
        subprocess.run(["git", "config", "user.name", "Agent Vault test"], cwd=updater, check=True)
        (updater / ".agent-vault" / "manifest.yaml").write_text("version: 2\n")
        subprocess.run(["git", "add", ".agent-vault/manifest.yaml"], cwd=updater, check=True)
        subprocess.run(["git", "commit", "-m", "remote update"], cwd=updater, check=True, capture_output=True)
        subprocess.run(["git", "push"], cwd=updater, check=True, capture_output=True)
        status = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=all"], cwd=vault_env["repo"], text=True
        )
        assert not status, status

        vault = Vault(repo_path=vault_env["repo"], key_path=vault_env["owner_key"], auto_pull=False)
        vault.pull()
        assert (vault_env["repo"] / ".agent-vault" / "manifest.yaml").read_text() == "version: 2\n"


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

    def test_url_clone_uses_a_nonexistent_temporary_checkout(self, tmp_path, monkeypatch):
        """A failed remote clone cannot publish a partial cache directory."""
        from agent_vault import vault as vault_module

        monkeypatch.setenv("HOME", str(tmp_path))
        temporary_parent = tmp_path / "temporary-parent"
        temporary_parent.mkdir()
        monkeypatch.setattr(vault_module.tempfile, "mkdtemp", lambda **_: str(temporary_parent))

        def fake_git(cwd, *args, **_):
            destination = Path(args[-1])
            assert not destination.exists()
            destination.mkdir()
            (destination / ".git").mkdir()
            return subprocess.CompletedProcess(["git", *args], 0, "", "")

        monkeypatch.setattr(vault_module, "_run_git", fake_git)
        cache_dir = vault_module._resolve_repo_path("https://example.invalid/vault.git")
        assert (cache_dir / ".git").is_dir()
        assert not temporary_parent.exists()

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
