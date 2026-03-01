class AgentVault < Formula
  desc "Zero-trust credential manager for AI agents"
  homepage "https://github.com/ewimsatt/agent-vault"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ewimsatt/agent-vault/releases/latest/download/agent-vault-aarch64-apple-darwin.tar.gz"
      # sha256 "PLACEHOLDER" # Updated by release automation
    else
      url "https://github.com/ewimsatt/agent-vault/releases/latest/download/agent-vault-x86_64-apple-darwin.tar.gz"
      # sha256 "PLACEHOLDER" # Updated by release automation
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/ewimsatt/agent-vault/releases/latest/download/agent-vault-aarch64-unknown-linux-gnu.tar.gz"
      # sha256 "PLACEHOLDER" # Updated by release automation
    else
      url "https://github.com/ewimsatt/agent-vault/releases/latest/download/agent-vault-x86_64-unknown-linux-gnu.tar.gz"
      # sha256 "PLACEHOLDER" # Updated by release automation
    end
  end

  def install
    bin.install "agent-vault"
  end

  test do
    assert_match "agent-vault", shell_output("#{bin}/agent-vault --help")
  end
end
