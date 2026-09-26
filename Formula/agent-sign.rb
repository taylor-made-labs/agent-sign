class AgentSign < Formula
  desc "Deterministic commit signing & identity multiplexer for AI coding agents"
  homepage "https://github.com/taylor-made-labs/agent-sign"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-aarch64-apple-darwin.tar.gz"
      # sha256 "<TO_BE_COMPUTED_ON_RELEASE>"
    else
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-x86_64-apple-darwin.tar.gz"
      # sha256 "<TO_BE_COMPUTED_ON_RELEASE>"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-x86_64-unknown-linux-gnu.tar.gz"
      # sha256 "<TO_BE_COMPUTED_ON_RELEASE>"
    end
  end

  def install
    bin.install "bin/agent-signd"
    bin.install "bin/agent-sign"
    bin.install "bin/agent-git"
    (bin/"git").install_symlink bin/"agent-git"
  end

  service do
    run [opt_bin/"agent-signd"]
    keep_alive true
    log_path var/"log/agent-signd.log"
    error_log_path var/"log/agent-signd.err.log"
  end

  def post_install
    system "#{bin}/agent-signd", "setup"
  end

  test do
    assert_match "agent-sign", shell_output("#{bin}/agent-sign --version 2>&1", 1)
  end
end
