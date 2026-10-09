class AgentSign < Formula
  desc "Signed git commits for AI agents, with one approval you can see and revoke"
  homepage "https://github.com/taylor-made-labs/agent-sign"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  # The sha256 lines are filled in from SHA256SUMS.txt when a release is tagged.
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-aarch64-apple-darwin.tar.gz"
    else
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-x86_64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-x86_64-unknown-linux-gnu.tar.gz"
    else
      url "https://github.com/taylor-made-labs/agent-sign/releases/download/v0.1.0/agent-sign-aarch64-unknown-linux-gnu.tar.gz"
    end
  end

  # The `git` wrapper is not linked into Homebrew's bin: that would put it in
  # front of git for every program on the machine and clash with Homebrew's own
  # git. It stays in libexec, and the installer puts it first on the PATH of
  # the shells agents start from.
  def install
    bin.install "bin/agent-signd"
    bin.install "bin/agent-sign"
    bin.install "bin/agent-ssh-sign"
    libexec.install "bin/agent-git"
    (libexec/"wrapper").mkpath
    (libexec/"wrapper").install_symlink libexec/"agent-git" => "git"
    pkgshare.install "scripts"
  end

  def caveats
    <<~EOS
      To finish setting up (agent key, service, and the git wrapper on your
      shell's PATH), run:
        #{pkgshare}/scripts/install.sh --from-homebrew #{opt_prefix}
    EOS
  end

  test do
    assert_match "agent-sign", shell_output("#{bin}/agent-sign --version 2>&1")
  end
end
