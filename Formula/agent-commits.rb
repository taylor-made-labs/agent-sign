class AgentCommits < Formula
  desc "Signed git commits for AI agents, with one approval you can see and revoke"
  homepage "https://github.com/taylor-made-labs/agent-commits"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  # The sha256 lines are filled in from SHA256SUMS.txt when a release is tagged.
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/taylor-made-labs/agent-commits/releases/download/v0.1.0/agent-commits-aarch64-apple-darwin.tar.gz"
    else
      url "https://github.com/taylor-made-labs/agent-commits/releases/download/v0.1.0/agent-commits-x86_64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/taylor-made-labs/agent-commits/releases/download/v0.1.0/agent-commits-x86_64-unknown-linux-gnu.tar.gz"
    else
      url "https://github.com/taylor-made-labs/agent-commits/releases/download/v0.1.0/agent-commits-aarch64-unknown-linux-gnu.tar.gz"
    end
  end

  # The `git` wrapper is not linked into Homebrew's bin: that would put it in
  # front of git for every program on the machine and clash with Homebrew's own
  # git. It stays in libexec, and the installer puts it first on the PATH of
  # the shells agents start from.
  def install
    bin.install "bin/agent-commitsd"
    bin.install "bin/agent-commits"
    bin.install "bin/agent-commits-ssh-sign"
    libexec.install "bin/agent-commits-git"
    (libexec/"wrapper").mkpath
    (libexec/"wrapper").install_symlink libexec/"agent-commits-git" => "git"
    bin.install_symlink bin/"agent-commitsd" => "agent-signd"
    bin.install_symlink bin/"agent-commits" => "agent-sign"
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
    assert_match "agent-commits", shell_output("#{bin}/agent-commits --version 2>&1")
  end
end
