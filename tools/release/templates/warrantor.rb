# Homebrew formula for the warrantor CLI.
#
# Lives in a personal tap (MuVeraAI-Corporation/homebrew-tap), which needs no
# approval from anyone and can ship the same day. homebrew-core has notability
# requirements -- a rough threshold of users and stars -- and is worth revisiting
# only once there are users to point at.
#
#   brew tap MuVeraAI-Corporation/tap
#   brew install warrantor
#
# The sha256 values are filled in from the release artifacts. `cargo dist` can
# generate and update this file automatically; until then, after a release run:
#   shasum -a 256 warrantor-v1.0.0-*.tar.gz
class Warrantor < Formula
  desc "Bounded authority for coding agents: irreversible actions staged for approval"
  homepage "https://github.com/MuVeraAI-Corporation/Warrantor"
  version "1.0.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_AARCH64_DARWIN"
    end
    on_intel do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_DARWIN"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_SHA256_X86_64_LINUX"
    end
  end

  def install
    bin.install "warrantor"
  end

  test do
    # Assert on real behaviour rather than just a zero exit: `--help` naming the
    # grant subcommand proves the CLI is wired, not merely present.
    assert_match "grant", shell_output("#{bin}/warrantor --help")
  end
end
