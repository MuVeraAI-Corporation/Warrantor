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
# BLOCKED WHILE THE REPOSITORY IS PRIVATE. Homebrew fetches release assets
# anonymously, and GitHub returns 404 for a private repo's assets to anonymous
# callers -- verified: `curl` gets 404 on the same URL `gh release download`
# fetches happily. Scoop and `cargo binstall` fetch the same way and are equally
# blocked. Publishing the tap before the repo is public ships a formula that
# fails for everyone who taps it.
#
# The sha256 values below were computed from the PUBLISHED v1.0.0 assets -- downloaded
# from the GitHub Release, not from a local build -- so they attest to what a user
# actually receives. Recompute after every release:
#   gh release download vX.Y.Z && shasum -a 256 warrantor-vX.Y.Z-*.tar.gz
#
# Homebrew chdirs into a tarball's single top-level directory while staging, so
# `bin.install "warrantor"` resolves even though the binary sits inside
# warrantor-v1.0.0-<target>/ rather than at the archive root. Verified against the
# real archive layout.
class Warrantor < Formula
  desc "Bounded authority for coding agents: irreversible actions staged for approval"
  homepage "https://github.com/MuVeraAI-Corporation/Warrantor"
  version "1.0.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "adf53bdb947694c5fdc0a170faf6c9adc52e5591a18c8b15837e8cc5aa036b17"
    end
    on_intel do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "28e0f8fcf2043ec7be0e90edc14feddd5aa3caf5dd4902d94e11c3160e4e443e"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/MuVeraAI-Corporation/Warrantor/releases/download/v#{version}/warrantor-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b45b1383e410dba162da1ff0a4134b40caa94b2d954d1d05862640eb2d70e02b"
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
