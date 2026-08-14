#!/usr/bin/env bash
#
# Build spaceport's Linux release binaries on any host that has docker.
#
# Each target is built inside a container of its own architecture rather than
# with a cross toolchain: `rusqlite` compiles sqlite from source and `ring`
# compiles assembly, so a real cross-compile means keeping four C toolchains
# working, while `--platform` means keeping none. The non-native architecture
# runs under whatever emulation docker has (Rosetta on Apple silicon, qemu
# elsewhere), which is slower to build and identical to run.
#
# This is what the release workflow does, on one host instead of four runners —
# with one difference worth knowing: the glibc builds pick up the base image's
# glibc as their floor, and the release workflow deliberately uses an older one.
# For a binary to hand to somebody else, take the one the release built.
#
#   scripts/cross-compile.sh                          # all four targets
#   scripts/cross-compile.sh x86_64-unknown-linux-musl
#   RUST_IMAGE=rust:1.90-slim-bookworm scripts/cross-compile.sh
#
# Binaries land in `dist/<target>/spaceport`, stripped.

set -euo pipefail

ALL_TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
)

# Slim, so the pull is small; the image still carries the gcc and binutils the
# native build needs.
RUST_IMAGE=${RUST_IMAGE:-rust:slim-bookworm}
PACKAGE=${PACKAGE:-spaceport-cli}
BINARY=spaceport
DIST=${DIST:-dist}

# The cargo registry, kept across runs and shared by every target: without it
# each build re-downloads every dependency.
CARGO_VOLUME=${CARGO_VOLUME:-spaceport-cross-cargo}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

usage() {
  sed -n '3,21p' "${BASH_SOURCE[0]}" | sed 's/^#\{1,2\} \{0,1\}//'
  echo
  echo "Targets: ${ALL_TARGETS[*]}"
}

case ${1-} in
  -h | --help)
    usage
    exit 0
    ;;
esac

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("${ALL_TARGETS[@]}")
fi

for target in "${targets[@]}"; do
  case " ${ALL_TARGETS[*]} " in
    *" ${target} "*) ;;
    *)
      echo "unknown target \`${target}\`; one of: ${ALL_TARGETS[*]}" >&2
      exit 2
      ;;
  esac
done

if ! docker info >/dev/null 2>&1; then
  echo "docker is not running, or this user cannot reach it" >&2
  exit 1
fi

# The architecture the container runs as. Everything else about the build —
# which target triple, which C compiler — follows from the triple itself.
platform_for() {
  case $1 in
    x86_64-*) echo linux/amd64 ;;
    aarch64-*) echo linux/arm64 ;;
  esac
}

host_platform=linux/amd64
case $(uname -m) in
  arm64 | aarch64) host_platform=linux/arm64 ;;
esac

for target in "${targets[@]}"; do
  platform=$(platform_for "$target")

  echo
  echo "==> ${target} (${platform})"
  if [ "$platform" != "$host_platform" ]; then
    echo "    emulated, so this is the slow one"
  fi

  # A target directory per architecture: the two containers disagree about what
  # a build script compiles to, and sharing one directory makes them rebuild
  # each other's artifacts on every alternate run.
  target_dir="target/docker/${platform#linux/}"

  docker run --rm --platform "$platform" \
    --volume "${root}:/work" \
    --volume "${CARGO_VOLUME}:/usr/local/cargo/registry" \
    --workdir /work \
    --env CARGO_TARGET_DIR="/work/${target_dir}" \
    --env CARGO_TERM_COLOR=always \
    --env CARGO_INCREMENTAL=0 \
    --env TARGET="$target" \
    --env PACKAGE="$PACKAGE" \
    --env DIST="$DIST" \
    --env TARGET_DIR="$target_dir" \
    --env HOST_UID="$(id -u)" \
    --env HOST_GID="$(id -g)" \
    "$RUST_IMAGE" \
    sh -eu -c '
      case "$TARGET" in
        *-musl)
          # `rusqlite`s bundled sqlite is C, so a musl-targeting C compiler has
          # to exist. Native to the container arch, so plain musl-tools does it.
          apt-get update -qq
          apt-get install -y --no-install-recommends musl-tools >/dev/null
          CC_x86_64_unknown_linux_musl=musl-gcc
          CC_aarch64_unknown_linux_musl=musl-gcc
          export CC_x86_64_unknown_linux_musl CC_aarch64_unknown_linux_musl
          ;;
      esac

      rustup target add "$TARGET" >/dev/null

      cargo build --release --locked --target "$TARGET" --package "$PACKAGE"

      mkdir -p "/work/${DIST}/${TARGET}"
      cp "/work/${TARGET_DIR}/${TARGET}/release/'"$BINARY"'" "/work/${DIST}/${TARGET}/"
      strip "/work/${DIST}/${TARGET}/'"$BINARY"'"

      # The build ran as root. On a Linux host that would otherwise leave a
      # target directory the user who started this cannot clean up.
      chown -R "${HOST_UID}:${HOST_GID}" "/work/${DIST}" "/work/${TARGET_DIR}"
    '
done

echo
for target in "${targets[@]}"; do
  binary="${DIST}/${target}/${BINARY}"
  echo "${binary}: $(cd "$root" && wc -c <"$binary" | tr -d ' ') bytes"
done
