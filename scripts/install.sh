#!/usr/bin/env sh
# herdr-with-ws installer
#
# Installs the herdr binary built from the `feature/http-ws-transport`
# fork (xueyangcs/herdr) which adds the WebSocket / HTTP transport.
#
#   curl -fsSL https://raw.githubusercontent.com/xueyangcs/herdr/feature/http-ws-transport/scripts/install.sh | sh
#
# Optional environment variables:
#   HERDR_WS_INSTALL_DIR  install path (default: $HOME/.local/bin)
#   HERDR_WS_REPO         GitHub repo slug (default: xueyangcs/herdr)
#   HERDR_WS_BRANCH       branch to download artifacts from
#                         (default: feature/http-ws-transport)
#   HERDR_WS_RUN_ID       specific GitHub Actions run id; otherwise we
#                         pick the latest successful build-test.yml run

set -eu

REPO="${HERDR_WS_REPO:-xueyangcs/herdr}"
BRANCH="${HERDR_WS_BRANCH:-feature/http-ws-transport}"
INSTALL_DIR="${HERDR_WS_INSTALL_DIR:-$HOME/.local/bin}"
WORKFLOW="build-test.yml"

bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
info()   { printf 'install.sh: %s\n' "$*"; }
fail()   { printf 'install.sh: error: %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require curl
require uname

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)  PLATFORM="linux" ;;
  Darwin) PLATFORM="macos" ;;
  *) fail "unsupported OS: $OS (need Linux or macOS)" ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH_TAG="x86_64" ;;
  arm64|aarch64) ARCH_TAG="aarch64" ;;
  *) fail "unsupported architecture: $ARCH" ;;
esac

ASSET="herdr-${PLATFORM}-${ARCH_TAG}"

# Linux ARM64 is not built by the build-test workflow; tell the user up front.
if [ "$PLATFORM" = "linux" ] && [ "$ARCH_TAG" = "aarch64" ]; then
  fail "no prebuilt binary for linux-aarch64 yet. Build from source: cargo build --release"
fi

bold "→ installing herdr (with WebSocket transport)"
info "platform: $PLATFORM/$ARCH_TAG"
info "repo:     $REPO ($BRANCH)"
info "asset:    $ASSET"
info "target:   $INSTALL_DIR/herdr"

mkdir -p "$INSTALL_DIR"

API="https://api.github.com/repos/${REPO}/actions"

run_id="${HERDR_WS_RUN_ID:-}"
if [ -z "$run_id" ]; then
  info "looking up latest successful build-test.yml run..."
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    AUTH_HEADER="-H Authorization: Bearer $GITHUB_TOKEN"
  else
    AUTH_HEADER=""
  fi
  # shellcheck disable=SC2086
  RESP=$(curl -fsSL $AUTH_HEADER \
    "${API}/workflows/${WORKFLOW}/runs?branch=${BRANCH}&status=success&per_page=1")
  run_id=$(printf '%s' "$RESP" \
    | sed -n 's/.*"id": *\([0-9][0-9]*\).*/\1/p' | head -n1)
  if [ -z "$run_id" ]; then
    fail "could not find a successful '$WORKFLOW' run on $BRANCH. \
Check https://github.com/${REPO}/actions or set HERDR_WS_RUN_ID."
  fi
  info "run id:   $run_id"
fi

# Find the artifact id matching our asset name on that run.
# shellcheck disable=SC2086
ARTIFACTS_JSON=$(curl -fsSL $AUTH_HEADER "${API}/runs/${run_id}/artifacts?per_page=50")
artifact_id=$(printf '%s' "$ARTIFACTS_JSON" \
  | tr ',' '\n' \
  | awk -v a="\"name\": \"$ASSET\"" '
      /"id"/ { id=$0 }
      $0 ~ a { print id; exit }' \
  | sed -n 's/.*"id": *\([0-9][0-9]*\).*/\1/p' | head -n1)

if [ -z "$artifact_id" ]; then
  fail "no artifact named '$ASSET' on run $run_id. \
Workflow may have changed; check the artifact name or pass HERDR_WS_RUN_ID."
fi

info "artifact: $artifact_id"

# Artifacts must be downloaded with auth in most cases — anonymous works for
# public repos via the redirect, but the download URL still requires auth on
# api.github.com. Use the public archive URL via the run page if no token.
DOWNLOAD_URL="${API}/artifacts/${artifact_id}/zip"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

info "downloading artifact zip..."
if [ -n "${GITHUB_TOKEN:-}" ]; then
  curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" \
    -o "$TMP/artifact.zip" "$DOWNLOAD_URL"
else
  # Without a token, fall back to nightly.link (public proxy for GitHub Actions
  # artifacts that doesn't require auth). This is the path most users hit.
  PROXY_URL="https://nightly.link/${REPO}/actions/artifacts/${artifact_id}.zip"
  info "using nightly.link proxy (set GITHUB_TOKEN for direct download)"
  curl -fsSL -o "$TMP/artifact.zip" "$PROXY_URL" || \
    fail "download failed. Set GITHUB_TOKEN with 'repo' scope and re-run."
fi

# Extract
require unzip 2>/dev/null || true
if command -v unzip >/dev/null 2>&1; then
  unzip -q -o "$TMP/artifact.zip" -d "$TMP"
elif command -v bsdtar >/dev/null 2>&1; then
  bsdtar -xf "$TMP/artifact.zip" -C "$TMP"
else
  fail "need 'unzip' or 'bsdtar' to extract the artifact"
fi

if [ ! -f "$TMP/herdr" ]; then
  fail "artifact didn't contain a 'herdr' binary"
fi

chmod +x "$TMP/herdr"

# Replace existing binary safely.
TARGET="$INSTALL_DIR/herdr"
if [ -e "$TARGET" ]; then
  info "stopping any running herdr (so the binary can be replaced)..."
  pkill -TERM -x herdr 2>/dev/null || true
  sleep 1
  pkill -KILL -x herdr 2>/dev/null || true
  rm -f "$TARGET"
fi

mv "$TMP/herdr" "$TARGET"
chmod +x "$TARGET"

bold "✓ installed: $TARGET"
"$TARGET" --version
echo
info "make sure $INSTALL_DIR is in your PATH"
info "next:  herdr --help"
info "       herdr ws-server --port 8080 --password <pw>     # remote machine"
info "       herdr --remote ws://host:8080 --ws-password <pw> # local machine"
