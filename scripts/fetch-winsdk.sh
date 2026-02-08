#!/usr/bin/env bash
#
# fetch-winsdk.sh — Download Windows SDK + CRT headers/libs via xwin.
#
# Uses an isolated CARGO_HOME/RUSTUP_HOME so nothing is left behind
# except the output directory containing crt/ and sdk/.
#

set -euo pipefail

# ---------- helpers ----------

# download URL to stdout
download() {
    if command -v curl &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf "$1"
    elif command -v wget &>/dev/null; then
        wget -qO- "$1"
    else
        echo "Error: neither curl nor wget found. Install one and retry." >&2
        exit 1
    fi
}

# ---------- defaults ----------

OUTPUT_DIR="./winsdk"
FORCE=0
ISOLATED=0

# ---------- argument parsing ----------

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Download Windows SDK and CRT headers/libs via xwin.

Options:
  --output DIR   Output directory (default: ./winsdk)
  --force        Re-download even if output directory already exists
  --isolated     Always download fresh Rust, ignore system Rust
  -h, --help     Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --isolated)
            ISOLATED=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ---------- skip if already downloaded ----------

if [[ $FORCE -eq 0 && -d "$OUTPUT_DIR/crt" && -d "$OUTPUT_DIR/sdk" ]]; then
    echo "Windows SDK already present in $OUTPUT_DIR (use --force to re-download)"
    exit 0
fi

# ---------- temp dir with cleanup ----------

_tmpbase="${TMPDIR:-/tmp}"
TMPDIR_ROOT="$(mktemp -d "${_tmpbase%/}/fetch-winsdk.XXXXXX")"
echo "Temp directory: $TMPDIR_ROOT"
cleanup() {
    echo "Cleaning up temp directory..."
    rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

# ---------- find or install xwin ----------

XWIN=""

# 1) Check for existing xwin on PATH
if [[ $ISOLATED -eq 0 ]] && command -v xwin &>/dev/null; then
    XWIN="$(command -v xwin)"
    echo "Using system xwin: $XWIN"
fi

# 2) Fall back to cargo install
if [[ -z "$XWIN" ]]; then
    XWIN_ROOT="$TMPDIR_ROOT/xwin-install"
    mkdir -p "$XWIN_ROOT"

    if [[ $ISOLATED -eq 0 ]] && command -v cargo &>/dev/null; then
        echo "Using system cargo: $(command -v cargo)"
    else
        echo "Downloading Rust toolchain into temp directory..."
        export CARGO_HOME="$TMPDIR_ROOT/cargo"
        export RUSTUP_HOME="$TMPDIR_ROOT/rustup"
        mkdir -p "$CARGO_HOME" "$RUSTUP_HOME"
        download https://sh.rustup.rs \
            | sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal
        export PATH="$CARGO_HOME/bin:$PATH"
    fi

    echo "Using cargo: $(which cargo)"
    cargo --version

    echo "Installing xwin..."
    cargo install xwin --root "$XWIN_ROOT"
    XWIN="$XWIN_ROOT/bin/xwin"
fi

# ---------- run xwin ----------

# Remove existing output if --force
if [[ $FORCE -eq 1 && -d "$OUTPUT_DIR" ]]; then
    echo "Removing existing $OUTPUT_DIR..."
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"

# Resolve to absolute path for xwin
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Fetching Windows SDK + CRT into $OUTPUT_DIR..."
"$XWIN" \
    --accept-license \
    --arch x86,x86_64 \
    --cache-dir "$TMPDIR_ROOT/xwin-cache" \
    splat \
    --copy \
    --output "$OUTPUT_DIR"

echo "Done. Windows SDK available at $OUTPUT_DIR"
