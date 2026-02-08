#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$PROJECT_DIR/bin"

# Clean output directory
rm -rf "$BIN_DIR"
mkdir -p "$BIN_DIR/x86" "$BIN_DIR/x64"

for arch in x86 x64; do
    echo "=== Building $arch ==="

    BUILD_DIR="$PROJECT_DIR/build-$arch"
    rm -rf "$BUILD_DIR"

    cmake --preset "$arch" -S "$PROJECT_DIR"
    cmake --build "$BUILD_DIR"

    # Copy scrun
    cp "$BUILD_DIR/tools/scrun.exe" "$BIN_DIR/$arch/scrun.exe"
    echo "  $arch/scrun.exe"

    # Copy all .bin files
    for bin in "$BUILD_DIR"/examples/*/*.bin; do
        [ -f "$bin" ] || continue
        name="$(basename "$bin")"
        cp "$bin" "$BIN_DIR/$arch/$name"
        size=$(wc -c < "$bin" | tr -d ' ')
        echo "  $arch/$name ($size bytes)"
    done

    echo ""
done

echo "Done. Output in $BIN_DIR/"
