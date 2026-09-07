#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo "Running Demo..."
echo "=========================================="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build/demo"
CLIENT_EXECUTABLE="$PROJECT_ROOT/client"
INPUT_FILE="$PROJECT_ROOT/demo/user_input_demo.txt"
DEMO_FILES_DIR="$PROJECT_ROOT/demo/demo_files"
LARGE_DEMO_FILE_NAME="large_demo_file.bin"
LARGE_DEMO_FILE="$DEMO_FILES_DIR/$LARGE_DEMO_FILE_NAME"

echo "Building client..."

# CMake owns platform and architecture selection. The demo only requests the
# Release client target and disables test dependencies.
cmake \
    -S "$PROJECT_ROOT" \
    -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF

cmake --build "$BUILD_DIR" --target client --parallel

# CMake places runtime targets in PROJECT_ROOT, so the expected executable is
# exactly $PROJECT_ROOT/client. Fail early if the build did not produce it.
if [[ ! -x "$CLIENT_EXECUTABLE" ]]; then
    echo "Error: client executable was not created at $CLIENT_EXECUTABLE" >&2
    exit 1
fi

echo "Build completed"
echo

# Generate a 21 MiB file so the demo can exercise the 20 MiB file-size limit.
dd if=/dev/zero of="$LARGE_DEMO_FILE" bs=1048576 count=21 >/dev/null 2>&1

# Remove generated demo files on both successful and failed exits.
trap 'rm -f "$INPUT_FILE" "$LARGE_DEMO_FILE"' EXIT

cat <<EOF > "$INPUT_FILE"
inv@lid_username
glo_chn
$DEMO_FILES_DIR
demo_image.jpg
invalid/filename
$LARGE_DEMO_FILE_NAME
demo_document.pdf
done
EOF

(
    cd "$PROJECT_ROOT"
    "$CLIENT_EXECUTABLE" < "$INPUT_FILE"
)

echo "Demo completed"
