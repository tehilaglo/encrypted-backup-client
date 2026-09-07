#!/usr/bin/env bash
set -e

echo "=========================================="
echo "Running Demo..."
echo "=========================================="

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INPUT_FILE="$PROJECT_ROOT/demo/user_input_demo.txt"
DEMO_DIR="$PROJECT_ROOT/demo"

cat <<EOF > "$INPUT_FILE"
inv@lid_username
glo_chn
$DEMO_DIR/demo_files
demo_image.jpg
invalid/filename
large_demo_video.mp4
demo_document.pdf
done
EOF

(
    cd "$PROJECT_ROOT"
    "$PROJECT_ROOT/client" < "$INPUT_FILE"
)

echo "Demo completed"
