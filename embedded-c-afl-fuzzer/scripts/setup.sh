#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Installing system dependencies ==="
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential gcc gdb python3 python3-pip git make

echo "=== Installing AFL++ ==="
if ! command -v afl-fuzz &>/dev/null; then
    if [ ! -d "/opt/AFLplusplus" ]; then
        git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git /opt/AFLplusplus
    fi
    cd /opt/AFLplusplus
    make distrib
    sudo make install
    cd "$PROJECT_ROOT"
else
    echo "AFL++ already installed"
fi

echo "=== Installing Python dependencies ==="
pip3 install -r "$PROJECT_ROOT/requirements.txt"

echo "=== Compiling fuzz targets with ASan ==="
cd "$PROJECT_ROOT/src/modules/fuzz_targets"
make clean
make all CC=gcc CFLAGS="-O2 -g -fsanitize=address"

echo "=== Compiling fuzz targets with AFL instrumentation ==="
make clean
make afl

echo "=== Creating seed corpus ==="
mkdir -p "$PROJECT_ROOT/crashes/corpus/buffer_overflow"
mkdir -p "$PROJECT_ROOT/crashes/corpus/heap_corruption"
mkdir -p "$PROJECT_ROOT/corpus/corpus/image_parser"

printf '\x00\x01\x00\x05hello' > "$PROJECT_ROOT/crashes/corpus/buffer_overflow/seed1.bin"
printf '\x00\x02\x00\x0aworld!!!!' > "$PROJECT_ROOT/crashes/corpus/buffer_overflow/seed2.bin"

printf '\x00\x00\x00\x01\x00\x03\x00\x05abcXXXXX' > "$PROJECT_ROOT/crashes/corpus/heap_corruption/seed1.bin"

printf 'IMGF\x00\x04\x00\x04\x03\x00' > "$PROJECT_ROOT/crashes/corpus/image_parser/seed1.bin"

printf 'IMGF\x00\x02\x00\x02\x01\x00\xff\xff' > "$PROJECT_ROOT/crashes/corpus/image_parser/seed2.bin"

echo "=== Setup complete ==="
echo "Binaries in: src/modules/fuzz_targets/bin/"
ls -la "$PROJECT_ROOT/src/modules/fuzz_targets/bin/"
echo ""
echo "To run fuzzer:"
echo "  python -m src.core.fuzz_harness --target src/modules/fuzz_targets/bin/buffer_overflow --input crashes/corpus/buffer_overflow --output crashes/output/buffer_overflow"
echo ""
echo "To triage crashes:"
echo "  python -m src.core.crash_triage --crashes-dir crashes/output/buffer_overflow/default/crashes --target src/modules/fuzz_targets/bin/buffer_overflow"
