# Setup Guide: Embedded C AFL Fuzzer

## Prerequisites

- Ubuntu 22.04 or similar Linux distribution
- GCC 11+
- Python 3.10+
- 8GB RAM minimum (16GB recommended for fuzzing)

## Step 1: Install AFL++

```bash
git clone https://github.com/AFLplusplus/AFLplusplus.git /opt/AFLplusplus
cd /opt/AFLplusplus
make distrib
sudo make install
```

Verify installation:

```bash
afl-fuzz --version
afl-gcc --version
```

## Step 2: Install Build and Analysis Tools

```bash
sudo apt-get install -y gcc gdb python3-pip
cd /path/to/embedded-c-afl-fuzzer
pip install -r requirements.txt
```

## Step 3: Compile Fuzz Targets

Regular build (with AddressSanitizer for analysis):

```bash
cd src/modules/fuzz_targets
make clean
make all
```

AFL-instrumented build (for fuzzing):

```bash
cd src/modules/fuzz_targets
make clean
make afl
```

Binaries will be in `src/modules/fuzz_targets/bin/`.

## Step 4: Prepare Seed Corpus

Create a minimal seed corpus for each target:

```bash
mkdir -p crashes/corpus/buffer_overflow
echo -ne '\x00\x01\x00\x05hello' > crashes/corpus/buffer_overflow/seed1
echo -ne 'IMGF\x00\x04\x00\x04\x03\x00' > crashes/corpus/buffer_overflow/seed2
```

## Step 5: Run the Fuzzer

Using the Python harness manager:

```bash
python -m src.core.fuzz_harness \
  --target src/modules/fuzz_targets/bin/buffer_overflow \
  --input crashes/corpus/buffer_overflow \
  --output crashes/output/buffer_overflow \
  --timeout 3600
```

Or directly with AFL:

```bash
afl-fuzz -i crashes/corpus/buffer_overflow \
  -o crashes/output/buffer_overflow \
  -m none -t 1000 \
  -- src/modules/fuzz_targets/bin/buffer_overflow
```

## Step 6: Analyze Crashes

Once crashes are found, triage them:

```bash
python -m src.core.crash_triage \
  --crashes-dir crashes/output/buffer_overflow/default/crashes \
  --target src/modules/fuzz_targets/bin/buffer_overflow \
  --source-dir src/modules/fuzz_targets/targets
```

## Step 7: Root Cause Analysis

Generate a detailed report:

```bash
python -m src.core.root_cause_analyzer \
  --source-dir src/modules/fuzz_targets/targets \
  --crash-file crashes/output/buffer_overflow/default/crashes/id:000000 \
  --signal SIGSEGV \
  --output reports/crash_analysis.md
```

## Step 8: GDB Walkthrough

Generate and use a GDB script for a specific crash:

```bash
python -m src.core.crash_triage \
  --crashes-dir crashes/output/buffer_overflow/default/crashes \
  --target src/modules/fuzz_targets/bin/buffer_overflow
```

Then run GDB:

```bash
gdb -x crash_0000.gdb
```

Inside GDB, key commands:

- `bt full` - Full backtrace with local variables
- `info registers` - CPU register state
- `x/16wx $rsp` - Memory dump at stack pointer
- `info frame` - Current frame information
- `frame N` - Switch to frame N
- `print variable` - Print variable value

## Docker Setup (Alternative)

```bash
cd lab/docker-compose
docker-compose up -d
docker exec -it fuzzer bash
```

## Interpreting ASan Output

When ASan detects an issue, look for:

- `heap-buffer-overflow` - Writing past allocated buffer
- `stack-buffer-overflow` - Writing past stack buffer
- `heap-use-after-free` - Accessing freed memory
- `SEGV on unknown address` - Possible null pointer or corruption

The ASan output includes the exact allocation/deallocation stack traces, making root cause identification straightforward.
