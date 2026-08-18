# Embedded C AFL Fuzzer

A cybersecurity portfolio project demonstrating fuzzing of C-based network and image parsing libraries using AFL++ (American Fuzzy Lop), with automated crash triage and root cause analysis.

## Architecture

```
 +-------------+     +----------------+     +---------------+     +----------+
 | Fuzz Input  | --> | AFL Fuzzer     | --> | Target Binary | --> | Crash /  |
 | (Corpus)    |     | (afl-fuzz)     |     | (Instrumented)|     | Signal   |
 +-------------+     +----------------+     +---------------+     +----------+
                                                                    |
                                                                    v
 +--------------+     +-----------+     +------------------+     +----------+
 | Markdown     | <-- | Root Cause| <-- | GDB Backtrace   | <-- | Crash    |
 | Report       |     | Analysis  |     | (bt full, regs) |     | Triage   |
 +--------------+     +-----------+     +------------------+     +----------+
```

## Features

- **Three fuzz targets** with distinct vulnerability classes
- **AFL++ integration** with persistent and fork-server modes
- **Automated crash triage** with deduplication by backtrace similarity
- **Root cause analysis** with vulnerability classification and severity scoring
- **GDB batch-mode analysis** with automated script generation
- **Docker and Terraform** infrastructure for cloud and containerized fuzzing
- **CI/CD pipeline** for automated compilation and testing

## Fuzz Targets

### 1. Buffer Overflow (buffer_overflow.c)

Parses a binary protocol header (2-byte type, 2-byte length) and copies data into a 64-byte stack buffer using `memcpy` without bounds checking when `type=0x0002`.

- **Vulnerability**: Stack buffer overflow (CWE-120)
- **Trigger**: Set type to `0x0002` and length greater than 64

### 2. Heap Corruption (heap_corruption.c)

Allocates heap records with name and data fields from input, then frees `records[1]->data` and `records[2]->name` before the final cleanup loop that tries to free all pointers again.

- **Vulnerability**: Double-free / use-after-free (CWE-416, CWE-415)
- **Trigger**: Provide input that creates 3+ records to trigger the premature free path

### 3. Image Parser (image_parser.c)

Parses a custom `IMGF` image format with width, height, and bytes-per-pixel fields. The buffer size calculation `width * height * bpp` can overflow on 32-bit arithmetic.

- **Vulnerability**: Integer overflow leading to small allocation (CWE-190)
- **Trigger**: Set width and height to values whose product overflows

## Usage

### Quick Start

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

### Compile Targets

```bash
cd src/modules/fuzz_targets
make all
```

### Run Fuzzer

```bash
python -m src.core.fuzz_harness \
  --target src/modules/fuzz_targets/bin/buffer_overflow \
  --input crashes/corpus/buffer_overflow \
  --output crashes/output/buffer_overflow
```

### Triage Crashes

```bash
python -m src.core.crash_triage \
  --crashes-dir crashes/output/buffer_overflow/default/crashes \
  --target src/modules/fuzz_targets/bin/buffer_overflow
```

### Root Cause Analysis

```bash
python -m src.core.root_cause_analyzer \
  --source-dir src/modules/fuzz_targets/targets \
  --signal SIGSEGV \
  --output reports/analysis.md
```

## Project Structure

```
embedded-c-afl-fuzzer/
+-- src/
|   +-- core/
|   |   +-- fuzz_harness.py
|   |   +-- crash_triage.py
|   |   +-- root_cause_analyzer.py
|   +-- modules/
|       +-- fuzz_targets/
|       |   +-- targets/        # C source files
|       |   +-- bin/            # Compiled binaries
|       |   +-- Makefile
|       +-- gdb_scripts/
+-- tests/
|   +-- unit/
|   +-- integration/
+-- lab/
|   +-- docker-compose.yml
|   +-- terraform/
+-- scripts/
+-- docs/
+-- crashes/
```

## Stack

C/C++, AFL++ (American Fuzzy Lop), Python 3, GCC, GDB, AddressSanitizer, Docker, Terraform
