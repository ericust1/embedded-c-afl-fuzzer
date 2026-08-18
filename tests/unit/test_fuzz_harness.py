import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
from src.core.fuzz_harness import FuzzHarness


class TestFuzzHarness:

    def test_harness_creation_standalone(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_bin = os.path.join(tmpdir, "target")
            input_dir = os.path.join(tmpdir, "input")
            output_dir = os.path.join(tmpdir, "output")
            harness = FuzzHarness(target_bin, input_dir, output_dir)
            harness_path = harness.create_harness(template_type="standalone")
            assert os.path.exists(harness_path)
            with open(harness_path, "r") as f:
                code = f.read()
            assert "fread" in code
            assert "read(STDIN_FILENO" in code
            assert "parse_protocol_message" in code
            assert "process_records" in code
            assert "parse_image" in code

    def test_harness_creation_afl_persistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target_bin = os.path.join(tmpdir, "target")
            input_dir = os.path.join(tmpdir, "input")
            output_dir = os.path.join(tmpdir, "output")
            harness = FuzzHarness(target_bin, input_dir, output_dir)
            harness_path = harness.create_harness(template_type="afl_persistent")
            assert os.path.exists(harness_path)
            with open(harness_path, "r") as f:
                code = f.read()
            assert "__AFL_FUZZ_INIT" in code
            assert "__AFL_LOOP" in code

    def test_build_target_with_gcc(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src_dir = os.path.join(tmpdir, "src")
            os.makedirs(src_dir)
            src_file = os.path.join(src_dir, "simple.c")
            with open(src_file, "w") as f:
                f.write(
                    '#include <stdio.h>\n'
                    '#include <stdlib.h>\n'
                    '#include <string.h>\n'
                    '#include <unistd.h>\n'
                    '\n'
                    'int parse_protocol_message(const unsigned char *buf, size_t buf_len) {\n'
                    '    return 0;\n'
                    '}\n'
                    'int process_records(const unsigned char *buf, size_t buf_len) {\n'
                    '    return 0;\n'
                    '}\n'
                    'int parse_image(const unsigned char *buf, size_t buf_len) {\n'
                    '    return 0;\n'
                    '}\n'
                )
            harness_file = os.path.join(src_dir, "harness.c")
            bin_dir = os.path.join(tmpdir, "bin")
            os.makedirs(bin_dir, exist_ok=True)
            target_bin = os.path.join(bin_dir, "target")
            harness = FuzzHarness(target_bin, os.path.join(tmpdir, "in"), os.path.join(tmpdir, "out"))
            harness.create_harness(template_type="standalone", output_path=harness_file)
            result = harness.build_target(src_file, harness_file, compiler="gcc")
            assert os.path.exists(result)
            assert harness.mode == "standalone"

    def test_stats_parsing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "output")
            os.makedirs(output_dir)
            stats_file = os.path.join(output_dir, "fuzzer_stats")
            with open(stats_file, "w") as f:
                f.write(
                    "start_time        : 1700000000\n"
                    "last_update       : 1700003600\n"
                    "fuzzer_pid        : 12345\n"
                    "cycles_done       : 42\n"
                    "execs_done        : 500000\n"
                    "execs_per_sec     : 1,250\n"
                    "paths_total       : 350\n"
                    "paths_favored     : 200\n"
                    "unique_crashes    : 7\n"
                    "unique_hangs      : 2\n"
                )
            harness = FuzzHarness("/tmp/dummy", "/tmp/in", output_dir)
            stats = harness.get_stats()
            assert stats is not None
            assert stats["execs_per_sec"] == 1250
            assert stats["paths_total"] == 350
            assert stats["unique_crashes"] == 7
            assert stats["unique_hangs"] == 2

    def test_run_fuzzer_requires_afl_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = FuzzHarness("/tmp/dummy", os.path.join(tmpdir, "in"), os.path.join(tmpdir, "out"))
            harness.mode = "standalone"
            with pytest.raises(RuntimeError, match="AFL instrumentation"):
                harness.run_fuzzer()

    def test_init_sets_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            harness = FuzzHarness("/a/b", "/c/d", "/e/f")
            assert harness.target_binary == "/a/b"
            assert harness.input_dir == "/c/d"
            assert harness.output_dir == "/e/f"
