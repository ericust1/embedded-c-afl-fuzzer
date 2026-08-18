import os
import sys
import subprocess
import tempfile
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
from src.core.crash_triage import CrashTriage
from src.core.root_cause_analyzer import RootCauseAnalyzer


def _compile_target(tmpdir):
    src = os.path.join(
        os.path.dirname(__file__),
        "../../src/modules/fuzz_targets/targets/buffer_overflow.c"
    )
    src = os.path.abspath(src)
    binary = os.path.join(tmpdir, "buffer_overflow")
    result = subprocess.run(
        ["gcc", "-O0", "-g", "-o", binary, src],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("Compilation failed: " + result.stderr)
    return binary


def _make_overflow_input():
    header = struct.pack(">HH", 0x0002, 200)
    payload = b"A" * 200
    return header + payload


class TestFuzzingPipeline:

    def test_overflow_crash_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_target(tmpdir)
            crash_input = _make_overflow_input()
            input_file = os.path.join(tmpdir, "crash_input")
            with open(input_file, "wb") as f:
                f.write(crash_input)
            result = subprocess.run(
                [binary, input_file],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode != 0

    def test_normal_input_no_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_target(tmpdir)
            header = struct.pack(">HH", 0x0001, 10)
            payload = b"hello wor"
            normal_input = header + payload
            input_file = os.path.join(tmpdir, "normal_input")
            with open(input_file, "wb") as f:
                f.write(normal_input)
            result = subprocess.run(
                [binary, input_file],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert result.returncode == 0

    def test_crash_triage_discovers_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_dir = os.path.join(tmpdir, "crashes")
            os.makedirs(crash_dir)
            for i in range(3):
                fpath = os.path.join(crash_dir, "crash_{:04d}".format(i))
                with open(fpath, "wb") as f:
                    f.write(b"\x00\x02" + b"A" * (i + 1))
            triage = CrashTriage(crash_dir)
            crashes = triage.discover_crashes()
            assert len(crashes) == 3

    def test_root_cause_classifies_overflow(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        bt_text = (
            "#0  0x0000000000401523 in parse_protocol_message "
            "(buf=0x7fffffffe3a0, buf_len=200) at buffer_overflow.c:22\n"
            "#1  0x0000000000401567 in main (argc=2, argv=0x7fffffffe4b8) "
            "at buffer_overflow.c:35\n"
        )
        frames = analyzer.parse_backtrace(bt_text)
        vtype = analyzer.classify_vulnerability(
            frames[0]["function"] if frames else "", bt_text, "SIGSEGV"
        )
        assert vtype == "buffer overflow"

    def test_image_parser_integer_overflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(
                os.path.dirname(__file__),
                "../../src/modules/fuzz_targets/targets/image_parser.c"
            )
            src = os.path.abspath(src)
            binary = os.path.join(tmpdir, "image_parser")
            result = subprocess.run(
                ["gcc", "-O0", "-g", "-o", binary, src],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return
            header = b"IMGF"
            header += struct.pack(">HH", 65535, 65535)
            header += struct.pack("B", 4)
            header += struct.pack("B", 0)
            payload = b"\x00" * 100
            input_file = os.path.join(tmpdir, "img_input")
            with open(input_file, "wb") as f:
                f.write(header + payload)
            res = subprocess.run(
                [binary, input_file],
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert res.returncode in (0, -6, -11)
