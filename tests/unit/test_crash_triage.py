import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
from src.core.crash_triage import CrashTriage


class TestCrashTriage:

    def test_discover_crashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(5):
                fpath = os.path.join(tmpdir, "crash_{:04d}".format(i))
                with open(fpath, "wb") as f:
                    f.write(b"\x00" * (i + 1))
            sub_dir = os.path.join(tmpdir, "subdir")
            os.makedirs(sub_dir)
            empty_file = os.path.join(tmpdir, "empty_crash")
            with open(empty_file, "wb") as f:
                pass
            triage = CrashTriage(tmpdir)
            crashes = triage.discover_crashes()
            assert len(crashes) == 5
            for c in crashes:
                assert c["size"] > 0
                assert "path" in c
                assert "name" in c

    def test_discover_crashes_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            triage = CrashTriage(tmpdir)
            crashes = triage.discover_crashes()
            assert crashes == []

    def test_deduplicate_crashes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(3):
                fpath = os.path.join(tmpdir, "crash_A_{}".format(i))
                with open(fpath, "wb") as f:
                    f.write(b"\x00\x02AAAA")
            for i in range(2):
                fpath = os.path.join(tmpdir, "crash_B_{}".format(i))
                with open(fpath, "wb") as f:
                    f.write(b"\x00\x03BBBB")
            triage = CrashTriage(tmpdir)
            crashes = triage.discover_crashes()
            groups = triage.deduplicate_crashes(crashes)
            assert len(groups) <= 5
            total = sum(len(g["crashes"]) for g in groups)
            assert total == 5

    def test_get_signal_info_segfault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_file = os.path.join(tmpdir, "crash1")
            with open(crash_file, "wb") as f:
                f.write(b"\x00\x02AAAA")
            triage = CrashTriage(tmpdir)
            mock_result = {
                "reproducible": True,
                "returncode": -11,
                "stderr": "SIGSEGV on address 0x00000000",
                "stdout": "",
            }
            with patch.object(triage, "reproduce_crash", return_value=mock_result):
                sig = triage.get_signal_info(crash_file, "/bin/false")
                assert sig["signal"] == "SIGSEGV"

    def test_get_signal_info_abort(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_file = os.path.join(tmpdir, "crash2")
            with open(crash_file, "wb") as f:
                f.write(b"\x00\x02AAAA")
            triage = CrashTriage(tmpdir)
            mock_result = {
                "reproducible": True,
                "returncode": -6,
                "stderr": "SIGABRT (AddressSanitizer heap-buffer-overflow)",
                "stdout": "",
            }
            with patch.object(triage, "reproduce_crash", return_value=mock_result):
                sig = triage.get_signal_info(crash_file, "/bin/false")
                assert sig["signal"] == "SIGABRT"

    def test_generate_gdb_script(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            crash_file = os.path.join(tmpdir, "crash.bin")
            with open(crash_file, "wb") as f:
                f.write(b"\x00")
            triage = CrashTriage(tmpdir)
            script_path = triage.generate_gdb_script(crash_file, "/tmp/target")
            assert os.path.exists(script_path)
            with open(script_path, "r") as f:
                content = f.read()
            assert "set pagination off" in content
            assert "bt full" in content
            assert "info registers" in content
