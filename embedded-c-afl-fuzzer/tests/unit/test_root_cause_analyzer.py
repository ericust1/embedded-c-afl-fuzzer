import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
from src.core.root_cause_analyzer import RootCauseAnalyzer


SAMPLE_BT_MEMCPY = """#0  0x0000000000401523 in parse_protocol_message (buf=0x7fffffffe3a0, buf_len=200) at buffer_overflow.c:22
#1  0x0000000000401567 in main (argc=2, argv=0x7fffffffe4b8) at buffer_overflow.c:35
"""

SAMPLE_BT_FREE = """#0  0x0000000000401890 in process_records (buf=0x7fffffffe3a0, buf_len=100) at heap_corruption.c:58
#1  0x0000000000401100 in free (ptr=0x60200000) at /build/glibc/src/glibc/malloc/malloc.c:3354
#2  0x0000000000401567 in main (argc=2, argv=0x7fffffffe4b8) at heap_corruption.c:75
"""

SAMPLE_BT_IMAGE = """#0  0x0000000000402005 in parse_image (buf=0x7fffffffe3a0, buf_len=16) at image_parser.c:28
#1  0x0000000000402050 in malloc (size=4294967295) at /build/glibc/src/glibc/malloc/malloc.c:3354
#2  0x0000000000401567 in main (argc=2, argv=0x7fffffffe4b8) at image_parser.c:42
"""

SAMPLE_BT_NULL = """#0  0x0000000000401523 in process_data (data=0x0, len=10) at handler.c:44
#1  0x0000000000401567 in main (argc=2, argv=0x7fffffffe4b8) at main.c:20
"""

SAMPLE_BT_ALT = """#0 some_function ()
#1 another_function ()
"""


class TestRootCauseAnalyzer:

    def test_parse_backtrace_standard(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        frames = analyzer.parse_backtrace(SAMPLE_BT_MEMCPY)
        assert len(frames) == 2
        assert frames[0]["function"] == "parse_protocol_message"
        assert frames[0]["line"] == 22
        assert frames[1]["function"] == "main"
        assert frames[0]["address"] == "0x0000000000401523"

    def test_parse_backtrace_alt_format(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        frames = analyzer.parse_backtrace(SAMPLE_BT_ALT)
        assert len(frames) == 2

    def test_identify_vulnerable_function(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        frames = analyzer.parse_backtrace(SAMPLE_BT_MEMCPY)
        func = analyzer.identify_vulnerable_function(frames)
        assert func == "parse_protocol_message"

    def test_classify_buffer_overflow(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        vtype = analyzer.classify_vulnerability(
            "parse_protocol_message", SAMPLE_BT_MEMCPY, "SIGSEGV"
        )
        assert vtype == "buffer overflow"

    def test_classify_heap_corruption(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        vtype = analyzer.classify_vulnerability(
            "process_records", SAMPLE_BT_FREE, "SIGABRT"
        )
        assert vtype in ("heap corruption", "use-after-free")

    def test_classify_integer_overflow(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        vtype = analyzer.classify_vulnerability(
            "parse_image", SAMPLE_BT_IMAGE, "SIGSEGV"
        )
        assert vtype == "integer overflow"

    def test_classify_null_deref(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        vtype = analyzer.classify_vulnerability(
            "process_data", SAMPLE_BT_NULL, "SIGSEGV"
        )
        assert vtype == "null dereference"

    def test_generate_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = RootCauseAnalyzer("/tmp/src")
            crash_info = {
                "crash_file": "/tmp/crash_001",
                "target_binary": "/tmp/buffer_overflow",
                "signal": "SIGSEGV",
                "vulnerable_function": "parse_protocol_message",
                "vulnerability_type": "buffer overflow",
                "severity": "critical",
                "cwe": "CWE-120",
                "backtrace": SAMPLE_BT_MEMCPY,
                "source_context": " 20 |     msg_length = (buf[2] << 8) | buf[3];\n >21 |     memcpy(local_buf, buf + 4, msg_length);\n 22 |     local_buf[msg_length] = '\\0';",
                "recommendation": "Add bounds checking on msg_length before memcpy.",
            }
            output_path = os.path.join(tmpdir, "report.md")
            result = analyzer.generate_analysis_report(crash_info, output_path)
            assert os.path.exists(result)
            with open(result, "r") as f:
                content = f.read()
            assert "Root Cause Analysis Report" in content
            assert "buffer overflow" in content
            assert "parse_protocol_message" in content
            assert "SIGSEGV" in content
            assert "Fix Recommendation" in content

    def test_locate_source_line_no_source_dir(self):
        analyzer = RootCauseAnalyzer(None)
        frame = {"address": "", "file": "buffer_overflow.c", "line": 22}
        result = analyzer.locate_source_line(frame)
        assert result is not None
        assert result["file"] == "buffer_overflow.c"
        assert result["line"] == 22

    def test_empty_backtrace(self):
        analyzer = RootCauseAnalyzer("/tmp/src")
        frames = analyzer.parse_backtrace("")
        assert frames == []
        func = analyzer.identify_vulnerable_function(frames)
        assert func is None
