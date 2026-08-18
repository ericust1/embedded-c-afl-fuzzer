import os
import re
import subprocess
import argparse
import datetime


class RootCauseAnalyzer:

    def __init__(self, source_dir):
        self.source_dir = os.path.abspath(source_dir) if source_dir else None

    def parse_backtrace(self, bt_text):
        frames = []
        lines = bt_text.split("\n")
        frame_re = re.compile(r"^#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s*(?:\((.*)\))?\s*(?:at\s+(\S+):(\d+))?")
        for line in lines:
            m = frame_re.search(line)
            if m:
                frame = {
                    "number": int(m.group(1)),
                    "address": m.group(2),
                    "function": m.group(3),
                    "args": m.group(4) or "",
                    "file": m.group(5) or "",
                    "line": int(m.group(6)) if m.group(6) else 0,
                }
                frames.append(frame)
        if not frames:
            alt_re = re.compile(r"^#(\d+)")
            for line in lines:
                m = alt_re.match(line.strip())
                if m:
                    frames.append({
                        "number": int(m.group(1)),
                        "address": "",
                        "function": line.strip(),
                        "args": "",
                        "file": "",
                        "line": 0,
                    })
        return frames

    def identify_vulnerable_function(self, frames):
        if not frames:
            return None
        if len(frames) >= 1:
            return frames[0]["function"]
        return None

    def locate_source_line(self, frame, source_dir=None):
        sd = source_dir or self.source_dir
        if not sd or not frame.get("address"):
            if frame.get("file") and frame.get("line"):
                return {"file": frame["file"], "line": frame["line"]}
            return None
        return None

    def classify_vulnerability(self, function_name, backtrace, crash_type):
        bt_lower = backtrace.lower() if backtrace else ""
        fn_lower = (function_name or "").lower()

        heap_indicators = ["malloc", "free", "realloc", "calloc", "heap", "alloc"]
        overflow_indicators = ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "gets", "read", "recv", "overflow", "buffer"]
        uaf_indicators = ["free", "use-after-free", "freed", "double-free", "double free"]
        null_indicators = ["null", "nil", "(nil)", "0x0 ", "0x0)", "dereference"]
        int_overflow_indicators = ["integer overflow", "truncation", "wrap", "unsigned", "multiply"]
        stack_indicators = ["stack", "$rsp", "$rbp", "canary", "stack smashing"]

        scores = {
            "buffer overflow": 0,
            "heap corruption": 0,
            "use-after-free": 0,
            "null dereference": 0,
            "integer overflow": 0,
            "stack overflow": 0,
        }

        if "memcpy" in fn_lower or "memcpy" in bt_lower:
            scores["buffer overflow"] += 3
        if "strcpy" in bt_lower or "strcat" in bt_lower:
            scores["buffer overflow"] += 3
        if "buffer" in bt_lower:
            scores["buffer overflow"] += 1
        if "overflow" in bt_lower:
            scores["buffer overflow"] += 2
            scores["integer overflow"] += 2
        if "heap-buffer-overflow" in bt_lower or "heap overflow" in bt_lower:
            scores["heap corruption"] += 4
        if "heap-use-after-free" in bt_lower or "use-after-free" in bt_lower:
            scores["use-after-free"] += 4
        if "double-free" in bt_lower or "double free" in bt_lower:
            scores["use-after-free"] += 3
            scores["heap corruption"] += 2
        if "alloc" in bt_lower and ("free" in bt_lower):
            scores["heap corruption"] += 2
        if crash_type == "SIGSEGV":
            if "null" in bt_lower or " 0x0 " in bt_lower or "0x0)" in bt_lower or "0x0," in bt_lower:
                scores["null dereference"] += 3
            else:
                scores["buffer overflow"] += 1
                scores["heap corruption"] += 1
        if crash_type == "SIGABRT":
            scores["heap corruption"] += 2
            scores["buffer overflow"] += 1
        if crash_type == "SIGFPE":
            scores["integer overflow"] += 4
        if "stack" in bt_lower or "stack" in fn_lower:
            scores["stack overflow"] += 2
        if "recursive" in bt_lower:
            scores["stack overflow"] += 3
        if "width" in fn_lower or "height" in fn_lower or "pixel" in fn_lower or "image" in fn_lower:
            scores["integer overflow"] += 3
        if "multiply" in bt_lower or "*" in fn_lower:
            scores["integer overflow"] += 1

        max_score = 0
        vuln_type = "unknown"
        for vtype, score in scores.items():
            if score > max_score:
                max_score = score
                vuln_type = vtype
        return vuln_type

    def generate_analysis_report(self, crash_info, output_path):
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        lines = []
        lines.append("# Root Cause Analysis Report")
        lines.append("")
        lines.append("Generated: {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        lines.append("")

        lines.append("## Crash Summary")
        lines.append("")
        lines.append("- **Crash File**: {}".format(crash_info.get("crash_file", "N/A")))
        lines.append("- **Target Binary**: {}".format(crash_info.get("target_binary", "N/A")))
        lines.append("- **Signal**: {}".format(crash_info.get("signal", "N/A")))
        lines.append("- **Vulnerable Function**: {}".format(crash_info.get("vulnerable_function", "N/A")))
        lines.append("- **Vulnerability Type**: {}".format(crash_info.get("vulnerability_type", "N/A")))
        lines.append("- **Severity**: {}".format(crash_info.get("severity", "N/A")))
        lines.append("")

        lines.append("## Backtrace")
        lines.append("")
        lines.append("```")
        lines.append(crash_info.get("backtrace", "No backtrace available."))
        lines.append("```")
        lines.append("")

        lines.append("## Source Context")
        lines.append("")
        src_ctx = crash_info.get("source_context", "")
        if src_ctx:
            lines.append("```")
            lines.append(src_ctx)
            lines.append("```")
        else:
            lines.append("No source context available.")
        lines.append("")

        lines.append("## Vulnerability Classification")
        lines.append("")
        lines.append("- **Type**: {}".format(crash_info.get("vulnerability_type", "unknown")))
        lines.append("- **Severity**: {}".format(crash_info.get("severity", "medium")))
        lines.append("- **CWE**: {}".format(crash_info.get("cwe", "N/A")))
        lines.append("")

        lines.append("## Fix Recommendation")
        lines.append("")
        rec = crash_info.get("recommendation", "Review the vulnerable function and add proper bounds checking.")
        lines.append(rec)
        lines.append("")

        report = "\n".join(lines)
        with open(output_path, "w") as f:
            f.write(report)
        return output_path


def _get_source_context(self, file_path, line_num, context_lines=3):
    if not self.source_dir or not file_path or line_num <= 0:
        return ""
    full_path = os.path.join(self.source_dir, file_path)
    if not os.path.exists(full_path):
        return ""
    try:
        with open(full_path, "r") as f:
            all_lines = f.readlines()
        start = max(0, line_num - context_lines - 1)
        end = min(len(all_lines), line_num + context_lines)
        result = []
        for i in range(start, end):
            marker = " >" if i + 1 == line_num else "  "
            result.append("{} {:>4d} | {}".format(marker, i + 1, all_lines[i].rstrip()))
        return "\n".join(result)
    except Exception:
        return ""


def main():
    parser = argparse.ArgumentParser(description="Root Cause Analyzer")
    parser.add_argument("--source-dir", required=True, help="Path to source code directory")
    parser.add_argument("--crash-file", help="Path to crash input file")
    parser.add_argument("--backtrace-file", help="File containing GDB backtrace")
    parser.add_argument("--output", default="analysis_report.md", help="Output report path")
    parser.add_argument("--signal", default="SIGSEGV", help="Crash signal type")
    args = parser.parse_args()

    analyzer = RootCauseAnalyzer(args.source_dir)

    bt_text = ""
    if args.backtrace_file and os.path.exists(args.backtrace_file):
        with open(args.backtrace_file, "r") as f:
            bt_text = f.read()

    frames = analyzer.parse_backtrace(bt_text)
    vuln_func = analyzer.identify_vulnerable_function(frames)
    vuln_type = analyzer.classify_vulnerability(vuln_func, bt_text, args.signal)

    severity_map = {
        "buffer overflow": "critical",
        "heap corruption": "critical",
        "use-after-free": "high",
        "null dereference": "medium",
        "integer overflow": "high",
        "stack overflow": "high",
        "unknown": "medium",
    }
    cwe_map = {
        "buffer overflow": "CWE-120 (Buffer Copy without Checking Size of Input)",
        "heap corruption": "CWE-122 (Heap-based Buffer Overflow)",
        "use-after-free": "CWE-416 (Use After Free)",
        "null dereference": "CWE-476 (NULL Pointer Dereference)",
        "integer overflow": "CWE-190 (Integer Overflow or Wraparound)",
        "stack overflow": "CWE-121 (Stack-based Buffer Overflow)",
        "unknown": "N/A",
    }
    rec_map = {
        "buffer overflow": "Add explicit bounds checking before memcpy/strcpy operations. Ensure the length field from untrusted input is validated against the destination buffer size.",
        "heap corruption": "Validate all size fields from untrusted input before heap allocation. Ensure no writes exceed the allocated buffer size.",
        "use-after-free": "Set pointers to NULL immediately after free. Implement reference counting or use memory-safe patterns.",
        "null dereference": "Add NULL checks after memory allocation (malloc, calloc) and before pointer dereference.",
        "integer overflow": "Use safe integer arithmetic. Check for overflow before multiplication operations, especially with user-controlled dimensions.",
        "stack overflow": "Reduce stack allocation sizes, use heap allocation for large buffers, or increase recursion limits.",
        "unknown": "Perform manual analysis with GDB and inspect register state at crash point.",
    }

    crash_info = {
        "crash_file": args.crash_file or "N/A",
        "target_binary": "N/A",
        "signal": args.signal,
        "vulnerable_function": vuln_func or "N/A",
        "vulnerability_type": vuln_type,
        "severity": severity_map.get(vuln_type, "medium"),
        "cwe": cwe_map.get(vuln_type, "N/A"),
        "backtrace": bt_text or "No backtrace provided.",
        "source_context": "",
        "recommendation": rec_map.get(vuln_type, "Review the crash and add proper validation."),
    }

    if frames:
        top_frame = frames[0]
        ctx = _get_source_context(analyzer, top_frame.get("file", ""), top_frame.get("line", 0))
        crash_info["source_context"] = ctx

    analyzer.generate_analysis_report(crash_info, args.output)
    print("Report written to {}".format(args.output))


if __name__ == "__main__":
    main()
