import os
import re
import subprocess
import argparse
import shlex


class CrashTriage:

    def __init__(self, crashes_dir):
        self.crashes_dir = os.path.abspath(crashes_dir)

    def discover_crashes(self):
        crashes = []
        if not os.path.isdir(self.crashes_dir):
            return crashes
        for fname in sorted(os.listdir(self.crashes_dir)):
            fpath = os.path.join(self.crashes_dir, fname)
            if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
                crashes.append({"path": fpath, "name": fname, "size": os.path.getsize(fpath)})
        return crashes

    def deduplicate_crashes(self, crashes):
        groups = []
        for crash in crashes:
            bt_info = self._get_addr2line_signature(crash["path"])
            matched = False
            for group in groups:
                if self._backtrace_similarity(group["signature"], bt_info) > 0.5:
                    group["crashes"].append(crash)
                    matched = True
                    break
            if not matched:
                groups.append({"signature": bt_info, "crashes": [crash], "count": 1})
        return groups

    def reproduce_crash(self, crash_file, target_binary):
        try:
            result = subprocess.run(
                [target_binary, crash_file],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return {
                "reproducible": result.returncode != 0,
                "returncode": result.returncode,
                "stderr": result.stderr[:2048],
                "stdout": result.stdout[:2048],
            }
        except subprocess.TimeoutExpired:
            return {"reproducible": False, "returncode": -1, "stderr": "timeout", "stdout": ""}
        except Exception as e:
            return {"reproducible": False, "returncode": -1, "stderr": str(e), "stdout": ""}

    def get_signal_info(self, crash_file, target_binary):
        result = self.reproduce_crash(crash_file, target_binary)
        stderr = result.get("stderr", "")
        signal_info = {"signal": None, "si_code": None, "description": ""}

        seg_match = re.search(r"SIGSEGV.*?(?:address|at)", stderr)
        if seg_match:
            signal_info["signal"] = "SIGSEGV"
            signal_info["description"] = "Segmentation fault"
            return signal_info

        abort_match = re.search(r"SIGABRT", stderr)
        if abort_match:
            signal_info["signal"] = "SIGABRT"
            signal_info["description"] = "Abort (likely heap corruption detected by ASan)"
            return signal_info

        fpe_match = re.search(r"SIGFPE", stderr)
        if fpe_match:
            signal_info["signal"] = "SIGFPE"
            signal_info["description"] = "Floating point exception (division by zero)"
            return signal_info

        if result["returncode"] < 0:
            sig_map = {-6: "SIGABRT", -7: "SIGBUS", -8: "SIGFPE", -11: "SIGSEGV"}
            sig_name = sig_map.get(result["returncode"])
            if sig_name:
                signal_info["signal"] = sig_name
                signal_info["description"] = "Process terminated with " + sig_name

        if result["returncode"] != 0 and not signal_info["signal"]:
            signal_info["signal"] = "UNKNOWN"
            signal_info["description"] = "Non-zero exit code: " + str(result["returncode"])

        return signal_info

    def analyze_with_gdb(self, crash_file, target_binary, source_dir=None):
        gdb_cmds = [
            "set pagination off",
            "set confirm off",
            "file " + shlex.quote(target_binary),
            "run " + shlex.quote(crash_file),
            "bt full",
            "info registers",
            "x/16wx $rsp",
            "info frame",
            "quit",
        ]
        input_text = "\n".join(gdb_cmds) + "\n"
        try:
            result = subprocess.run(
                ["gdb", "-batch", "-nx"],
                input=input_text,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {"backtrace": result.stdout, "gdb_stderr": result.stderr}
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {"backtrace": "", "gdb_stderr": str(e)}

    def generate_gdb_script(self, crash_file, target_binary, output_path=None):
        if output_path is None:
            output_path = os.path.splitext(crash_file)[0] + ".gdb"
        lines = [
            "set pagination off",
            "set confirm off",
            "file " + shlex.quote(target_binary),
            "run " + shlex.quote(crash_file),
            "bt full",
            "info registers",
            "x/16wx $rsp",
            "info frame",
            "quit",
        ]
        with open(output_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        return output_path

    def _get_addr2line_signature(self, crash_file, target_binary=None):
        if target_binary is None:
            return crash_file
        try:
            result = subprocess.run(
                ["addr2line", "-e", target_binary, "-a", "0x00000000"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return crash_file

    def _backtrace_similarity(self, sig1, sig2):
        if sig1 == sig2:
            return 1.0
        words1 = set(sig1.split())
        words2 = set(sig2.split())
        if not words1 or not words2:
            return 0.0
        intersection = words1 & words2
        union = words1 | words2
        return len(intersection) / len(union) if union else 0.0


def main():
    parser = argparse.ArgumentParser(description="Crash Triage Tool")
    parser.add_argument("--crashes-dir", required=True, help="Directory containing crash files")
    parser.add_argument("--target", required=True, help="Target binary path")
    parser.add_argument("--source-dir", default=None, help="Source directory for GDB analysis")
    args = parser.parse_args()

    triage = CrashTriage(args.crashes_dir)
    crashes = triage.discover_crashes()
    print("Discovered {} crash files".format(len(crashes)))

    for c in crashes:
        print("\n--- {} ({} bytes) ---".format(c["name"], c["size"]))
        sig = triage.get_signal_info(c["path"], args.target)
        print("Signal: {} - {}".format(sig["signal"], sig["description"]))
        repro = triage.reproduce_crash(c["path"], args.target)
        print("Reproducible: {}".format(repro["reproducible"]))

    if args.source_dir:
        for c in crashes:
            gdb_out = triage.analyze_with_gdb(c["path"], args.target, args.source_dir)
            if gdb_out["backtrace"]:
                print("\n=== GDB Output for {} ===".format(c["name"]))
                print(gdb_out["backtrace"][:1024])


if __name__ == "__main__":
    main()
