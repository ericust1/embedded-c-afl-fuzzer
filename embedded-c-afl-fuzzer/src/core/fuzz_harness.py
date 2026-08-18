import os
import subprocess
import time
import argparse
import shlex


class FuzzHarness:

    def __init__(self, target_binary, input_dir, output_dir):
        self.target_binary = os.path.abspath(target_binary)
        self.input_dir = os.path.abspath(input_dir)
        self.output_dir = os.path.abspath(output_dir)
        self.mode = "AFL_INSTRUMENTED"
        self._process = None

    def create_harness(self, template_type="standalone", output_path=None):
        if template_type == "standalone":
            code = (
                '#include <stdio.h>\n'
                '#include <stdlib.h>\n'
                '#include <string.h>\n'
                '#include <unistd.h>\n'
                '\n'
                '#define MAX_INPUT 8192\n'
                '\n'
                'extern int parse_protocol_message(const unsigned char *buf, size_t buf_len);\n'
                'extern int process_records(const unsigned char *buf, size_t buf_len);\n'
                'extern int parse_image(const unsigned char *buf, size_t buf_len);\n'
                '\n'
                'static unsigned char input_buf[MAX_INPUT];\n'
                '\n'
                'int main(int argc, char **argv) {\n'
                '    ssize_t n;\n'
                '    FILE *f;\n'
                '    if (argc > 1) {\n'
                '        f = fopen(argv[1], "rb");\n'
                '        if (!f) return 1;\n'
                '        n = fread(input_buf, 1, MAX_INPUT, f);\n'
                '        fclose(f);\n'
                '    } else {\n'
                '        n = read(STDIN_FILENO, input_buf, MAX_INPUT);\n'
                '        if (n < 0) return 1;\n'
                '    }\n'
                '    parse_protocol_message(input_buf, (size_t)n);\n'
                '    process_records(input_buf, (size_t)n);\n'
                '    parse_image(input_buf, (size_t)n);\n'
                '    return 0;\n'
                '}\n'
            )
        else:
            code = (
                '#include <stdio.h>\n'
                '#include <stdlib.h>\n'
                '#include <unistd.h>\n'
                '\n'
                '__AFL_FUZZ_INIT();\n'
                '\n'
                'int main(void) {\n'
                '    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;\n'
                '    while (__AFL_LOOP(10000)) {\n'
                '        int len = __AFL_FUZZ_TESTCASE_LEN;\n'
                '        extern int parse_protocol_message(const unsigned char *, size_t);\n'
                '        parse_protocol_message(buf, len);\n'
                '    }\n'
                '    return 0;\n'
                '}\n'
            )

        if output_path is None:
            output_path = os.path.join(os.path.dirname(self.target_binary), "harness.c")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write(code)
        return output_path

    def build_target(self, source_file, harness_file, compiler="afl-gcc"):
        cmd = [
            compiler, "-O2", "-g", "-o", self.target_binary,
            source_file, harness_file
        ]
        if "afl" in compiler:
            self.mode = "AFL_INSTRUMENTED"
        else:
            self.mode = "standalone"
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError("Build failed: " + result.stderr)
        return self.target_binary

    def run_fuzzer(self, timeout_seconds=3600, max_total_time=36000):
        if self.mode != "AFL_INSTRUMENTED":
            raise RuntimeError("Target must be compiled with AFL instrumentation")
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.input_dir, exist_ok=True)
        cmd = [
            "afl-fuzz",
            "-i", self.input_dir,
            "-o", self.output_dir,
            "-m", "none",
            "-t", "1000",
            "-V", str(max_total_time),
            "--", self.target_binary
        ]
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return self._process

    def get_stats(self):
        stats_file = os.path.join(self.output_dir, "fuzzer_stats")
        if not os.path.exists(stats_file):
            return None
        stats = {}
        with open(stats_file, "r") as f:
            for line in f:
                line = line.strip()
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                stats[key.strip()] = val.strip()
        result = {
            "execs_per_sec": stats.get("execs_per_sec", "0"),
            "paths_total": stats.get("paths_total", "0"),
            "unique_crashes": stats.get("unique_crashes", "0"),
            "unique_hangs": stats.get("unique_hangs", "0"),
        }
        for k in result:
            result[k] = int(result[k].replace(",", "")) if result[k].replace(",", "").isdigit() else 0
        return result

    def monitor_fuzzer(self, interval=30):
        while self._process and self._process.poll() is None:
            stats = self.get_stats()
            if stats:
                print(
                    "[{}] execs/sec={} paths={} crashes={} hangs={}".format(
                        time.strftime("%H:%M:%S"),
                        stats["execs_per_sec"],
                        stats["paths_total"],
                        stats["unique_crashes"],
                        stats["unique_hangs"],
                    )
                )
            time.sleep(interval)
        return self.get_stats()


def main():
    parser = argparse.ArgumentParser(description="AFL Fuzz Harness Manager")
    parser.add_argument("--target", required=True, help="Path to target binary")
    parser.add_argument("--input", required=True, help="Input corpus directory")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--timeout", type=int, default=3600, help="Fuzzer timeout in seconds")
    parser.add_argument("--max-time", type=int, default=36000, help="Max total fuzz time")
    parser.add_argument("--monitor-interval", type=int, default=30, help="Stats polling interval")
    args = parser.parse_args()

    harness = FuzzHarness(args.target, args.input, args.output)
    proc = harness.run_fuzzer(timeout_seconds=args.timeout, max_total_time=args.max_time)
    harness.monitor_fuzzer(interval=args.monitor_interval)


if __name__ == "__main__":
    main()
