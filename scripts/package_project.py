import os
import sys
import zipfile


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    parent_dir = os.path.dirname(project_root)
    zip_name = os.path.basename(project_root) + ".zip"
    zip_path = os.path.join(parent_dir, zip_name)

    excluded = {"__pycache__", ".git", ".idea", ".vscode"}
    excluded_ext = {".pyc", ".o", ".bin"}
    excluded_files = {
        "buffer_overflow", "heap_corruption", "image_parser", "standalone_harness"
    }

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if d not in excluded]
            for fname in files:
                if fname in excluded_files and os.path.dirname(root).endswith("bin"):
                    continue
                if any(fname.endswith(ext) for ext in excluded_ext):
                    continue
                fpath = os.path.join(root, fname)
                arcname = os.path.relpath(fpath, project_root)
                zf.write(fpath, arcname)

    size = os.path.getsize(zip_path)
    print("Packaged {} ({:,} bytes)".format(zip_path, size))


if __name__ == "__main__":
    main()
