import os
import shutil
import subprocess
import argparse
from pathlib import Path

import base64_decryptor as b64d
import ping_test
import tls_test
import time
print('''
⠀⠀⠀⢠⣾⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣰⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣄⣀⣀⣤⣤⣶⣾⣿⣿⣿⡷
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⣿⣿⣿⡇⠀⡾⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁⠀⠀⠀⠀⠀
⣿⣿⣿⣧⡀⠁⣀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠉⢹⠉⠙⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⣀⣼⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠀⠤⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⠿⠋⢃⠈⠢⡁⠒⠄⡀⠈⠁⠀⠀{meow meow mf}
⣿⣿⠟⠁⠀⠀⠈⠉⠉⠁⠀⠀⠀⠀⠈⠆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
''')

BASE_DIR = Path("initial_data")
LOCAL_DIR = Path("local")
URLS_FILE = Path("urls.txt")

# ---- args ----
parser = argparse.ArgumentParser()
parser.add_argument(
    "--no-url",
    action="store_true",
    help="Skip downloading URLs, process only local files"
)
args = parser.parse_args()

# ---- reset workspace safely ----
if BASE_DIR.exists():
    print(f"[*] Cleaning existing workspace: {BASE_DIR}")
    shutil.rmtree(BASE_DIR)

BASE_DIR.mkdir(exist_ok=True)

# ---- download files (optional) ----
downloaded_files = 0
if not args.no_url:
    print(f"[*] Downloading URLs from {URLS_FILE}")
    subprocess.run(["wget", "-i", str(URLS_FILE.resolve())], cwd=BASE_DIR, check=False)
    downloaded_files = len(list(BASE_DIR.iterdir()))
else:
    print("[*] --no-url enabled: skipping URL downloads")

# ---- copy local user files ----
copied_files = 0
if LOCAL_DIR.is_dir():
    for file_path in LOCAL_DIR.iterdir():
        if file_path.is_file():
            dst = BASE_DIR / file_path.name
            if dst.exists():
                dst = BASE_DIR / f"local_{file_path.name}"
            shutil.copy2(file_path, dst)
            copied_files += 1
print(f"[*] Copied {copied_files} local files")

# ---- decrypt base64 files ----
decrypted_files = 0
decrypted_lines = {}
print("[*] Decrypting files")
for file_path in BASE_DIR.iterdir():
    if file_path.is_file():
        out_path = file_path.with_suffix(file_path.suffix + ".de")
        b64d.runner(input_file=str(file_path), output_file=str(out_path))
        decrypted_files += 1
        # Count lines in decrypted file
        with open(out_path, "r", errors="ignore") as f:
            decrypted_lines[out_path.name] = sum(1 for _ in f)

for name, lines in decrypted_lines.items():
    print(f"  {name}: {lines} lines after decryption")

# ---- TCP check (nc) ----
alive_files = 0
alive_lines = {}
print("[*] Running TCP checks")
for file_path in BASE_DIR.iterdir():
    if file_path.suffix == ".de":
        alive_path = file_path.with_suffix(file_path.suffix + ".alive")
        subprocess.run(["./nc_test.sh", str(file_path), str(alive_path)], check=False)
        if alive_path.exists():
            alive_files += 1
            with open(alive_path, "r", errors="ignore") as f:
                alive_lines[alive_path.name] = sum(1 for _ in f)

for name, lines in alive_lines.items():
    print(f"  {name}: {lines} lines after TCP check")

# ---- latency filter ----
filtered_files = 0
filtered_lines = {}
print("[*] Filtering by ping latency")
for file_path in BASE_DIR.iterdir():
    if file_path.suffix == ".alive":
        filtered_path = file_path.with_suffix(file_path.suffix + ".filtered")
        ping_test.filter_by_ping(input_file=str(file_path), output_file=str(filtered_path))
        filtered_files += 1
        with open(filtered_path, "r", errors="ignore") as f:
            filtered_lines[filtered_path.name] = sum(1 for _ in f)

for name, lines in filtered_lines.items():
    print(f"  {name}: {lines} lines after ping filter")

# ---- TLS check ----
tls_files = 0
tls_lines = {}
print("[*] Running TLS checks")
for file_path in BASE_DIR.iterdir():
    if file_path.suffix == ".filtered":
        tls_out = file_path.with_suffix(file_path.suffix + ".tls")
        tls_test.tls_runner_threaded(str(file_path), str(tls_out))
        tls_files += 1
        if tls_out.exists():
            with open(tls_out, "r", errors="ignore") as f:
                tls_lines[tls_out.name] = sum(1 for _ in f)


for name, lines in tls_lines.items():
    print(f"  {name}: {lines} lines after TLS check")

# ---- cleanup ----
removed_files = 0
for file_path in BASE_DIR.iterdir():
    if file_path.suffix in [".de", ".txt"]:
        file_path.unlink()
        removed_files += 1
    if file_path.suffix == "tls":
        os.system("awk '{print $NF, $0}' proxy | sort -n | cut -d' ' -f2- > "+f"{file_path}")

# ---- final report ----
print("\n[*] Process completed ✔")
print(f"Downloaded files : {downloaded_files}")
print(f"Copied files     : {copied_files}")
print(f"Decrypted files  : {decrypted_files}")
print(f"TCP alive files  : {alive_files}")
print(f"Filtered files   : {filtered_files}")
print(f"TLS tested files : {tls_files}")
print(f"Removed files    : {removed_files}")
