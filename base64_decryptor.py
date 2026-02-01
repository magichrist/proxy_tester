import base64
import re


def is_base64(s: str) -> bool:
    s = s.strip()
    if len(s) < 8:
        return False
    if not re.fullmatch(r'[A-Za-z0-9+/=]+', s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def runner(input_file, output_file):
    with open(input_file, "r", encoding="utf-8", errors="ignore") as fin, \
            open(output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.rstrip("\n")
            if is_base64(line):
                try:
                    decoded = base64.b64decode(line).decode("utf-8", errors="ignore")
                    fout.write(decoded + "\n")
                except Exception:
                    fout.write(line + "\n")
            else:
                fout.write(line + "\n")
