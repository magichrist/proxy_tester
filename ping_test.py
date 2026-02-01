import subprocess
import re
from threading import Thread, Lock
from queue import Queue
from typing import Optional
from Config import *
HOST_RE = re.compile(r'@([^:/?]+)')


def extract_host(line: str) -> Optional[str]:
    m = HOST_RE.search(line)
    return m.group(1) if m else None


def ping_host(
    host: str,
    ping_count: int,
    ping_timeout: int,
) -> Optional[float]:
    try:
        proc = subprocess.run(
            ["ping", "-c", str(ping_count), "-W", str(ping_timeout), host],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if proc.returncode != 0:
            return None

        for line in proc.stdout.splitlines():
            if "avg" in line or "round-trip" in line:
                return float(line.split("/")[4])
    except Exception:
        return None

    return None


def filter_by_ping(
    input_file: str,
    output_file: str,
    max_ping_ms: int = PING_MAX_TIME_MS,
    ping_count: int = PING_COUNT,
    ping_timeout: int = PING_TIMEOUT,
    max_threads: int = PING_THREADS,
) -> None:
    """
    Read URLs from input_file, ping hosts concurrently,
    write accepted lines to output_file.
    """

    queue: Queue[str] = Queue()
    lock = Lock()

    # Clear output file
    open(output_file, "w").close()

    def worker():
        while True:
            item = queue.get()
            if item is None:
                break

            line = item.strip()
            host = extract_host(line)

            if not host:
                queue.task_done()
                continue

            avg_ping = ping_host(host, ping_count, ping_timeout)

            if avg_ping is None:
                print(f"✖ unreachable {host}")
            elif avg_ping <= max_ping_ms:
                print(f"✔ {host} {avg_ping:.1f} ms")
                with lock:
                    with open(output_file, "a", encoding="utf-8") as fout:
                        fout.write(line + "\n")
            else:
                print(f"✖ {host} {avg_ping:.1f} ms (too slow)")

            queue.task_done()

    # Start workers
    threads = []
    for _ in range(max_threads):
        t = Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    # Feed queue
    with open(input_file, "r", encoding="utf-8") as fin:
        for line in fin:
            queue.put(line)

    queue.join()

    # Stop workers
    for _ in threads:
        queue.put(None)
    for t in threads:
        t.join()
