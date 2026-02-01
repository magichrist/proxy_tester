import socket
import ssl
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from Config import TLS_TIMEOUT, TLS_THREADS


def parse_vless_host_port_sni(link: str):
    """Extract host, port, and SNI from a VLESS link."""
    u = urlparse(link)
    q = parse_qs(u.query)
    host = u.hostname
    port = u.port or 443
    sni = q.get("sni", [host])[0]  # fallback to host if no SNI
    return host, port, sni


def tls_alive(host: str, port: int, sni: str = None, timeout: int = TLS_TIMEOUT) -> bool:
    """Check if TLS handshake succeeds."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host):
                return True
    except Exception:
        return False


def check_link(link: str):
    """Thread target: test one link and return result tuple."""
    link = link.strip()
    if not link:
        return None
    try:
        host, port, sni = parse_vless_host_port_sni(link)
        if tls_alive(host, port, sni):
            return (link, True, host, port, sni)
        else:
            return (link, False, host, port, sni)
    except Exception:
        return (link, False, None, None, None)


def tls_runner_threaded(input_file: str, output_file: str, max_workers: int = TLS_THREADS):
    """Threaded TLS scanner: reads links line by line, tests them, writes working ones."""
    working_count = 0
    with open(output_file, 'w') as out_file, ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        with open(input_file, 'r') as in_file:
            for line in in_file:
                futures.append(executor.submit(check_link, line))

        for future in as_completed(futures):
            result = future.result()
            if not result:
                continue
            link, success, host, port, sni = result
            if success:
                print(f"[✅] TLS handshake succeeded: {host}:{port} (SNI={sni})")
                out_file.write(link + "\n")
                working_count += 1
            else:
                if host and port:
                    print(f"[❌] TLS handshake failed: {host}:{port} (SNI={sni})")
                else:
                    print(f"[⚠️] Error testing link: {link}")

    print(f"\n[ℹ️] Saved {working_count} working links to {output_file}")

# Example usage:
# tls_runner_threaded("vless_links.txt", "working_links.txt", max_workers=50)
