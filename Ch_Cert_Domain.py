
import socket
import ssl
import base64
import csv
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# ---------- User config ----------
#Change this according to your settings
PROXY_USER = 'speqfgjvpe'
PROXY_PASS = 'OF0X7t4svK0c~xsxqn'
PROXY_HOST = "dc.decodo.com"
PROXY_PORT = 10001


INPUT_PATH  = Path("C:/Users/vagis/OneDrive - Georgia Institute of Technology/Documents/Gtech/Class/RA Work/Web PKI/New folder/2.0/Parts/domains_part11.txt")       #one hostname per line; Change file location accordingly
OUTPUT_PATH = Path("C:/Users/vagis/OneDrive - Georgia Institute of Technology/Documents/Gtech/Class/RA Work/Web PKI/New folder/2.0/Parts/cert_results11.csv")  #CSV table to write; Change file location accordingly
TARGET_PORT = 443
TIMEOUT_SEC = 10.0                       # lower timeout for speed; bump if needeoutl
MAX_WORKERS = 30                         # increase/decrease based on your bandwidth/limits
RETRIES_PER_HOST = 1                     # 0 or 1 retries can help flaky handshakes
# ---------------------------------

CSV_HEADERS = ["host", "subject", "issuer", "valid_from", "valid_until", "sha256", "dns_sans", "error"]
_write_lock = Lock()  # protects file writes across threads

def open_proxy_tunnel(proxy_host: str, proxy_port: int, user: str, pwd: str,
                      target_host: str, target_port: int, timeout: float) -> socket.socket:
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except Exception as e:
        raise RuntimeError(f"TCP connect to proxy failed: {e}")

    try:
        sock.settimeout(timeout)
        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        req = (
            f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            f"Host: {target_host}:{target_port}\r\n"
            f"Proxy-Authorization: Basic {auth}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"User-Agent: simple-cert-probe/1.0\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode())

        # Read until end of headers
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk

        header = resp.split(b"\r\n\r\n", 1)[0].decode(errors="ignore")
        first_line = header.splitlines()[0] if header else ""
        if "200" not in first_line:
            try:
                sock.close()
            except Exception:
                pass
            raise RuntimeError(f"CONNECT failed: {first_line}")
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise

def tls_handshake_over_tunnel(tunneled_sock: socket.socket, server_hostname: str, timeout: float) -> ssl.SSLSocket:
    try:
        ctx = ssl.create_default_context()
    except Exception as e:
        try:
            tunneled_sock.close()
        except Exception:
            pass
        raise RuntimeError(f"Creating SSL context failed: {e}")

    try:
        ssock = ctx.wrap_socket(tunneled_sock, server_hostname=server_hostname)
        ssock.settimeout(timeout)
        ssock.do_handshake()
        return ssock
    except Exception as e:
        try:
            tunneled_sock.close()
        except Exception:
            pass
        raise RuntimeError(f"TLS handshake failed: {e}")

def parse_leaf_cert_from_sslsocket(ssock: ssl.SSLSocket) -> x509.Certificate:
    try:
        der = ssock.getpeercert(binary_form=True)
        if not der:
            raise RuntimeError("Peer did not return a certificate")
        cert = x509.load_der_x509_certificate(der, default_backend())
        return cert
    except Exception as e:
        raise RuntimeError(f"Reading/parsing peer certificate failed: {e}")
    finally:
        try:
            ssock.close()
        except Exception:
            pass

def extract_basic_info(cert: x509.Certificate) -> Tuple[str, str, str, str, str, Optional[str]]:
    try:
        subject = cert.subject.rfc4514_string()
    except Exception:
        subject = ""

    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = ""

    try:
        not_before = cert.not_valid_before_utc.isoformat()
    except Exception:
        try:
            not_before = cert.not_valid_before.isoformat()
        except Exception:
            not_before = ""

    try:
        not_after = cert.not_valid_after_utc.isoformat()
    except Exception:
        try:
            not_after = cert.not_valid_after.isoformat()
        except Exception:
            not_after = ""

    try:
        fp = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fp = ""

    san_str = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_str = ", ".join(san.get_values_for_type(x509.DNSName))
    except Exception:
        san_str = ""

    return subject, issuer, not_before, not_after, fp, san_str

def load_domains(path: Path) -> List[str]:
    hosts: List[str] = []
    try:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                hosts.append(line)
    except Exception as e:
        raise RuntimeError(f"Failed to read input file {path}: {e}")
    return hosts

def probe_one_host_once(host: str) -> Dict[str, str]:
    """
    Single attempt for one host.
    On any error, return a dict with only host and error.
    On success, return full row with error="".
    """
    row = {h: "" for h in CSV_HEADERS}
    row["host"] = host
    try:
        tunnel = open_proxy_tunnel(PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS, host, TARGET_PORT, TIMEOUT_SEC)
    except Exception as e:
        row["error"] = f"CONNECT error: {e}"
        return row

    try:
        ssl_sock = tls_handshake_over_tunnel(tunnel, host, TIMEOUT_SEC)
    except Exception as e:
        row["error"] = f"TLS error: {e}"
        return row

    try:
        cert = parse_leaf_cert_from_sslsocket(ssl_sock)
    except Exception as e:
        row["error"] = f"Cert read error: {e}"
        return row

    try:
        subject, issuer, nb, na, sha256hex, san = extract_basic_info(cert)
        row.update({
            "subject": subject,
            "issuer": issuer,
            "valid_from": nb,
            "valid_until": na,
            "sha256": sha256hex,
            "dns_sans": san,
            "error": ""
        })
    except Exception as e:
        row["error"] = f"Extraction error: {e}"

    return row

def probe_one_host(host: str) -> Dict[str, str]:
    """
    Probe with optional retry for resiliency.
    If both attempts fail, return last error.
    """
    last = None
    try:
        last = probe_one_host_once(host)
        if last.get("error"):
            # optional retry (e.g., transient handshake issues)
            for _ in range(RETRIES_PER_HOST):
                last = probe_one_host_once(host)
                if not last.get("error"):
                    break
        return last
    except Exception as e:
        return {"host": host, "subject": "", "issuer": "", "valid_from": "", "valid_until": "", "sha256": "", "dns_sans": "", "error": f"Unexpected: {e}"}

def append_csv_row(path: Path, row: Dict[str, str], write_header_if_empty: bool = True) -> None:
    """
    Append one row to CSV safely across threads. Flush immediately.
    """
    try:
        with _write_lock:
            file_exists = path.exists() and path.stat().st_size > 0
            with path.open("a", encoding="utf-8", newline="", buffering=1) as f:
                writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
                if write_header_if_empty and not file_exists:
                    writer.writeheader()
                    f.flush()
                writer.writerow(row)
                f.flush()
    except Exception as e:
        # We must not crash the whole run due to a file write; print and continue.
        print(f"[WRITE ERROR] {e}", flush=True)

def main():
    # Prepare output file (truncate at start)
    try:
        with OUTPUT_PATH.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()
            f.flush()
    except Exception as e:
        print(f"Failed to initialize CSV: {e}", flush=True)
        return

    # Load domains
    try:
        domains = load_domains(INPUT_PATH)
    except Exception as e:
        print(e, flush=True)
        return

    if not domains:
        print("No domains to process.", flush=True)
        return

    print(f"Starting with {len(domains)} domains, concurrency={MAX_WORKERS}", flush=True)

    # Launch concurrent probes
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            future_map = {ex.submit(probe_one_host, h): h for h in domains}
            for fut in as_completed(future_map):
                host = future_map[fut]
                try:
                    row = fut.result()
                except Exception as e:
                    row = {h: "" for h in CSV_HEADERS}
                    row["host"] = host
                    row["error"] = f"Fatal worker error: {e}"

                # Print concise status to terminal
                if row.get("error"):
                    print(f"[FAIL] {host} -> {row['error']}", flush=True)
                    # Per your rule: keep only host+error in the CSV row (others blank)
                    minimal = {h: "" for h in CSV_HEADERS}
                    minimal["host"] = host
                    minimal["error"] = row["error"]
                    append_csv_row(OUTPUT_PATH, minimal, write_header_if_empty=False)
                else:
                    print(f"[OK]   {host} -> {row.get('issuer','')}", flush=True)
                    append_csv_row(OUTPUT_PATH, row, write_header_if_empty=False)

    except Exception as e:
        print(f"Executor error: {e}", flush=True)

    print(f"All done. Results in {OUTPUT_PATH}", flush=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Fatal error: {e}", flush=True)
