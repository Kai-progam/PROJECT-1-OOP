# threaded_portscanner.py
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Tuple, Optional

class ThreadedPortScanner:
    def __init__(self, target: str, ports: Iterable[int], timeout: float = 0.6, max_workers: int = 50, verbose: bool = True):
        self.target = target
        self.ports = list(ports)
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.ip = None

    def _resolve(self) -> Optional[str]:
        try:
            self.ip = socket.gethostbyname(self.target)
            return self.ip
        except socket.gaierror:
            if self.verbose:
                print(f"[!] Tidak bisa resolve host: {self.target}")
            return None

    def _scan_port(self, port: int) -> Tuple[int, bool, Optional[str]]:
        try:
            with socket.create_connection((self.ip, port), timeout=self.timeout) as s:
                s.settimeout(0.5)
                banner = None
                try:
                    b = s.recv(1024)
                    if b:
                        banner = b.decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    pass
                return port, True, banner
        except Exception:
            return port, False, None

    def scan(self) -> List[Tuple[int, bool, Optional[str]]]:
        if not self._resolve():
            return []
        results = []
        if self.verbose:
            print(f"Scanning {self.target} ({self.ip}) with {self.max_workers} workers")
            start = datetime.now()

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self._scan_port, p): p for p in self.ports}
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                if self.verbose:
                    port, is_open, _ = res
                    if is_open:
                        print(f"  [+] {port} open")
        if self.verbose:
            end = datetime.now()
            print(f"Scan selesai dalam {end - start}")
        return results

if __name__ == "__main__":
    ports = range(1, 1025)  # contoh scan well-known range
    s = ThreadedPortScanner("127.0.0.1", ports, timeout=0.4, max_workers=200, verbose=True)
    out = s.scan()
    opens = [p for p, open_, _ in out if open_]
    print("Open ports:", opens)
