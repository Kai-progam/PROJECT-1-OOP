import socket
from datetime import datetime
import time

class PortScanner:
    def __init__(self, target, ports, timeout=0.5, verbose=True):
        self.target = target
        self.ports = list(ports)
        self.timeout = timeout
        self.verbose = verbose
        self.ip_target = None

    def _resolve(self):
        try:
            self.ip_target = socket.gethostbyname(self.target)
            return True
        except socket.gaierror as e:
            if self.verbose:
                print(f"[!] Cannot resolve host: {self.target} [error at:{e}]")
            self.target = None
            return False
        

    def scan_port(self):
        result = []

        if not self._resolve():
            return result

        if self.verbose:
            print(f"Scanning {self.target} ({self.ip_target})")
            start = datetime.now()
            print(f"Start: {start}")

        for p in self.ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET = ipv4 | SOCK_STREAM = TCP
                s.settimeout(self.timeout)
                code = s.connect_ex((self.ip_target,p))
                latency = (datetime.now() - start).total_seconds() * 1000.0
                if code == 0:
                    result.append(p)
                    if self.verbose:
                        print(f"    [+]Port {p} is open! (latency = {latency:.1f} ms)")
                    else:
                        print(f"    [-]Port {p} Closed!")
            except KeyboardInterrupt:
                print("\n[!] Dibatalkan oleh user")
                break
            except Exception as e:
                if self.verbose:
                    print(f"  [!] Error cek port {p}: {e}")
            finally:
                s.close()

        if self.verbose:
            end = datetime.now()
            print(f"Scan Completed  in {end-start}")
            print(f"end: {end}")

        return result
    
            
# Testing
# tes = PortScanner("127.0.0.1",[80,81])
# tes.scan_port()
