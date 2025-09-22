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
        except socket.gaierror:
            if self.verbose:
                print(f"[!] Cannot resolve host: {self.target}")
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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                code = s.connect_ex((self.ip_target, p))  # 0 = sukses (open)
                if code == 0:
                    result.append(p)
                    if self.verbose:
                        print(f"  [+] Port {p} open!\n\n")
                        time.sleep(1)
                else:
                    if self.verbose:
                        print(f"  [-] Port {p} closed!")
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
            print(f"Scan completed in {end - start}")
            print(f"End: {end}")

        return result


# testing
if __name__ == "__main__":
    target = "192.168.68.1"
    ports = [80]
    print(type(ports))
    scanner = PortScanner(target, ports, timeout=0.4, verbose=True)
    hasil = scanner.scan_port()
    # print("Port terbuka:", hasil)
