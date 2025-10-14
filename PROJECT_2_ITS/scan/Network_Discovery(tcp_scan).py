# import socket
# import ipaddress
# from datetime import datetime
# from concurrent.futures import ThreadPoolExecutor, as_completed

# class NetworkDiscovery:
#     def __init__(self, target_network):
#         self.target_network = target_network

#     def probe_host(self, ip, ports=[22, 80, 443], timeout=0.5):
#         """
#         Mengecek apakah 1 host online dengan mencoba koneksi ke beberapa port umum.
#         """
#         online = False
#         for p in ports:
#             try:
#                 s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 s.settimeout(timeout)
#                 code = s.connect_ex((ip, p))   
#                 s.close()
#                 if code == 0:
#                     online = True
#                     break
#             except Exception:
#                 pass

#         try:
#             hostname = socket.gethostbyaddr(ip)[0]
#         except Exception:
#             hostname = None

#         return {
#             "ip_address": ip,
#             "mac_address": None,
#             "hostname": hostname,
#             "status": "online" if online else "offline",
#             "last_seen": datetime.now()
#         }

#     def scan_network(self, ports=[22, 80, 443], timeout=0.5, max_workers=200):
#         """
#         Memindai seluruh host dalam subnet target_network untuk melihat siapa yang aktif.
#         """
#         network = ipaddress.ip_network(self.target_network, strict=False)
#         hosts = [str(ip) for ip in network.hosts()]

#         print(f"[~] Scanning {len(hosts)} hosts in {self.target_network} ...")
#         data = []

#         with ThreadPoolExecutor(max_workers=max_workers) as executor:
#             futures = {executor.submit(self.probe_host, ip, ports, timeout): ip for ip in hosts}
#             for fut in as_completed(futures):
#                 result = fut.result()
#                 data.append(result)
#                 if result["status"] == "online":
#                     print(f"    [+] {result['ip_address']} ONLINE ({result['hostname'] or 'no-hostname'})")

#         print(f"[*] Scan selesai. {len([r for r in data if r['status']=='online'])} host online ditemukan.")
#         return data


# # Test program
# if __name__ == "__main__":
#     tes = NetworkDiscovery("192.168.1.0/24")
#     hasil = tes.scan_network()
