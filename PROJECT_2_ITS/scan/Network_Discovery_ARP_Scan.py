from scapy.all import ARP, Ether, srp, conf
from datetime import datetime
import ipaddress

class NetworkDiscovery:
    def __init__(self, target_network,timeout=2,verbose = True):
        self.target_network = target_network
        self.timeout = timeout
        self.verbose = verbose

    def resolve(self):
        try:
            ipaddress.ip_network(self.target_network)
            return True
        except (ipaddress.AddressValueError,ipaddress.NetmaskValueError):
            if self.verbose:
                print(f"[!] Cannot resolve netowork: {self.target_network}")
            self.target = None
            return False
        

    def arp_scan(self):
        results = []

        if not self.resolve():
            return results
        conf.verb = 0
        pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_network)
        ans, _ =   ans, _ = srp(pkt, timeout=self.timeout)
        
        for sent, recv in ans:
            ip = recv.psrc
            mac = recv.hwsrc
            date = datetime.utcnow()
            results.append({
                "ip": ip,
                "mac": mac,
                "last_seen": date
            })
            if self.verbose:
                print(f"[+] {ip} - {mac} - {date}")
                print(f"found {len(results)} host!")
        

        # for i,ip1 in enumerate(results):
        #     print(f"{i +1}. {ip1["ip"]}---{ip1["mac"]}---{ip1["last_seen"]}") cek isi results(tidak wajib hanya pengecekan)
            # print(i,ip1)
            
        return results
    


# cidr = input("CIDR to sweep (e.g. 192.168.1.0/24): ").strip()
# print("Run as root/Administrator for ARP scan")
# got = NetworkDiscovery(cidr)
# len_ = got.arp_scan()
# print(f"Found {len(len_)} hosts")