from db.DB_Manager import DatabaseManager
from scan.scanner import PortScanner
from scan.Network_Discovery_ARP_Scan import NetworkDiscovery
import time
from socket import gaierror
from Attack_.DoS import Denial_of_Service

def main():
    while True:
        try:
            db_name = {
                "host" : "localhost",
                "user" : "root",
                "password" : "",
                "database" : "db_network_scanning_system"
            }
            connect_db = DatabaseManager(**db_name)
            connect_db.connect()
            time.sleep(0.5)
            print("==================================")
            print("= WELCOME TO PORT SCANNING TOOLS =")
            print("==================================")
            input1 = int(input("1. Input IP for Scan \n2. Input Network for Scan IP Host \n3. Check Online Host \n4. Check Open Port Data  \n5. Data History \n6. Exit \nInput: "))
            if input1 == 1:
                try:
                    ip = (input("Input IP Adrress: "))
                    port_range1 = int(input("Input first port: "))
                    port_range2 = int(input("Input second port: "))

                    if port_range1 == port_range2:
                        print("     \n[!]Cannot using same port\n")


                    port_fix = list(range(port_range1,port_range2))
                    run = PortScanner(ip,port_fix)
                    result_total_port = run.scan_port()
                    if run.ip_target is None:
                        print(f"[!] Scan Failed: tidak bisa resolve host {ip}. Data tidak disimpan.")

            
                            # lanjutkan loop / kembali ke menu
                    else:
                        connect_db.save_result(ip,port_fix,result_total_port)
                except (ValueError,AttributeError) as e:
                    print(f"\nYou have mistake on {e}")
            elif input1 == 2:
                try:
                    network_address = input("Input Network Address [192.168.2.0/24]\nInput:")
                    run1 = NetworkDiscovery(network_address)
                    result_total_host = run1.arp_scan()
                    for r in result_total_host:
                            r["status"] = "online"
                    if run1.target_network is None:
                        print(f"[!] Scan gagal: tidak bisa resolve host {ip}. Data tidak disimpan.")
                    else:
                        connect_db.save_network_discovery(network_address,result_total_host)
                        
                except (ValueError,AttributeError) as e:
                    print(f"\nYou have mistake on {e}")
            elif input1 == 3:
                connect_db.check_online_host()
            elif input1 == 4:
                connect_db.check_open_port_data()        
            elif input1 == 5:
                connect_db.Check_History()
            elif input1 == 6:
                DatabaseManager.close(connect_db)
                break
            elif input1 == 777:
                try:
                    connect_db.check_open_port_data()
                    print("============================")
                    print("Welcome to Secret Option!!!")
                    print("============================")

                    choose = str(input("What ID do you want delete? \nType:"))
                    connect_db.delete_data(choose)
                except AttributeError as e:
                    print(f"you have mistake on {e}")
            elif input1 == 666:
                try:
                    connect_db.check_open_port_data()
                    print("============================")
                    print("Welcome to Secret Option!!!")
                    print("============================")
                    choose = str(input("What ID do you want update? \nType:"))
                    new_ip = new_ip = str(input("Update Status Port: "))
                    connect_db.update_data(choose,new_ip)
                except (AttributeError,UnboundLocalError) as e:
                    print(f"you have mistake on {e}")

            elif input1 == 623614430:
                print("==============================")
                print("Welcome to DoS Program Option!")
                print("Don't Use for Bad intention!!!")
                print("==============================")
                ip_network = str(input(f"Input IP_Target [127.0.0.1]: "))
                port = int(input(f"Input Port Target [80,22,443]: "))
                threading = int(input(f"Input Threading: "))
                attack = Denial_of_Service(ip_network,port,threading)
                attack.threading()


            else:
                print("     [!]You input wrong number!\n")
            time.sleep(0.5)
        except ValueError as e:
            print(f"    [!]You have problem at {e}\n    [!]please using a number!\n")
        except KeyboardInterrupt:
            print("\nCanceled by user!")
            break
        except gaierror:
            print("     [!]Cannot using wrong IP!")
            break


main()