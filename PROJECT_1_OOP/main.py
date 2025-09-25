from db.DB_Manager import DatabaseManager
from scan.scanner import PortScanner
import time
from socket import gaierror
# from db import db_save

def main():
    while True:
        try:
            db_name = {
                "host" : "localhost",
                "user" : "root",
                "password" : "admin",
                "database" : "db_network_scanning_system"
            }
            connect_db = DatabaseManager(**db_name)
            connect_db.connect()
            time.sleep(0.5)
            print("==================================")
            print("= WELCOME TO PORT SCANNING TOOLS =")
            print("==================================")
            input1 = int(input("1. Input IP for Scan \n2. Check Open Port Data  \n3. Check Data History\n4. Exit \nInput: "))
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
                        print(f"[!] Scan gagal: tidak bisa resolve host {ip}. Data tidak disimpan.")

            
                            # lanjutkan loop / kembali ke menu
                    else:
                        connect_db.save_result(ip,port_fix,result_total_port)
                except (ValueError,AttributeError) as e:
                    print(f"\nYou have mistake on {e}")
            elif input1 == 2:
                connect_db.check_open_port_data()        
            elif input1 == 3:
                connect_db.Check_History()
            elif input1 == 777:
                try:
                    connect_db.Check_History()
                    print("============================")
                    print("Welcome to Secret Option!!!")
                    print("============================")

                    choose = str(input("What ID do you want delete? \nType:"))
                    connect_db.delete_data(choose)
                except AttributeError as e:
                    print(f"you have mistake on {e}")
            elif input1 == 666:
                try:
                    connect_db.Check_History()
                    print("============================")
                    print("Welcome to Secret Option!!!")
                    print("============================")
                    choose = str(input("What ID do you want update? \nType:"))
                    new_ip = new_ip = str(input("Enter new IP Address: "))
                    connect_db.update_data(choose,new_ip)
                except (AttributeError,UnboundLocalError) as e:
                    print(f"you have mistake on {e}")
            elif input1 == 4:
                DatabaseManager.close(connect_db)
                break
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