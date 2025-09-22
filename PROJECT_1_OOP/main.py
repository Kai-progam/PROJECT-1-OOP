from db.DB_Manager import DatabaseManager
from scan.scanner import PortScanner
import time
import re
from db import db_save
import socket

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
            print("----------------------")
            input1 = int(input("WELCOME TO PORT SCANNING TOOLS \n1. Input IP for Scan \n2. Check Last Scan  \n3. Check Data History  \n4.Exit \nInput: "))
            if input1 == 1:
                try:
                    ip = (input("Input IP Adrress: "))
                    port_range1 = int(input("Input first port: "))
                    port_range2 = int(input("Input second port: "))
                    port_fix = list(range(port_range1,port_range2))
                    if port_range1 == port_range2:
                        print("     \n[!]Cannot using same port")
                    elif port_range1 != port_range2:
                        run = PortScanner(ip,port_fix)
                        result_total_port = run.scan_port()
                        db_save.save_result(ip,port_fix,result_total_port)


                    else:
                        print("     [!] Something wrong in here")
                except (ValueError,AttributeError) as e:
                    print(f"\nYou have mistake on {e}")
            elif input1 == 2:
                continue
            elif input1 == 3:
                continue
            elif input1 == 4:
                DatabaseManager.close(connect_db)
                break
            else:
                print("You input wrong number")
            print("----------------------")
            time.sleep(0.5)
        except ValueError as e:
            print(f"You have problem at{e}")
        except KeyboardInterrupt:
            print("\nCanceled by user!")
            break


main()