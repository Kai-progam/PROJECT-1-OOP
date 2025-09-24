import mysql.connector
from mysql.connector import IntegrityError
import time
from tabulate import tabulate
from datetime import datetime
from socket import gaierror
import random
# mapping port yang bakal jadi parameter db

PORT_SERVICE ={
        20: "FTP (data)",
        21: "FTP (control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP (server)",
        68: "DHCP (client)",
        69: "TFTP",
        79: "Finger",
        80: "HTTP",
        88: "Kerberos",
        110: "POP3",
        111: "RPCbind/portmapper",
        119: "NNTP",
        123: "NTP",
        137: "NetBIOS-Name",
        138: "NetBIOS-Datagram",
        139: "NetBIOS-SSN (SMB/NetBIOS)",
        143: "IMAP",
        161: "SNMP",
        179: "BGP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB (Microsoft-DS)",
        512: "rlogin/rsh",
        513: "who/rwho",
        514: "syslog / rsh",
        631: "IPP (printing)",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        465: "SMTPS",
        587: "SMTP (submission)",
    }

VULN_RULES = {
    21: [("Unencrypted FTP", "FTP is running without encryption; credentials and data may be exposed.", "high"),
         ("Anonymous FTP allowed", "Anonymous login permitted on FTP, allowing public file access.", "high")],
    22: [("Weak SSH credentials", "SSH allows password auth and may be subject to brute-force if passwords are weak.", "medium")],
    23: [("Telnet in plaintext", "Telnet transmits credentials in cleartext.", "high")],
    53: [("Open DNS zone transfer", "DNS allows zone transfer (AXFR) exposing domain records.", "high")],
    69: [("TFTP open", "TFTP allows unauthenticated file transfers; device configs may leak.", "high")],
    80: [("Web application issues", "Common web vulnerabilities (XSS/SQLi) may be present on HTTP.", "medium")],
    111: [("RPC/portmapper exposure", "RPC services exposed and can be enumerated.", "medium")],
    123: [("NTP amplification risk", "NTP can be abused for reflective DDoS if not restricted.", "high")],
    137: [("NetBIOS info leak", "NetBIOS exposes host and share info.", "high")],
    139: [("SMB/NetBIOS exposure", "SMB shares might be exposed; high risk on Internet.", "high")],
    161: [("SNMP default community", "SNMP using default community strings can leak config info.", "high")],
    179: [("BGP route compromise", "BGP misconfig can allow route hijacking.", "critical")],
    389: [("LDAP anonymous bind", "LDAP allows anonymous binds that reveal directory info.", "medium")],
    443: [("TLS / Web app risk", "HTTPS may hide web app vulnerabilities or have TLS misconfig.", "medium")],
    445: [("SMB exposed", "SMB exposed to Internet — known to allow remote compromise.", "critical")],
    # add more rules as needed
}

class DatabaseManager():
    def __init__(self,host,user,password,database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database

    def connect(self):
        try:
            print("connecting to database...")
            time.sleep(0.5)
            self.Mydb = mysql.connector.connect(
                host = self.host,
                user = self.user,
                password = self.password,
                database = self.database
            )
            self.cursor  = self.Mydb.cursor()
            print("connection successful")
            time.sleep(0.5)
        except mysql.connector.Error as e:
            print(f"some mistakes on {e}")

    def close(self):
        print("     [~]Saving to the database...")
        time.sleep(0.5)
        if self.cursor:
            self.Mydb.close()
        if self.Mydb:
            self.Mydb.close()
        print("     [+]Save data Success!")
        time.sleep(0.25)

    def save_result(self,target_ip, port, open_ports):
        try:
    
            # insert scans table
            port_scan_id = f"S{random.randint(1,9999)}"
            scan_date = datetime.now()

            cursor = self.Mydb.cursor() #cursor for using database query
            insert_port_scan = "INSERT INTO port_scan(port_scan_id,target_ip,scan_date,total_port,open_port) VALUES (%s,%s,%s,%s,%s)"
            yap = (port_scan_id,target_ip,scan_date,len(port),len(open_ports))
            cursor.execute(insert_port_scan,yap)


            # insert into port_scan_result
            insert_port_scan_result = "INSERT INTO port_scan_result(port_scan_result_id,port_scan_id,port_number,port_status,services_name) VALUES (%s,%s,%s,%s,%s)"
            for p in port:
                port_scan_result_id = f"R{random.randint(1,9999)}"
                port_status = "open" if p in open_ports else "closed"
                service = PORT_SERVICE.get(p, "Unknown")
                
                cursor.execute(insert_port_scan_result,(port_scan_result_id,port_scan_id,p,port_status,service))

            # insert into vulnerabilities
                insert_vulnerabilities = "INSERT INTO vulnerabilities(vuln_id,port_scan_result_id,vulnerability_name,descriptions,severity) VALUES (%s,%s,%s,%s,%s)"
                vuln_id = f"V{random.randint(1,9999)}"
                if port_status == "open" and p in VULN_RULES:
                    rules = VULN_RULES[p]
                    for (vname,vdesc,vsev) in rules:
                        cursor.execute(insert_vulnerabilities, (vuln_id,port_scan_result_id,vname, vdesc, vsev))
                elif port_status == "closed":
                    cursor.execute(insert_vulnerabilities, (vuln_id,port_scan_result_id,"Unknown","Unknown","Unknown"))
                else:
                    print("     [~]Sorry for the Problem...")
                
            # saved into db
            self.Mydb.commit()
            self.close()
            cursor.close()
            print(f"[+] Saved scan {port_scan_id}: total ports = {port} | open ports = {open_ports}")
        except IntegrityError:
            print(f"    [!] Im Sorry This application under developmend")
        except gaierror as e:
            return False

    def check_open_port_data(self):
        select_join = (""" 
    SELECT port_scan.port_scan_id, port_scan.scan_date, port_scan.target_ip, port_scan_result.port_number, port_scan_result.port_status, port_scan_result.services_name, vulnerabilities.vulnerability_name, vulnerabilities.descriptions, vulnerabilities.severity
    FROM port_scan
    JOIN port_scan_result ON port_scan_result.port_scan_id = port_scan.port_scan_id	
    JOIN vulnerabilities ON vulnerabilities.port_scan_result_id = port_scan_result.port_scan_result_id
    WHERE port_scan_result.port_status = "open"; 
                       """)

        self.cursor.execute(select_join)
        items2 =  self.cursor.fetchall()
        if not items2:
            print(" [!] The Database Not Yet Exist")
        headers = ["ID","Scan Date","IP Target","Port Number","Port Status", "Services", "Vulnerability", "Descriptions","Severity"]
        print(tabulate(items2,headers=headers, tablefmt="grid"))   

    def Check_History(self):
        history_join= (""" 
        SELECT port_scan.port_scan_id, port_scan.scan_date, port_scan.target_ip, port_scan_result.port_number, port_scan_result.port_status, port_scan_result.services_name, vulnerabilities.vulnerability_name, vulnerabilities.descriptions, vulnerabilities.severity
        FROM port_scan
        JOIN port_scan_result ON port_scan_result.port_scan_id = port_scan.port_scan_id	
        JOIN vulnerabilities ON vulnerabilities.port_scan_result_id = port_scan_result.port_scan_result_id; 
                       """)
        self.cursor.execute(history_join)
        items3 =  self.cursor.fetchall()   
        if not items3:
            print(" [!] The Database Not Yet Exist")
        headers = ["ID","Scan Date","IP Target","Port Number","Port Status", "Services", "Vulnerability", "Descriptions","Severity"]
        print(tabulate(items3,headers=headers, tablefmt="grid"))        

    
    def delete_data(self,scan_id):
        try:
            vuln_del = """
        DELETE v FROM vulnerabilities v
            JOIN port_scan_result r ON v.port_scan_result_id = r.port_scan_result_id
            WHERE r.port_scan_id = %s
        """
            self.cursor.execute(vuln_del,(scan_id,))
            query_result = "DELETE FROM port_scan_result WHERE port_scan_id = %s"
            self.cursor.execute(query_result, (scan_id,))
            query_scan = "DELETE FROM port_scan WHERE port_scan_id = %s"
            self.cursor.execute(query_scan, (scan_id,))
        
            self.Mydb.commit()
            print(f"    [+] ID {scan_id} Deleted")

        except Exception as e:
            print(f"[!] Error saat menghapus data: {e}")
            self.Mydb.rollback()
        finally:
            self.cursor.close()
            self.Mydb.close()
    def update_data(self,port_scan_id,new_ip):
        try:
            cursor = self.Mydb.cursor()
            query = """
            UPDATE port_scan
            SET target_ip = %s
            WHERE port_scan_id = %s
            """
            cursor.execute(query, (new_ip, port_scan_id))
            self.Mydb.commit()
            print(f"[+] Data {port_scan_id} updated to new IP {new_ip}")
        except Exception as e:
            print(f"[!] Error update: {e}")
        finally:
            cursor.close()


# #  test conn
# # db1 = DatabaseManager("localhost","root","admin","db_network_scanning_system")