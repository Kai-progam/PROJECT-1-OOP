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
    20: [("Plaintext FTP data", "FTP data channel transmits files without encryption; sensitive files can be intercepted.", "high")],
    21: [("Unencrypted FTP control", "FTP control channel commonly allows plaintext authentication and anonymous login.", "high"),
         ("Anonymous FTP allowed", "Anonymous login permitted on FTP, enabling public file upload/download.", "high")],
    22: [("Weak SSH credentials", "SSH allowing password auth with weak/default passwords may be brute-forced.", "medium"),
         ("Deprecated SSH protocol v1", "SSH server supports protocol v1 which is insecure.", "high")],
    23: [("Telnet plaintext credentials", "Telnet transmits credentials in cleartext; should be disabled in favor of SSH.", "high")],
    25: [("Open SMTP relay", "Misconfigured SMTP may accept and forward mail from unauthorized sources.", "high"),
         ("No STARTTLS", "SMTP without STARTTLS exposes credentials and messages in plaintext.", "medium")],
    53: [("Open DNS zone transfer", "DNS allows AXFR zone transfer exposing domain records.", "high"),
         ("Recursive DNS for any", "Recursive resolver open to the internet can be abused for DNS amplification.", "high")],
    67: [("Rogue DHCP risk", "Rogue DHCP server on local network can redirect clients to malicious gateways/DNS.", "high")],
    68: [("DHCP client issue", "Client-side DHCP misconfiguration may accept malicious offers; check DHCP server behaviour.", "medium")],
    69: [("TFTP unauthenticated transfer", "TFTP allows unauthenticated GET/PUT; device configs or binaries may leak.", "high")],
    79: [("Finger information disclosure", "Finger may expose user information on older/unpatched systems.", "low")],
    80: [("Web application vulnerabilities", "HTTP services commonly expose XSS, SQLi, directory listing, or default pages.", "medium"),
         ("Directory listing / default page", "Web server exposes directory listing or default 'welcome' pages.", "low")],
    88: [("Kerberos misconfiguration", "Kerberos service misconfiguration or clock skew may allow authentication issues.", "high")],
    110: [("POP3 plaintext auth", "POP3 without TLS transmits credentials in cleartext.", "medium")],
    111: [("RPCbind/portmapper exposure", "Portmapper/RPCbind can reveal RPC services and allow further enumeration.", "medium")],
    119: [("NNTP open posting or relay", "NNTP servers may allow unauthenticated posting or information leakage.", "low")],
    123: [("NTP amplification risk", "Unrestricted NTP servers can be abused for DDoS amplification (monlist).", "high")],
    137: [("NetBIOS name/service leak", "NetBIOS may reveal hostnames/shares and facilitate enumeration.", "high")],
    138: [("NetBIOS datagram info leak", "NetBIOS datagram can leak host/service info over UDP.", "high")],
    139: [("SMB over NetBIOS exposure", "SMB shares or null sessions may be exposed; risk of info leak or RCE on vulnerable versions.", "high")],
    143: [("IMAP plaintext auth", "IMAP without TLS can expose credentials and mail content.", "medium")],
    161: [("SNMP default community strings", "SNMP using default community strings (public/private) can reveal device configs.", "high"),
          ("SNMP write access", "SNMP with write privileges can allow configuration changes.", "critical")],
    179: [("BGP misconfiguration / hijack risk", "BGP that accepts unfiltered prefixes or lacks authentication can facilitate route hijacking.", "critical")],
    194: [("IRC abuse / info leak", "Public IRC servers may be used for abuse or leak info via channels.", "low")],
    389: [("LDAP anonymous bind", "LDAP allowing anonymous bind can expose directory information.", "medium"),
          ("LDAP injection / misconfig", "Improper input handling or misconfig can expose sensitive directory entries.", "high")],
    443: [("TLS configuration issues", "Weak ciphers, expired/invalid certs, or missing HSTS reduce TLS effectiveness.", "medium"),
          ("Web application vulnerabilities over HTTPS", "Application-layer vulns (XSS, SQLi) still applicable over TLS.", "medium")],
    445: [("SMB exposed to Internet", "SMB exposed publicly can allow credential theft, share access, or RCE on vulnerable versions.", "critical")],
    512: [("rlogin/rsh legacy access", "rlogin/rsh allow unauthenticated or weakly authenticated remote execution (legacy).", "high")],
    513: [("who/rwho info disclosure", "Legacy who/rwho services may leak user/host information.", "low")],
    514: [("syslog/rsh insecure service", "Legacy services listening on 514 may accept unauthenticated input or remote shells.", "medium")],
    631: [("Printer info or unauth printing", "IPP exposing printer config or allowing unauthenticated prints can leak/cause data loss.", "low")],
    993: [("IMAPS TLS issues", "IMAPS relies on TLS; misconfig leads to credential disclosure risk.", "medium")],
    995: [("POP3S TLS issues", "POP3S relies on TLS; misconfiguration can expose credentials.", "medium")],
    3306: [("MySQL exposed to network", "MySQL accessible from network without ACLs/firewall; risk of data exfiltration.", "high"),
         ("Weak/default MySQL credentials", "Default or weak DB credentials can allow unauthorized access.", "high"),
         ("Unencrypted MySQL traffic", "MySQL connections without TLS may expose credentials and queries.", "high")],
    465: [("SMTPS / TLS misconfig", "SMTPS misconfiguration can allow credential or message exposure.", "medium")],
    587: [("SMTP submission misconfig", "Submission port without proper auth/TLS can allow abuse or credential leakage.", "medium")]    # add more rules as needed
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
    
    def save_network_discovery(self,network_target,result):
        try:
            # insert network_scans
            network_id = (f"N{random.randint(0000,9999)}")
            scan_date = datetime.now()
            total_hosts = len(result)
            online_hosts = len([r for r in result if r.get("status", "").lower() == "online"])
            cursor = self.Mydb.cursor()
            insert_network_scans = "INSERT INTO network_scans(network_id,network_target,scan_date,total_hosts,online_hosts) VALUES (%s,%s,%s,%s,%s)"
            sv = (network_id,network_target,scan_date,total_hosts,online_hosts)
            cursor.execute(insert_network_scans,sv)

            
            # insert network_result_scan
            insert_network_scans_results= "INSERT INTO network_scan_results(result_network_id, network_id, ip_address,mac_address, status, last_seen) VALUES (%s,%s,%s,%s,%s,%s)"

            for i in result:

                result_network_id = f"R{random.randint(1,9999)}"
                host_status = "online" if i in result else "offline"
                ip_address = i.get("ip")
                mac_address = i.get("mac")
                last_seen = i.get("last_seen")
                cursor.execute(insert_network_scans_results,(result_network_id,network_id,ip_address,mac_address,host_status,last_seen))


            self.Mydb.commit()
            cursor.close()
            self.Mydb.close()
            print(f"[+] Saved scan {network_id}: Network Address = {network_target} | Total Host = {len(result)}")

        except IntegrityError as e:
            print(f"    [!] Im Sorry This application under development \nmistake on {e}")
        except gaierror as e:
            return False
        except Exception as e:
            print(f"[!] Error during update data: {e}")
            self.Mydb.rollback()

    def check_online_host(self):
        try:
            
            select_network_host = ("SELECT * FROM network_scan_results")

            self.cursor.execute(select_network_host)
            items2 =  self.cursor.fetchall()
            headers = ["result_network_id","network_id","ip_address","mac_address","status","last_seen"]
            print(tabulate(items2,headers=headers, tablefmt="grid"))
            time.sleep(0.5)
            if not items2:
                print(" [!] The Database Not Yet Exist")
        except AttributeError as e:
            print(f"     [!] Error at {e} \n    PLease Maksure you are connented to the database!")
            return True
        


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
                # vuln_id = f"V{random.randint(1,9999)}"
                if port_status == "open" and p in VULN_RULES:
                    rules = VULN_RULES[p]
                    for (vname,vdesc,vsev) in rules:
                        vuln_id = f"V{random.randint(1,9999)}"
                        cursor.execute(insert_vulnerabilities, (vuln_id,port_scan_result_id,vname, vdesc, vsev))
                elif port_status == "closed":
                        vuln_id = f"V{random.randint(1,9999)}"
                        cursor.execute(insert_vulnerabilities , (vuln_id,port_scan_result_id,"Unknown","Unknown","Unknown"))
                else:
                    print("     [~]Sorry for the Problem...")
                
            # saved into db
            self.Mydb.commit()
            self.close()
            cursor.close()
            print(f"[+] Saved scan {port_scan_id}: total ports = {port} | open ports = {open_ports}")
        except IntegrityError as e:
            print(f"    [!] Im Sorry This application under development \nmistake on {e}")
        except gaierror as e:
            return False
        except Exception as e:
            print(f"[!] Error during update data: {e}")
            self.Mydb.rollback()

    def check_open_port_data(self):
        try:
            select_join = (""" 
        SELECT port_scan.port_scan_id, port_scan_result.port_scan_result_id, port_scan.scan_date, port_scan.target_ip, port_scan_result.port_number, port_scan_result.port_status, port_scan_result.services_name, vulnerabilities.vulnerability_name, vulnerabilities.descriptions, vulnerabilities.severity
        FROM port_scan
        JOIN port_scan_result ON port_scan_result.port_scan_id = port_scan.port_scan_id	
        JOIN vulnerabilities ON vulnerabilities.port_scan_result_id = port_scan_result.port_scan_result_id
        WHERE port_scan_result.port_status = "open"; 
                        """)

            self.cursor.execute(select_join)
            items2 =  self.cursor.fetchall()
            headers = ["ID","Result ID","Scan Date","IP Target","Port Number","Port Status", "Services", "Vulnerability", "Descriptions","Severity"]
            print(tabulate(items2,headers=headers, tablefmt="plain"))
            time.sleep(0.5)
            if not items2:
                print(" [!] The Database Not Yet Exist")
        except AttributeError as e:
            print(f"     [!] Error at {e} \n    PLease Maksure you are connented to the database!")
            return True
    def Check_History(self):
        try:
            history_join= (""" 
            SELECT port_scan.port_scan_id, port_scan_result.port_scan_result_id, port_scan.scan_date, port_scan.target_ip, port_scan_result.port_number, port_scan_result.port_status, port_scan_result.services_name, vulnerabilities.vulnerability_name, vulnerabilities.descriptions, vulnerabilities.severity
            FROM port_scan
            JOIN port_scan_result ON port_scan_result.port_scan_id = port_scan.port_scan_id	
            JOIN vulnerabilities ON vulnerabilities.port_scan_result_id = port_scan_result.port_scan_result_id; 
                        """)
            self.cursor.execute(history_join)
            items3 =  self.cursor.fetchall()   
            headers = ["ID","Result ID","Scan Date","IP Target","Port Number","Port Status", "Services", "Vulnerability", "Descriptions","Severity"]
            print(tabulate(items3,headers=headers, tablefmt="plain"))     
            if not items3:
                print(" [!] The Database Not Yet Exist")
                time.sleep(0.5)
   
        except AttributeError as e:
            print(f"     [!] Error at {e} \n    PLease Maksure you are connented to the database!")
            return True
    
    def delete_data(self,scan_id):
        try:
            vuln_del = """
        DELETE v FROM vulnerabilities v
            JOIN port_scan_result r ON v.port_scan_result_id = r.port_scan_result_id
            WHERE r.port_scan_id = %s
        """
            
            cursor = self.Mydb.cursor()
            check_query = "SELECT 1 FROM port_scan WHERE port_scan_id = %s"
            cursor.execute(check_query, (scan_id,))
            result = cursor.fetchone()

            if result:
                self.cursor.execute(vuln_del,(scan_id,))
                query_result = "DELETE FROM port_scan_result WHERE port_scan_id = %s"
                self.cursor.execute(query_result, (scan_id,))
                query_scan = "DELETE FROM port_scan WHERE port_scan_id = %s"
                self.cursor.execute(query_scan, (scan_id,))
                self.Mydb.commit()
                print(f"    [+] ID {scan_id} Deleted")
            else:
                print(f"    [!]The ID is not exist!")

        except Exception as e:
            print(f"[!] Error during delete data: {e}")
            self.Mydb.rollback()
        finally:
            self.cursor.close()
            self.Mydb.close()
    def update_data(self,port_scan_id,status_port):
        try:
            
            cursor = self.Mydb.cursor()
            check_query = "SELECT 1 FROM port_scan_result WHERE port_scan_result_id = %s"
            cursor.execute(check_query, (port_scan_id,))
            result = cursor.fetchone()
            if result:
                query = """
                UPDATE port_scan_result
                SET port_status = %s
                WHERE port_scan_result_id = %s
                """
                cursor.execute(query, (status_port, port_scan_id))
                self.Mydb.commit()
                print(f"[+] Data {port_scan_id} updated into {status_port}")
            else:
                print(f"    [!]The ID is not exist!")
        except Exception as e:
            print(f"[!] Error during update data: {e}")
            self.Mydb.rollback()
        finally:
            cursor.close()


# #  test conn
# # db1 = DatabaseManager("localhost","root","admin","db_network_scanning_system")