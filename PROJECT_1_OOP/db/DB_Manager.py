import mysql.connector
import time

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
        print("terminating the database...")
        time.sleep(0.5)
        if self.cursor:
            self.Mydb.close()
        if self.Mydb:
            self.Mydb.close()
        print("Terminate Successful")
        time.sleep(0.25)
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
        for i,j,k,l,m,n,o,p,q in items2:
            print(f"ID : {i} \nDate: {j} \nIP Target: {k} \nPort: {l} \nStatus: {m} \nService: {n} \nVulnerability:{o} \nDescriptions:{p} \nSeverity:{q} \n\n")
            time.sleep(0.5)

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
        for i,j,k,l,m,n,o,p,q in items3:
            print(f"ID : {i} \nDate: {j} \nIP Target: {k} \nPort: {l} \nStatus: {m} \nService: {n} \nVulnerability:{o} \nDescriptions:{p} \nSeverity:{q} \n\n")
            time.sleep(0.5)

    
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


#  test conn
# db1 = DatabaseManager("localhost","root","admin","db_network_scanning_system")